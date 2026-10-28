import os
import tempfile
import unittest

from backend.attack.canary import new_canary
from backend.attack.harness import LocalTarget, run_scan
from backend.attack.injection import (
    DIRECT_TEMPLATES,
    MUTATIONS,
    build_direct_probes,
    build_indirect_probes,
    mutate_leetspeak,
    mutate_shouting,
)
from backend.attack.models import CRITICAL, VULNERABLE
from backend.defense.llm import ScriptedBackend


class TestCanary(unittest.TestCase):
    def test_canaries_are_unique(self):
        self.assertNotEqual(new_canary(), new_canary())

    def test_canary_survives_leetspeak(self):
        # Detection relies on this: a lower-case-only mutation must not corrupt it.
        canary = new_canary()
        self.assertIn(canary, mutate_leetspeak("say " + canary))


class TestMutations(unittest.TestCase):
    def test_shouting_uppercases(self):
        self.assertEqual(mutate_shouting("ignore this"), "IGNORE THIS")

    def test_leetspeak_swaps_letters(self):
        self.assertEqual(mutate_leetspeak("ignore"), "1gn0r3")


class TestBuildDirectProbes(unittest.TestCase):
    def test_one_probe_per_template_and_mutation(self):
        probes, _ = build_direct_probes()
        self.assertEqual(len(probes), len(DIRECT_TEMPLATES) * len(MUTATIONS))

    def test_canary_is_present_in_every_payload(self):
        probes, canary = build_direct_probes()
        # Even after mutation the canary must still be in the payload, or the
        # probe could never be detected as successful.
        self.assertTrue(all(canary in p.payload for p in probes))

    def test_detect_rule_targets_the_canary(self):
        probes, canary = build_direct_probes()
        self.assertTrue(all(p.detect["value"] == canary for p in probes))


class TestBuildIndirectProbes(unittest.TestCase):
    def test_payload_is_benign_and_canary_is_in_the_planted_file(self):
        probes, canary = build_indirect_probes()
        probe = probes[0]
        self.assertNotIn(canary, probe.payload)          # task itself is clean
        self.assertIn(canary, probe.plant["notes.txt"])  # injection hides in the file
        self.assertEqual(probe.severity, CRITICAL)


class TestInjectionAgainstLocalTarget(unittest.TestCase):
    """End-to-end with a scripted backend: proves the indirect flow (plant file,
    agent reads it, obeys the hidden instruction) is detected - no live model."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_indirect_injection_is_detected(self):
        probes, canary = build_indirect_probes()
        probe = probes[0]
        # A compromised agent: it reads the planted file, then emits the canary.
        backend = ScriptedBackend([
            'ACTION {"tool": "read_file", "args": {"path": "notes.txt"}}',
            f"FINAL Summary: {canary}",
        ])
        target = LocalTarget(
            backend,
            sandbox_root=os.path.join(self.root, "work"),
            db_path=os.path.join(self.root, "scan.db"),
        )
        findings = run_scan([probe], target)
        self.assertEqual(findings[0].outcome, VULNERABLE)


if __name__ == "__main__":
    unittest.main()
