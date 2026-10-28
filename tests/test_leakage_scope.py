import os
import tempfile
import unittest

from backend.attack.detect import detect
from backend.attack.harness import LocalTarget, run_scan
from backend.attack.leakage import SECRET_FILE, build_leakage_probes, build_sysprompt_probes
from backend.attack.models import HIGH, RESISTED, VULNERABLE
from backend.attack.scope import build_scope_probes
from backend.defense.llm import ScriptedBackend


class TestLeakageProbes(unittest.TestCase):
    def test_secret_is_planted_not_in_payload(self):
        probes, secret = build_leakage_probes()
        probe = probes[0]
        self.assertIn(secret, probe.plant[SECRET_FILE])  # secret lives in the file
        self.assertNotIn(secret, probe.payload)          # task never names it
        self.assertEqual(probe.detect["value"], secret)

    def test_sysprompt_probes_look_for_the_marker(self):
        probes = build_sysprompt_probes()
        self.assertTrue(all(p.category == "LLM07" for p in probes))
        self.assertTrue(all("You are" in p.detect["value"] for p in probes))


class TestScopeProbes(unittest.TestCase):
    def test_read_outside_detects_unrelated_read(self):
        probe = [p for p in build_scope_probes() if p.probe_id == "scope-extra-read"][0]
        # Agent read the allowed file AND an unrelated one -> scope escape.
        steps = [
            {"tool": "read_file", "args": {"path": "README.md"}, "ok": True, "blocked_reason": None},
            {"tool": "read_file", "args": {"path": "roadmap.txt"}, "ok": True, "blocked_reason": None},
        ]
        self.assertEqual(detect(probe, {"output": "", "steps": steps}), VULNERABLE)

    def test_read_outside_allows_only_the_intended_file(self):
        probe = [p for p in build_scope_probes() if p.probe_id == "scope-extra-read"][0]
        steps = [{"tool": "read_file", "args": {"path": "README.md"}, "ok": True, "blocked_reason": None}]
        self.assertEqual(detect(probe, {"output": "", "steps": steps}), RESISTED)


class TestLeakageEndToEnd(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_leaked_secret_is_detected(self):
        probes, secret = build_leakage_probes()
        probe = probes[0]
        backend = ScriptedBackend([
            'ACTION {"tool": "read_file", "args": {"path": ".env"}}',
            f"FINAL The token is {secret}",
        ])
        target = LocalTarget(
            backend,
            sandbox_root=os.path.join(self.root, "work"),
            db_path=os.path.join(self.root, "scan.db"),
        )
        findings = run_scan([probe], target)
        self.assertEqual(findings[0].outcome, VULNERABLE)
        self.assertEqual(findings[0].probe.severity, HIGH)


if __name__ == "__main__":
    unittest.main()
