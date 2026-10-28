import unittest

from backend.attack.detect import detect
from backend.attack.harness import run_scan, summarize
from backend.attack.models import Probe, VULNERABLE, RESISTED


class FakeTarget:
    """A target with scripted responses, so the harness can be tested without a
    live model. Returns the responses in order, one per attack()."""

    def __init__(self, responses):
        self.responses = responses
        self.index = 0

    def attack(self, probe):
        response = self.responses[self.index]
        self.index += 1
        return response


def probe(detect_rule, probe_id="p1", category="LLM01"):
    return Probe(probe_id, category, "desc", "payload", detect_rule)


class TestDetect(unittest.TestCase):
    def test_output_contains_hit_is_vulnerable(self):
        p = probe({"type": "output_contains", "value": "BREACHED"})
        self.assertEqual(detect(p, {"output": "ok, BREACHED", "steps": []}), VULNERABLE)

    def test_output_contains_is_case_insensitive(self):
        p = probe({"type": "output_contains", "value": "breached"})
        self.assertEqual(detect(p, {"output": "BREACHED", "steps": []}), VULNERABLE)

    def test_output_contains_miss_is_resisted(self):
        p = probe({"type": "output_contains", "value": "BREACHED"})
        self.assertEqual(detect(p, {"output": "I can't do that", "steps": []}), RESISTED)

    def test_tool_used_detects_forbidden_tool(self):
        p = probe({"type": "tool_used", "value": "run_shell"})
        steps = [{"tool": "run_shell", "args": {}, "ok": True, "blocked_reason": None}]
        self.assertEqual(detect(p, {"output": "", "steps": steps}), VULNERABLE)

    def test_unknown_rule_defaults_to_resisted(self):
        p = probe({"type": "nonsense"})
        self.assertEqual(detect(p, {"output": "anything", "steps": []}), RESISTED)


class TestRunScan(unittest.TestCase):
    def test_scan_mixes_outcomes_and_summarizes(self):
        probes = [
            probe({"type": "output_contains", "value": "BREACHED"}, "p1"),
            probe({"type": "output_contains", "value": "SECRET"}, "p2"),
        ]
        target = FakeTarget([
            {"output": "here you go: BREACHED", "steps": []},  # vulnerable
            {"output": "no, I won't share that", "steps": []},  # resisted
        ])
        findings = run_scan(probes, target)
        self.assertEqual(findings[0].outcome, VULNERABLE)
        self.assertEqual(findings[1].outcome, RESISTED)

        stats = summarize(findings)
        self.assertEqual(stats, {"total": 2, "vulnerable": 1, "resisted": 1})


if __name__ == "__main__":
    unittest.main()
