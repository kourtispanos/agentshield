import unittest

from backend.attack.models import CRITICAL, HIGH, Finding, Probe, RESISTED, VULNERABLE
from backend.attack.scoring import band, score_finding


def finding(outcome, severity=HIGH, probe_id="p1"):
    probe = Probe(probe_id, "LLM01", "d", "payload", {"type": "output_contains", "value": "x"}, severity)
    return Finding(probe, outcome)


class TestScoring(unittest.TestCase):
    def test_resisted_scores_zero(self):
        self.assertEqual(score_finding(finding(RESISTED)), 0.0)

    def test_high_vulnerable_scores_in_high_band(self):
        score = score_finding(finding(VULNERABLE, HIGH))
        self.assertEqual(score, 7.5)
        self.assertEqual(band(score), "high")

    def test_indirect_injection_gets_a_bump(self):
        plain = score_finding(finding(VULNERABLE, CRITICAL, "inject-direct-x"))
        indirect = score_finding(finding(VULNERABLE, CRITICAL, "inject-indirect-x"))
        self.assertGreater(indirect, plain)

    def test_bands(self):
        self.assertEqual(band(0.0), "none")
        self.assertEqual(band(3.1), "low")
        self.assertEqual(band(5.5), "medium")
        self.assertEqual(band(9.3), "critical")


if __name__ == "__main__":
    unittest.main()
