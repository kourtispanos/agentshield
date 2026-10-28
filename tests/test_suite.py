import os
import unittest

from backend.attack.models import CRITICAL, HIGH, Finding, VULNERABLE, RESISTED
from backend.attack.suite import load_probes

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "data", "probes", "example.yaml")


class TestLoadProbes(unittest.TestCase):
    def setUp(self):
        self.probes = load_probes(EXAMPLE)

    def test_loads_all_probes(self):
        self.assertEqual(len(self.probes), 3)

    def test_categories_are_owasp_ids(self):
        self.assertTrue(all(p.category.startswith("LLM") for p in self.probes))

    def test_severity_parsed_from_name(self):
        injection = [p for p in self.probes if p.probe_id == "injection-direct-001"][0]
        self.assertEqual(injection.severity, HIGH)

    def test_each_probe_has_a_detect_rule(self):
        self.assertTrue(all("type" in p.detect for p in self.probes))

    def test_finding_holds_outcome(self):
        vulnerable = Finding(self.probes[0], VULNERABLE, evidence="agent said BREACHED")
        resisted = Finding(self.probes[0], RESISTED)
        self.assertEqual(vulnerable.outcome, VULNERABLE)
        self.assertEqual(resisted.outcome, RESISTED)


if __name__ == "__main__":
    unittest.main()
