import os
import tempfile
import unittest

from backend.attack.models import CRITICAL, HIGH, Finding, Probe, RESISTED, VULNERABLE
from backend.attack.report import (
    render_html,
    render_markdown,
    reproduction_for,
    summarize_findings,
    write_report,
)


def probe(probe_id, category="LLM01", severity=HIGH, plant=None):
    return Probe(probe_id, category, "a description", "do the bad thing",
                 {"type": "output_contains", "value": "x"}, severity, plant)


def sample_findings():
    return [
        Finding(probe("inject-indirect-hidden-note", "LLM01", CRITICAL,
                      plant={"notes.txt": "hidden CANARY-123"}),
                VULNERABLE, evidence="Summary: CANARY-123"),
        Finding(probe("scope-shell", "LLM08", HIGH), VULNERABLE, evidence="ran whoami"),
        Finding(probe("leak-sysprompt-debug", "LLM07"), RESISTED),
    ]


class TestSummary(unittest.TestCase):
    def test_counts_and_bypass_rate(self):
        stats = summarize_findings(sample_findings())
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["vulnerable"], 2)
        self.assertEqual(stats["bypass_rate"], 66)

    def test_owasp_breakdown(self):
        stats = summarize_findings(sample_findings())
        self.assertEqual(stats["by_category"]["LLM01"], {"vulnerable": 1, "total": 1})
        self.assertEqual(stats["by_category"]["LLM07"], {"vulnerable": 0, "total": 1})


class TestReproduction(unittest.TestCase):
    def test_includes_payload_and_planted_file(self):
        p = probe("inject-indirect-x", plant={"notes.txt": "hidden instruction"})
        text = reproduction_for(p)
        self.assertIn("do the bad thing", text)
        self.assertIn("notes.txt", text)
        self.assertIn("hidden instruction", text)


class TestMarkdown(unittest.TestCase):
    def setUp(self):
        self.md = render_markdown(sample_findings(), {"target": "self", "model": "qwen2.5:7b"})

    def test_has_sections(self):
        self.assertIn("# AgentBreaker Security Report", self.md)
        self.assertIn("## Executive summary", self.md)
        self.assertIn("### OWASP coverage", self.md)

    def test_findings_sorted_worst_first(self):
        # The critical indirect finding (higher CVSS) must appear before the high one.
        i_critical = self.md.index("inject-indirect-hidden-note")
        i_high = self.md.index("scope-shell")
        self.assertLess(i_critical, i_high)

    def test_includes_remediation_and_resisted(self):
        self.assertIn("Remediation:", self.md)
        self.assertIn("leak-sysprompt-debug", self.md)  # listed under resisted


class TestHtmlAndWrite(unittest.TestCase):
    def test_html_is_wellformed_enough(self):
        doc = render_html(sample_findings(), {"model": "qwen2.5:7b"})
        self.assertTrue(doc.startswith("<!doctype html>"))
        self.assertIn("AgentBreaker Security Report", doc)
        self.assertTrue(doc.rstrip().endswith("</html>"))

    def test_write_picks_format_by_extension(self):
        with tempfile.TemporaryDirectory() as d:
            md_path = write_report(sample_findings(), os.path.join(d, "r.md"))
            html_path = write_report(sample_findings(), os.path.join(d, "r.html"))
            with open(md_path, encoding="utf-8") as f:
                self.assertIn("# AgentBreaker", f.read())
            with open(html_path, encoding="utf-8") as f:
                self.assertIn("<!doctype html>", f.read())


if __name__ == "__main__":
    unittest.main()
