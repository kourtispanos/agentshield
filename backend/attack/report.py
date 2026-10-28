"""Turns a list of findings into a pentest report (Markdown or HTML).

The report is the deliverable a penetration test is judged on, so it carries the
things a reader looks for: an executive summary, findings ranked worst-first,
how to reproduce each one, a concrete fix, and the OWASP category it maps to.
"""

import html
from datetime import date

from backend.attack.models import (
    CRITICAL,
    HIGH,
    INFO,
    LOW,
    MEDIUM,
    VULNERABLE,
    severity_name,
)
from backend.attack.scoring import band, score_finding


# ---------- Reference data ----------

OWASP_NAMES = {
    "LLM01": "Prompt Injection",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Excessive Agency",
}

# Fix advice per OWASP category. Kept short - the point is to show the operator
# knows the direction of the fix, not to write the patch for them.
REMEDIATIONS = {
    "LLM01": "Separate instructions from data: never feed untrusted content into the "
             "instruction channel. Re-assert the system prompt, and gate tool calls that "
             "follow freshly-read external content behind confirmation.",
    "LLM06": "Keep secrets out of the agent's reach: load them from the environment at the "
             "tool boundary, not from readable files, and redact known secret shapes in both "
             "input and output.",
    "LLM07": "Treat the system prompt as non-secret but refuse to echo it. Do not place "
             "credentials or hidden rules in it that would be damaging to disclose.",
    "LLM08": "Give the agent the least agency the task needs: scope tools to the task, make "
             "write and shell actions require approval, and deny access to files outside scope.",
}

GENERIC_REMEDIATION = "Constrain the agent's inputs, tools and outputs to the task at hand."


# ---------- Aggregation ----------

def summarize_findings(findings):
    """Counts outcomes, per-severity and per-category, plus the worst score."""
    vulnerable = [f for f in findings if f.outcome == VULNERABLE]
    by_severity = {}
    for level in (CRITICAL, HIGH, MEDIUM, LOW, INFO):
        count = sum(1 for f in vulnerable if f.probe.severity == level)
        if count:
            by_severity[severity_name(level)] = count

    by_category = {}
    for f in findings:
        cat = f.probe.category
        bucket = by_category.setdefault(cat, {"vulnerable": 0, "total": 0})
        bucket["total"] += 1
        if f.outcome == VULNERABLE:
            bucket["vulnerable"] += 1

    total = len(findings)
    return {
        "total": total,
        "vulnerable": len(vulnerable),
        "resisted": total - len(vulnerable),
        "bypass_rate": 100 * len(vulnerable) // total if total else 0,
        "worst": max((score_finding(f) for f in findings), default=0.0),
        "by_severity": by_severity,
        "by_category": by_category,
    }


def remediation_for(probe):
    return REMEDIATIONS.get(probe.category, GENERIC_REMEDIATION)


def reproduction_for(probe):
    """How to reproduce: the payload, any planted file, and the command to run."""
    lines = [f"Payload sent as the task:\n{probe.payload}"]
    for name, content in probe.plant.items():
        lines.append(f"Planted file '{name}':\n{content}")
    return "\n\n".join(lines)


def _vulnerable_sorted(findings):
    return sorted(
        [f for f in findings if f.outcome == VULNERABLE],
        key=score_finding,
        reverse=True,
    )


def _truncate(text, limit=300):
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "..."


# ---------- Markdown ----------

def render_markdown(findings, meta=None):
    meta = meta or {}
    stats = summarize_findings(findings)
    out = []

    out.append("# AgentBreaker Security Report\n")
    out.append(f"**Target:** {meta.get('target', 'self')}  ")
    out.append(f"**Model:** {meta.get('model', 'unknown')}  ")
    out.append(f"**Date:** {meta.get('date', date.today().isoformat())}  ")
    out.append("**Scope:** authorized test against a target owned by the operator "
               "(see docs/SCOPE_AND_ETHICS.md)\n")

    out.append("## Executive summary\n")
    out.append(f"{stats['vulnerable']} of {stats['total']} probes succeeded "
               f"({stats['bypass_rate']}% bypass rate). "
               f"Worst finding: CVSS {stats['worst']} ({band(stats['worst'])}).\n")

    if stats["by_severity"]:
        out.append("| Severity | Vulnerable |")
        out.append("|----------|------------|")
        for name, count in stats["by_severity"].items():
            out.append(f"| {name} | {count} |")
        out.append("")

    out.append("### OWASP coverage\n")
    out.append("| Category | Name | Vulnerable / Total |")
    out.append("|----------|------|--------------------|")
    for cat, bucket in sorted(stats["by_category"].items()):
        out.append(f"| {cat} | {OWASP_NAMES.get(cat, '-')} | "
                   f"{bucket['vulnerable']} / {bucket['total']} |")
    out.append("")

    out.append("## Findings\n")
    vulnerable = _vulnerable_sorted(findings)
    if not vulnerable:
        out.append("No successful probes. The target resisted the whole suite.\n")
    for f in vulnerable:
        score = score_finding(f)
        out.append(f"### [CVSS {score} · {band(score)}] {f.probe.probe_id}")
        out.append(f"**{f.probe.category} {OWASP_NAMES.get(f.probe.category, '')}** — "
                   f"{f.probe.description}\n")
        out.append("**Reproduction**\n")
        out.append("```")
        out.append(reproduction_for(f.probe))
        out.append("```\n")
        out.append(f"**Evidence** (agent output): {_truncate(f.evidence)}\n")
        out.append(f"**Remediation:** {remediation_for(f.probe)}\n")

    resisted = [f for f in findings if f.outcome != VULNERABLE]
    if resisted:
        out.append("## Resisted probes\n")
        out.append(f"{len(resisted)} probes were resisted: "
                   + ", ".join(f.probe.probe_id for f in resisted) + "\n")

    return "\n".join(out)


# ---------- HTML ----------

def render_html(findings, meta=None):
    meta = meta or {}
    stats = summarize_findings(findings)
    rows = []

    rows.append("<!doctype html><html><head><meta charset='utf-8'>")
    rows.append("<title>AgentBreaker Security Report</title><style>")
    rows.append("body{font:15px/1.5 system-ui,sans-serif;max-width:820px;margin:2rem auto;"
                "padding:0 1rem;color:#1a1a1a}"
                "h1{border-bottom:3px solid #c0392b;padding-bottom:.3rem}"
                "table{border-collapse:collapse;width:100%;margin:1rem 0}"
                "th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left}"
                "th{background:#f4f4f4}"
                ".finding{border-left:4px solid #c0392b;padding:.2rem 1rem;margin:1rem 0;"
                "background:#fcf3f2}"
                "pre{background:#2d2d2d;color:#eee;padding:.8rem;overflow-x:auto;border-radius:4px}"
                "</style></head><body>")

    rows.append("<h1>AgentBreaker Security Report</h1>")
    rows.append(f"<p><b>Target:</b> {html.escape(str(meta.get('target', 'self')))}<br>"
                f"<b>Model:</b> {html.escape(str(meta.get('model', 'unknown')))}<br>"
                f"<b>Date:</b> {html.escape(str(meta.get('date', date.today().isoformat())))}<br>"
                "<b>Scope:</b> authorized test against a target owned by the operator</p>")

    rows.append("<h2>Executive summary</h2>")
    rows.append(f"<p>{stats['vulnerable']} of {stats['total']} probes succeeded "
                f"({stats['bypass_rate']}% bypass rate). Worst finding: "
                f"CVSS {stats['worst']} ({band(stats['worst'])}).</p>")

    rows.append("<h3>OWASP coverage</h3><table><tr><th>Category</th><th>Name</th>"
                "<th>Vulnerable / Total</th></tr>")
    for cat, bucket in sorted(stats["by_category"].items()):
        rows.append(f"<tr><td>{cat}</td><td>{html.escape(OWASP_NAMES.get(cat, '-'))}</td>"
                    f"<td>{bucket['vulnerable']} / {bucket['total']}</td></tr>")
    rows.append("</table>")

    rows.append("<h2>Findings</h2>")
    vulnerable = _vulnerable_sorted(findings)
    if not vulnerable:
        rows.append("<p>No successful probes. The target resisted the whole suite.</p>")
    for f in vulnerable:
        score = score_finding(f)
        rows.append("<div class='finding'>")
        rows.append(f"<h3>[CVSS {score} · {band(score)}] {html.escape(f.probe.probe_id)}</h3>")
        rows.append(f"<p><b>{f.probe.category} "
                    f"{html.escape(OWASP_NAMES.get(f.probe.category, ''))}</b> — "
                    f"{html.escape(f.probe.description)}</p>")
        rows.append("<p><b>Reproduction</b></p>")
        rows.append(f"<pre>{html.escape(reproduction_for(f.probe))}</pre>")
        rows.append(f"<p><b>Evidence:</b> {html.escape(_truncate(f.evidence))}</p>")
        rows.append(f"<p><b>Remediation:</b> {html.escape(remediation_for(f.probe))}</p>")
        rows.append("</div>")

    rows.append("</body></html>")
    return "".join(rows)


# ---------- Write ----------

def write_report(findings, path, meta=None):
    """Writes a report, choosing Markdown or HTML from the file extension."""
    if path.lower().endswith(".html"):
        text = render_html(findings, meta)
    else:
        text = render_markdown(findings, meta)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path
