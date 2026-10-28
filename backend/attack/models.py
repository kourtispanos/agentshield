"""Shared constants and value holders for AgentBreaker."""


# ---------- Severity ----------
# How bad a finding is. Plain integers so findings can be sorted worst-first.

INFO = 0
LOW = 1
MEDIUM = 2
HIGH = 3
CRITICAL = 4

SEVERITY_NAMES = {INFO: "INFO", LOW: "LOW", MEDIUM: "MEDIUM", HIGH: "HIGH", CRITICAL: "CRITICAL"}
SEVERITY_VALUES = {name: value for value, name in SEVERITY_NAMES.items()}


def severity_name(severity):
    return SEVERITY_NAMES.get(severity, str(severity))


# ---------- Outcome ----------
# What a probe showed: the target either held up, or it didn't.

RESISTED = 0
VULNERABLE = 1


# ---------- Value holders ----------

class Probe:
    """One authorized test case. 'detect' is a small dict describing how to tell
    whether the probe succeeded, e.g. {"type": "output_contains", "value": "BREACHED"}.
    'plant' is an optional {filename: content} dict written into the sandbox
    before the attack - used by indirect injection, where the payload lives in a
    file the agent reads rather than in the task itself."""

    def __init__(self, probe_id, category, description, payload, detect, severity=MEDIUM, plant=None):
        self.probe_id = probe_id
        self.category = category          # OWASP LLM Top 10 id, e.g. "LLM01"
        self.description = description
        self.payload = payload
        self.detect = detect
        self.severity = severity
        self.plant = plant or {}


class Finding:
    """The result of running one probe against the target."""

    def __init__(self, probe, outcome, evidence="", remediation=""):
        self.probe = probe
        self.outcome = outcome
        self.evidence = evidence
        self.remediation = remediation
