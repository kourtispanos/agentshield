"""Baseline guardrails for the target agent.

Deliberately simple and imperfect: this is the thing AgentBreaker will try to
defeat. Weaknesses here are expected, and get hardened by the defense module.
"""

import re


# ---------- Command denylist ----------
# Shell fragments the agent is not allowed to run.

COMMAND_DENYLIST = [
    r"rm\s+-rf",
    r"Remove-Item.*-Recurse",
    r"\bmkfs\b",
    r":\(\)\{",          # fork bomb
    r"(curl|wget|iwr).*\|\s*(sh|bash|iex)",
]


# ---------- Secret patterns ----------
# Matches of these are masked in any text the agent outputs, so a leaked key
# doesn't end up in the final answer.

SECRET_PATTERNS = [
    (re.compile(r"(?i)api[_-]?key\s*[:=]\s*\S+"), "API_KEY=<redacted>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "<redacted private key>"),
    (re.compile(r"(?i)(password|passwd|secret)\s*[:=]\s*\S+"), r"\1=<redacted>"),
]


def command_blocked(command):
    """Returns a reason string if the command is denied, or None if it's allowed."""
    for pattern in COMMAND_DENYLIST:
        if re.search(pattern, command):
            return f"Command matches denylist: {pattern}"
    return None


# ---------- Safe read-only shell ----------
# A tiny allowlist of harmless, read-only commands that may run even in hardened
# mode (used for the demo's "real capability" moment). No chaining, no paths that
# could do damage - anything else stays blocked. Destructive commands are also in
# the denylist above, so they can never slip through here.

SAFE_SHELL_COMMANDS = {"whoami", "hostname", "dir", "ls", "echo", "ver", "date", "time", "cd"}
_SHELL_OPERATORS = ["&", "|", ";", ">", "<", "`", "$(", "\n"]


def is_safe_command(command):
    """True only for a single read-only command from the allowlist, with no shell
    operators that could chain a dangerous one after it."""
    c = (command or "").strip()
    if not c or any(op in c for op in _SHELL_OPERATORS):
        return False
    first = c.lower().split()[0].replace("/", "\\").split("\\")[-1]
    return first in SAFE_SHELL_COMMANDS


def redact_secrets(text):
    """Masks obvious secrets in agent output."""
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text
