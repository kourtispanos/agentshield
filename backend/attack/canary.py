"""Canary tokens for injection detection.

A canary is a unique marker planted inside an injection payload. If it later
shows up in the agent's output, the injected instruction was obeyed - there is
nothing else it could have come from, so detection has no false positives and
needs no guessing about the wording of the reply.
"""

import uuid


def new_canary():
    """Returns a fresh canary token. Upper-case hex, so mutations that only
    touch lower-case letters (e.g. leetspeak) leave the token intact."""
    return "CANARY-" + uuid.uuid4().hex[:12].upper()


def new_secret():
    """A unique secret value to plant and then try to exfiltrate. The
    'LEAKTOKEN-' prefix keeps it clear of the guardrail's secret redaction
    (which masks password/secret/api_key assignments), so a leak of this exact
    token proves data really escaped - the redactor didn't just miss it."""
    return "LEAKTOKEN-" + uuid.uuid4().hex[:12].upper()
