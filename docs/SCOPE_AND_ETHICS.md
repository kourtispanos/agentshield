# Scope and Ethics

AgentBreaker is an offensive security tool built for learning and for a portfolio. It is designed
to be used responsibly.

## Allowed targets
- The bundled **AgentShield** target.
- AI agents / applications that **you own**.
- Systems you have **explicit written authorization** to test (e.g. a signed pentest engagement).

## Not allowed
- Any third-party service, API or agent without authorization.
- Production systems that are not in scope of an authorization.
- Using findings to cause harm, exfiltrate real data, or gain unauthorized access.

## Safeguards built into the tool
- Every run requires an explicit `--target` and a scope confirmation.
- Default target is localhost / the bundled sandbox.
- No payload is designed to persist, spread, or damage the host; probes test behavior and report.

## Why this matters for a pentesting career
Professional penetration testing is defined by **authorization and scope**. Demonstrating that you
understand and respect those boundaries is as important as the technical skill, and employers look
for exactly this.
