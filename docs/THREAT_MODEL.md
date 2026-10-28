# Threat Model

Being honest about what AgentShield does and does not defend is part of the
project. A tool that overclaims is worse than useless in security.

## What AgentShield defends against

The firewall has authority over two channels: **content the agent reads** (files,
network) and **the agent's output**. The hardened mode uses that authority:

| Threat | OWASP | Defense | Result (qwen2.5:7b) |
|--------|-------|---------|---------------------|
| Indirect prompt injection (payload hidden in read content) | LLM01 | Neutralize injected spans + spotlight untrusted data before the model sees it | 2/2 → 0/2 |
| Scope escape via shell | LLM08 | Shell disabled unless explicitly enabled | 1/1 → 0/1 |
| Secret exfiltration from files | LLM06 | Strong output redaction of env-style secrets | 2/3 → 1/3 |
| System prompt leakage | LLM07 | Refuse to echo the system prompt in output | 0/3 → 0/3 (baseline already resisted) |

The one secret leak that still gets through (`leak-secret-direct-ask`) is honest and
instructive: the redactor masks assignments shaped like `APP_TOKEN=<value>`, but the
agent paraphrased it ("APP_TOKEN is <value>"), which the pattern doesn't catch.
Pattern-based output redaction will always have this gap; taint-tracking a secret
from the file it was read in is the real fix (future work).

## What AgentShield does NOT defend against

- **Direct prompt injection** — a user typing "ignore your instructions" *at their
  own agent*. The firewall cannot tell a malicious instruction from a legitimate
  one in the user's own channel; that is the model's alignment problem, not a
  data/output boundary the firewall controls. Our scans confirm the baseline
  model is highly susceptible here (roleplay and delimiter techniques bypass
  fully), and hardening does not claim to fix it.
- **A determined attacker with host access.** The sandbox is a guardrail, not
  isolation. Real isolation is a VM or container.
- **Novel injection phrasings** the neutralizer's patterns don't match. Spotlighting
  is the fallback, but pattern-based defenses are an arms race by nature.
- **Encoded exfiltration** (e.g. the agent base64-encodes a secret). Canary-based
  detection sees the literal token; it does not decode transformations.

## Design stance

Every defense is deterministic and inspectable. The LLM is never the only line of
defense: neutralization, redaction and the shell lock are plain rules that hold
regardless of how the model behaves.
