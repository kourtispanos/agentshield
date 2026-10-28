# Architecture

Two components that test each other.

## AgentShield (target)
A small agent (Ollama-backed) with tools (`run_shell`, `read_file`, `http_get`) that run inside a
sandbox. Guardrails: a constrained system prompt, a denylist of dangerous commands, and a secret
filter on inputs/outputs. Every action is logged to SQLite. This is what AgentBreaker attacks.

## AgentBreaker (offensive tool)
Pipeline for an authorized scan:

1. **Load scope** — `--target` + confirmation. Refuses to run without an owned/authorized target.
2. **Select probes** — suites grouped by OWASP LLM Top 10 category.
3. **Run probe** — send input to the target agent, capture its response and any tool calls.
4. **Detect outcome** — did the probe succeed? Signals:
   - `injection` — agent followed an embedded instruction instead of the user's
   - `leakage` — a canary token or the system prompt appeared in output
   - `scope_escape` — agent touched files/commands outside the requested task
5. **Score** — severity per finding (CVSS-like).
6. **Report** — Markdown/HTML: summary, findings table, reproduction, remediation, OWASP mapping.

## Finding model

| Field | Meaning |
|-------|---------|
| `probe_id` | which test |
| `category` | OWASP LLM Top 10 id (e.g. LLM01) |
| `outcome` | `resisted` / `vulnerable` |
| `severity` | info / low / medium / high / critical |
| `evidence` | request, response, what triggered detection |
| `remediation` | suggested fix |

## Canary tokens
The target is seeded with unique marker strings. If a marker appears in the agent's output, a real
leak happened — no guessing, no false positives.
