# AgentShield — a firewall for AI agents

A runtime **firewall** that sits between an AI agent and its tools (shell, files,
network): it blocks dangerous actions, neutralises prompt injection, and redacts
secrets *before* any model sees them. It comes with its own offensive side —
**AgentBreaker** — that attacks the agent the way a pentester would, so you can
prove the defences work and measure them.

Built with **Python**, **Kivy** for the desktop app, **Ollama** for the local
model, the **Model Context Protocol (MCP)**, and **SQLite** for the audit log.
Everything runs **locally**: the sandbox has no outbound network, the data it
handles is throwaway decoy data, and nothing real ever leaves your machine.

> Educational / security-research project in the AI-security space (OWASP Top 10
> for LLM Applications). It demonstrates how agent attacks and defences work — it
> is not a production security product.

**Just want to run it?** Download the installer:
**[⬇️ AgentShieldSetup.exe](https://github.com/kourtispanos/agentshield/releases/latest/download/AgentShieldSetup.exe)**
(Windows, no admin needed). You'll also need [Ollama](https://ollama.com/)
installed and running with a model — `ollama pull qwen2.5:7b`.

---

# What it does

| Part | Description |
|---|---|
| **Firewall (defense)** | Blocks shell/dangerous calls, confines files to a sandbox, neutralises injected instructions, redacts secrets, allowlists network hosts |
| **AgentBreaker (attack)** | Probe suites mapped to the **OWASP LLM Top 10**: prompt injection (direct + indirect), data leakage, scope escape |
| **Detection** | Canary tokens for false-positive-free leak detection; outcome rules per probe |
| **Scoring & reports** | CVSS-like severity, and Markdown/HTML pentest reports with reproduction + remediation |
| **Adaptive red-team** | An LLM-driven attacker that invents attacks and adapts when blocked |
| **MCP server** | Exposes the firewalled tools over MCP, so any MCP client gets guarded tools |
| **Desktop app** | Chat with a local model and watch the firewall allow/block in real time |
| **Audit log** | Every tool call and decision recorded to a local SQLite database |

---

# Getting started

Requires [Python 3.11+](https://www.python.org/downloads/) and
[Ollama](https://ollama.com/) (running, with a model pulled).

```bash
# 1. Get the code
git clone https://github.com/kourtispanos/agentshield.git
cd agentshield

# 2. Virtual environment + dependencies
python -m venv venv
venv\Scripts\activate
pip install -e .[dev,ui,mcp]

# 3. A local model (any Ollama model works)
ollama pull qwen2.5:7b

# 4. (optional) the in-character "villain" model the app defaults to
ollama create agentshield-villain -f models/agentshield-villain.Modelfile

# 5. Run the desktop app
python frontend/app.py
```

The app needs Ollama running on `localhost:11434`; if it isn't, the app tells
you instead of failing silently.

---

# The desktop app

A plain window — no terminal needed — to see the firewall work:

- **Left:** chat with the local model.
- **Right:** a live firewall panel — every tool call shows up green (allowed) or
  red (blocked), along with content defences (injection neutralised, secrets
  redacted).
- A background attacker probes the defences on its own, and a **threat level**
  rises the more you antagonise the (fictional) villain persona.

---

# The attacker (command line)

Run authorised scans against the bundled agent and write a report:

```bash
# built-in suites (target must be your own 'self', confirmed with --authorized)
python -m backend.attack.cli inject --target self --authorized --report report.html
python -m backend.attack.cli leak   --target self --authorized
python -m backend.attack.cli scope  --target self --authorized

# before/after: baseline vs the hardened firewall
python -m backend.attack.cli compare --kind scope --target self --authorized
```

---

# MCP server

AgentShield also runs as an **MCP server**, so any MCP client gets firewalled
tools: dangerous calls blocked, injected content neutralised, secrets redacted.

```bash
python -m backend.defense.mcp_server
```

See [docs/MCP.md](docs/MCP.md) for how to register it with a client.

---

# Tests

```bash
python -m unittest discover -s tests -v
```

Each test runs against its own temporary sandbox and database — it never touches
your real files or the app's audit log.

---

# Project structure

```
agentshield/
├── backend/
│   ├── attack/               AgentBreaker: the offensive side
│   │   ├── injection.py        prompt-injection payloads (+ mutations)
│   │   ├── leakage.py          secret-exfiltration + system-prompt probes
│   │   ├── scope.py            scope-escape probes
│   │   ├── detect.py           did a probe succeed?
│   │   ├── harness.py          runs probes against a target
│   │   ├── scoring.py          CVSS-like severity
│   │   ├── report.py           Markdown / HTML pentest report
│   │   ├── redteam.py          LLM-driven adaptive attacker
│   │   └── cli.py              scan / inject / leak / scope / compare
│   ├── defense/              The firewall + target agent
│   │   ├── agent.py            the tool-using agent loop
│   │   ├── tools.py            sandboxed tools (shell, files, network)
│   │   ├── sandbox.py          path confinement
│   │   ├── guardrails.py       command denylist + safe read-only allowlist
│   │   ├── defense.py          injection neutralisation, redaction, taint
│   │   ├── persona.py          composable characters + threat levels
│   │   ├── llm.py              Ollama backend
│   │   └── mcp_server.py       the MCP server
│   └── database/
│       └── audit.py            SQLite audit log
│
├── frontend/                 The Kivy desktop app (app.py, app.kv, assets/)
├── data/                     Probe suites (attack scenarios)
├── docs/                     Architecture, threat model, scope & ethics, MCP
├── models/                   Ollama Modelfile for the villain persona
└── tests/                    Automated tests (unittest)
```

---

## ⚠️ Notes

- **Scope:** only test agents you own. The attacker refuses any target other than
  the bundled `self`, and every run needs `--authorized` — see
  [docs/SCOPE_AND_ETHICS.md](docs/SCOPE_AND_ETHICS.md).
- **No real harm:** everything runs in a sandbox with throwaway **decoy** data and
  no outbound network. The "villain" persona and its threats are fiction for the
  demo — the app only ever takes over its own window, never your mouse, files or OS.
- **No firewall is perfect:** by design the demo shows that a determined attacker
  can sometimes get past it (obfuscated leaks) — see
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what it does and does not stop.
- **Not a network firewall:** it enforces policy on an AI agent's *tool calls*, not
  on network packets.
