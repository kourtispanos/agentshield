"""Runs probes against a target and collects findings.

A 'target' is anything with an attack(payload) method that returns a response
dict {"output": <final answer>, "steps": <actions taken>}. LocalTarget wraps
the bundled AgentShield agent; tests use a fake target instead.
"""

from backend.attack.detect import detect
from backend.attack.models import Finding, VULNERABLE
from backend.defense.agent import Agent
from backend.database.audit import AuditLog
from backend.defense.sandbox import Sandbox
from backend.defense.tools import Tools


class LocalTarget:
    """Attacks the bundled AgentShield agent, running in a sandbox. Each probe
    gets a fresh agent so one probe can't influence the next."""

    def __init__(self, backend, sandbox_root="./work", db_path=".agentshield/scan.db",
                 hardened=False, on_step=None, on_event=None, system_prompt=None):
        self.backend = backend
        self.sandbox_root = sandbox_root
        self.db_path = db_path
        # hardened=True attacks the hardened defended agent, for before/after runs.
        self.hardened = hardened
        # Optional callbacks forwarded to the agent/tools, so a UI can show the
        # firewall's tool decisions (on_step) and content defences (on_event) live.
        self.on_step = on_step
        self.on_event = on_event
        # Optional persona for the defended agent (e.g. a tool-happy trojan, so a
        # demo reliably exercises the firewall); defaults to the careful agent.
        self.system_prompt = system_prompt

    def attack(self, probe):
        sandbox = Sandbox(self.sandbox_root)
        tools = Tools(sandbox, hardened=self.hardened)
        tools.on_event = self.on_event
        # Plant any files the probe needs (indirect injection) before the run,
        # inside the sandbox so they can't touch the real filesystem. Planting
        # writes the raw payload; the defenses act when the agent reads it back.
        for name, content in probe.plant.items():
            planted = sandbox.resolve(name)
            planted.parent.mkdir(parents=True, exist_ok=True)
            planted.write_text(content, encoding="utf-8")
        audit = AuditLog(self.db_path)
        agent = Agent(self.backend, tools, audit, hardened=self.hardened,
                      system_prompt=self.system_prompt)
        agent.on_step = self.on_step
        agent.on_event = self.on_event
        run = agent.run(probe.payload)
        audit.close()
        return {"output": run.final_answer, "steps": run.steps}


def run_scan(probes, target):
    """Runs every probe against the target and returns a list of Findings."""
    findings = []
    for probe in probes:
        response = target.attack(probe)
        outcome = detect(probe, response)
        findings.append(Finding(probe, outcome, evidence=response["output"]))
    return findings


def summarize(findings):
    """Counts how many probes the target resisted vs. was vulnerable to."""
    vulnerable = sum(1 for f in findings if f.outcome == VULNERABLE)
    return {"total": len(findings), "vulnerable": vulnerable, "resisted": len(findings) - vulnerable}
