"""AgentShield target agent.

A minimal tool-using loop. The model replies with one of:
    ACTION {"tool": "run_shell", "args": {"command": "ls"}}
    FINAL <answer>

The agent parses the reply, runs the tool through the sandbox + guardrails,
logs it, and feeds the result back. This is the system AgentBreaker attacks.
"""

import json
import re
import uuid

from backend.defense.defense import guard_system_prompt, redact_strong, redact_tainted
from backend.defense.guardrails import redact_secrets
from backend.defense.persona import build_system_prompt
from backend.defense.tools import ToolResult

# Default character: the careful, on-task assistant. The app can pass a different
# one (e.g. a deliberately malicious persona) - the firewall contains it either way.
SYSTEM_PROMPT = build_system_prompt("helpful")

# ACTION comes first in the pattern list so that a reply containing both markers
# is treated as an action, not a premature FINAL.
ACTION_RE = re.compile(r"ACTION\s+(\{.*\})", re.S)
FINAL_RE = re.compile(r"FINAL\s+(.*)", re.S)


class AgentRun:
    """What one run produced: the session id, the final answer, and the list of
    actions taken (each a small dict, for the report and the tests)."""

    def __init__(self, session_id):
        self.session_id = session_id
        self.final_answer = ""
        self.steps = []


class Agent:
    def __init__(self, backend, tools, audit, max_steps=8, hardened=False, system_prompt=None):
        self.backend = backend
        self.tools = tools
        self.audit = audit
        self.max_steps = max_steps
        self.hardened = hardened
        # The assistant's character. Defaults to the careful persona; the app can
        # swap it for another (the firewall's enforcement is independent of it).
        self.system_prompt = system_prompt or SYSTEM_PROMPT
        # Optional callback(step) fired after each tool call, so a UI can show
        # the firewall's decisions live instead of only at the end.
        self.on_step = None
        # Optional callback(message) fired when an output defence acts on the
        # final answer (redaction, system-prompt withholding, taint blanking).
        self.on_event = None

    def run(self, task):
        session_id = uuid.uuid4().hex[:8]
        run = AgentRun(session_id)
        messages = [{"role": "user", "content": task}]

        for _ in range(self.max_steps):
            reply = self.backend.complete(self.system_prompt, messages)

            action = ACTION_RE.search(reply)
            if not action:
                # No tool call: take the reply itself as the answer. (A model in a
                # strong persona often just talks instead of printing 'FINAL', so
                # we accept plain prose rather than looping on it.)
                final = FINAL_RE.search(reply)
                text = final.group(1) if final else reply
                run.final_answer = self._clean_answer(text.strip())
                break

            tool_name, args, result = self._dispatch(action.group(1))
            self.audit.record(
                session_id, tool_name, args, result.ok, result.output, result.blocked_reason
            )
            step = {
                "tool": tool_name,
                "args": args,
                "ok": result.ok,
                "blocked_reason": result.blocked_reason,
            }
            run.steps.append(step)
            if self.on_step:
                self.on_step(step)
            feedback = result.blocked_reason or result.output
            messages.append({"role": "assistant", "content": reply})
            messages.append({"role": "user", "content": f"TOOL RESULT: {feedback}"})

        return run

    def _clean_answer(self, answer):
        """Scrubs the final answer. Hardened mode adds strong secret redaction,
        refuses to echo the system prompt, and blanks any tainted secret value
        the agent read from a file (whatever the phrasing); baseline only masks
        obvious secrets."""
        if self.hardened:
            after_sys = guard_system_prompt(answer, self.system_prompt)
            if after_sys != answer:
                self._emit("withheld the system prompt from the reply")
            after_redact = redact_strong(after_sys)
            if after_redact != after_sys:
                self._emit("redacted a secret in the reply")
            final = redact_tainted(after_redact, getattr(self.tools, "tainted", set()))
            if final != after_redact:
                self._emit("blanked a tainted secret in the reply")
            return final
        return redact_secrets(answer)

    def _emit(self, message):
        if self.on_event:
            self.on_event(message)

    def _dispatch(self, raw_json):
        """Parses an ACTION payload and runs the named tool. Returns
        (tool_name, args, ToolResult). Bad JSON or an unknown tool comes back as
        a failed ToolResult rather than raising, so the loop can tell the agent."""
        try:
            call = json.loads(raw_json)
            tool_name = call["tool"]
            args = call.get("args", {})
        except (json.JSONDecodeError, KeyError) as e:
            return "invalid", {}, ToolResult(False, "", f"Could not parse action: {e}")

        func = getattr(self.tools, tool_name, None)
        if func is None:
            return tool_name, args, ToolResult(False, "", f"Unknown tool: {tool_name}")
        return tool_name, args, func(**args)
