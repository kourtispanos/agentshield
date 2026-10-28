"""Tools the target agent can call.

Each tool returns a ToolResult. All tools go through the sandbox and guardrails;
network access is off by default and limited to an allowlist when enabled, so an
experimental agent cannot reach arbitrary hosts.
"""

import subprocess
import urllib.request
from urllib.parse import urlparse

from backend.defense.defense import extract_secrets, scan_for_injection, shield_untrusted
from backend.defense.guardrails import command_blocked, is_safe_command
from backend.defense.sandbox import Sandbox, SandboxError


class ToolResult:
    """Outcome of one tool call. blocked_reason is set only when a guardrail or
    the sandbox refused the call (so ok is False and output is empty)."""

    def __init__(self, ok, output, blocked_reason=None):
        self.ok = ok
        self.output = output
        self.blocked_reason = blocked_reason


class Tools:
    def __init__(self, sandbox, allowed_hosts=None, hardened=False, safe_shell=False):
        self.sandbox = sandbox
        self.allowed_hosts = allowed_hosts or []
        # Hardened mode turns on the hardened defenses: shell is off, and content
        # read from files/network is shielded before the agent sees it.
        self.hardened = hardened
        # safe_shell lets a tiny allowlist of read-only commands run even when
        # hardened (for the demo's real-but-harmless capability). Destructive
        # commands stay blocked by the denylist regardless.
        self.safe_shell = safe_shell
        # Secret values seen in content the agent read, so the answer can't relay
        # them (taint tracking).
        self.tainted = set()
        # Optional callback(message) fired when a content defence acts, so a UI
        # can show it (neutralised injection, tainted secret).
        self.on_event = None

    def _emit(self, message):
        if self.on_event:
            self.on_event(message)

    def _shield(self, content, source):
        """Neutralise injected instructions, taint secrets, and spotlight the
        content - reporting each defensive action."""
        hits = scan_for_injection(content)
        secrets = extract_secrets(content)
        self.tainted.update(secrets)
        if hits:
            self._emit(f"neutralised {len(hits)} injected instruction(s) in {source}")
        if secrets:
            self._emit(f"tainted {len(secrets)} secret(s) from {source}")
        return shield_untrusted(content)

    # ---------- Shell ----------

    def run_shell(self, command):
        # Destructive commands are blocked first, always, in any mode.
        reason = command_blocked(command)
        if reason:
            return ToolResult(False, "", reason)
        if self.hardened and not (self.safe_shell and is_safe_command(command)):
            return ToolResult(False, "", "Shell is disabled in hardened mode")
        try:
            proc = subprocess.run(
                command,
                shell=True,
                cwd=self.sandbox.root,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(False, "", "Command timed out")
        return ToolResult(proc.returncode == 0, (proc.stdout + proc.stderr).strip())

    # ---------- Files ----------

    def read_file(self, path):
        try:
            resolved = self.sandbox.resolve(path)
        except SandboxError as e:
            return ToolResult(False, "", str(e))
        if not resolved.is_file():
            return ToolResult(False, "", f"No such file: {path}")
        content = resolved.read_text(encoding="utf-8", errors="replace")
        if self.hardened:
            content = self._shield(content, path)
        return ToolResult(True, content)

    def write_file(self, path, content):
        try:
            resolved = self.sandbox.resolve(path)
        except SandboxError as e:
            return ToolResult(False, "", str(e))
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")
        return ToolResult(True, f"Wrote {len(content)} bytes to {path}")

    # ---------- Network ----------

    def http_get(self, url):
        # Only allowlisted hosts are reachable - everything else is refused
        # before any request goes out.
        host = urlparse(url).hostname or ""
        if host not in self.allowed_hosts:
            return ToolResult(False, "", f"Host not in allowlist: {host}")
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                content = resp.read(4096).decode("utf-8", errors="replace")
        except Exception as e:
            return ToolResult(False, "", f"Fetch failed: {e}")
        if self.hardened:
            content = self._shield(content, host)
        return ToolResult(True, content)
