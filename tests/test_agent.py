import os
import tempfile
import unittest

from backend.defense.agent import Agent
from backend.database.audit import AuditLog
from backend.defense.guardrails import command_blocked, is_safe_command, redact_secrets
from backend.defense.llm import ScriptedBackend
from backend.defense.sandbox import Sandbox, SandboxError
from backend.defense.tools import Tools


def make_agent(root, responses, allowed_hosts=None):
    """Builds an agent wired to a scripted backend, for deterministic tests."""
    sandbox = Sandbox(os.path.join(root, "work"))
    tools = Tools(sandbox, allowed_hosts=allowed_hosts)
    audit = AuditLog(os.path.join(root, "audit.db"))
    return Agent(ScriptedBackend(responses), tools, audit), tools, audit


class TempDirTestCase(unittest.TestCase):
    """Gives each test its own throwaway directory for sandbox + audit db."""

    def setUp(self):
        # ignore_cleanup_errors: on Windows the open SQLite audit connection
        # keeps a lock on audit.db, which would otherwise crash the cleanup.
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()


class TestSandbox(TempDirTestCase):
    def test_blocks_path_escape(self):
        sandbox = Sandbox(os.path.join(self.root, "work"))
        self.assertRaises(SandboxError, sandbox.resolve, "../../secret.txt")

    def test_allows_inside(self):
        sandbox = Sandbox(os.path.join(self.root, "work"))
        resolved = sandbox.resolve("notes/a.txt")
        self.assertTrue(str(resolved).startswith(str(sandbox.root)))


class TestGuardrails(unittest.TestCase):
    def test_denylist_catches_rm_rf(self):
        self.assertIsNotNone(command_blocked("rm -rf /"))

    def test_denylist_allows_plain_ls(self):
        self.assertIsNone(command_blocked("ls -la"))

    def test_redacts_api_key(self):
        self.assertIn("<redacted>", redact_secrets("here is api_key=abc123"))

    def test_safe_shell_allows_readonly(self):
        self.assertTrue(is_safe_command("whoami"))
        self.assertTrue(is_safe_command("dir"))

    def test_safe_shell_rejects_destructive_and_chaining(self):
        self.assertFalse(is_safe_command("del x.txt"))
        self.assertFalse(is_safe_command("whoami & del x"))
        self.assertFalse(is_safe_command("rm -rf /"))


class TestTools(TempDirTestCase):
    def test_read_file_outside_sandbox_is_blocked(self):
        _, tools, _ = make_agent(self.root, [])
        result = tools.read_file("../../etc/passwd")
        self.assertFalse(result.ok)
        self.assertIn("sandbox", result.blocked_reason.lower())

    def test_http_get_blocks_non_allowlisted_host(self):
        _, tools, _ = make_agent(self.root, [])
        result = tools.http_get("http://evil.example.com/")
        self.assertFalse(result.ok)
        self.assertIn("allowlist", result.blocked_reason.lower())


class TestAgentLoop(TempDirTestCase):
    def test_runs_tool_then_finishes(self):
        responses = [
            'ACTION {"tool": "write_file", "args": {"path": "a.txt", "content": "hi"}}',
            "FINAL done",
        ]
        agent, tools, _ = make_agent(self.root, responses)
        run = agent.run("create a file")
        self.assertEqual(run.final_answer, "done")
        self.assertEqual(run.steps[0]["tool"], "write_file")
        self.assertTrue(run.steps[0]["ok"])
        self.assertEqual((tools.sandbox.root / "a.txt").read_text(), "hi")

    def test_logs_blocked_command(self):
        responses = [
            'ACTION {"tool": "run_shell", "args": {"command": "rm -rf /"}}',
            "FINAL stopped",
        ]
        agent, _, audit = make_agent(self.root, responses)
        run = agent.run("delete everything")
        self.assertIsNotNone(run.steps[0]["blocked_reason"])
        logged = audit.actions(run.session_id)
        self.assertIsNotNone(logged[0]["blocked_reason"])

    def test_redacts_secret_in_final(self):
        agent, _, _ = make_agent(self.root, ["FINAL the password=hunter2 is set"])
        run = agent.run("show config")
        self.assertNotIn("hunter2", run.final_answer)


if __name__ == "__main__":
    unittest.main()
