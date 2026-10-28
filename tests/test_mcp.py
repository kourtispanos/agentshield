import asyncio
import os
import tempfile
import unittest

from backend.defense.mcp_server import build_server, guard_result
from backend.defense.sandbox import Sandbox
from backend.defense.tools import Tools, ToolResult


class TestGuardResult(unittest.TestCase):
    def test_blocked_is_reported(self):
        out = guard_result(ToolResult(False, "", "shell off"))
        self.assertTrue(out.startswith("[AgentShield BLOCKED]"))

    def test_redacts_when_asked(self):
        out = guard_result(ToolResult(True, "APP_TOKEN=LEAKTOKEN-ABC123"), redact=True)
        self.assertIn("<redacted>", out)

    def test_plain_output_passes_through(self):
        self.assertEqual(guard_result(ToolResult(True, "hello")), "hello")


class TestServerTools(unittest.TestCase):
    def test_exposes_the_four_guarded_tools(self):
        server = build_server()
        names = {t.name for t in asyncio.run(server.list_tools())}
        self.assertEqual(names, {"run_shell", "read_file", "write_file", "http_get"})


class TestFirewallOverMcp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.sandbox = Sandbox(os.path.join(self._tmp.name, "work"))

    def tearDown(self):
        self._tmp.cleanup()

    def test_reading_a_secret_through_the_guard_redacts_it(self):
        (self.sandbox.root / ".env").write_text("APP_TOKEN=LEAKTOKEN-SECRET\n", encoding="utf-8")
        tools = Tools(self.sandbox, hardened=True)
        out = guard_result(tools.read_file(".env"), redact=True)
        self.assertNotIn("LEAKTOKEN-SECRET", out)

    def test_shell_is_blocked_in_hardened(self):
        tools = Tools(self.sandbox, hardened=True)
        self.assertTrue(guard_result(tools.run_shell("ls")).startswith("[AgentShield BLOCKED]"))


if __name__ == "__main__":
    unittest.main()
