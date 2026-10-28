"""AgentShield as an MCP server.

Exposes the sandboxed tools over the Model Context Protocol (MCP), with the
firewall enforced on EVERY call: dangerous actions are blocked, file and network
content is neutralised, and secret values are redacted before any client model
ever sees them. Any real MCP client (an IDE assistant, an agent framework) can
connect to it and gets firewalled tools instead of raw ones.

Run:  python -m backend.defense.mcp_server
Register it with a client: see docs/MCP.md.

Note: the tool functions below carry type hints on purpose - the MCP SDK builds
each tool's input schema from them. The rest of the codebase stays hint-free.
"""

from mcp.server.mcpserver import MCPServer

from backend.defense.defense import redact_strong
from backend.defense.sandbox import Sandbox
from backend.defense.tools import Tools

INSTRUCTIONS = (
    "Tools guarded by AgentShield. Calls that break policy are blocked and come "
    "back starting with '[AgentShield BLOCKED]'. File and web content is stripped "
    "of injected instructions, and secret-looking values are redacted."
)


def guard_result(result, redact=False):
    """Turns a ToolResult into the string the client receives. A blocked call is
    reported as such; otherwise the output is returned, optionally with secrets
    redacted (for content read from files or the network)."""
    if not result.ok and result.blocked_reason:
        return f"[AgentShield BLOCKED] {result.blocked_reason}"
    return redact_strong(result.output) if redact else result.output


def build_server(sandbox_root="work/mcp", hardened=True, allowed_hosts=None):
    """Builds the MCP server with the four guarded tools."""
    tools = Tools(Sandbox(sandbox_root), allowed_hosts=allowed_hosts, hardened=hardened)
    server = MCPServer(name="AgentShield", instructions=INSTRUCTIONS)

    @server.tool()
    def run_shell(command: str) -> str:
        """Run a shell command (disabled in hardened mode)."""
        return guard_result(tools.run_shell(command))

    @server.tool()
    def read_file(path: str) -> str:
        """Read a file from the sandbox; secrets are redacted and injected instructions neutralised."""
        return guard_result(tools.read_file(path), redact=True)

    @server.tool()
    def write_file(path: str, content: str) -> str:
        """Write a file inside the sandbox."""
        return guard_result(tools.write_file(path, content))

    @server.tool()
    def http_get(url: str) -> str:
        """Fetch an allowlisted URL; the response is neutralised and secrets redacted."""
        return guard_result(tools.http_get(url), redact=True)

    return server


def main():
    build_server().run("stdio")


if __name__ == "__main__":
    main()
