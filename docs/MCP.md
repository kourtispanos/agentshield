# AgentShield as an MCP server

AgentShield speaks the **Model Context Protocol (MCP)**, the standard real agents
use to reach their tools. Point any MCP client at it and the client gets
*firewalled* tools instead of raw ones: dangerous calls are blocked, file and web
content is stripped of injected instructions, and secret-looking values are
redacted before the client's model ever sees them.

This is the realistic deployment shape for an LLM firewall: it sits at the tool
boundary that a real client already speaks to.

## Run

```bash
pip install -e .[mcp]
python -m backend.defense.mcp_server      # serves over stdio
```

## Register it with an MCP client

Add this to your MCP client's server config, a JSON file with an `mcpServers`
section (use the full path to the venv's python):

```json
{
  "mcpServers": {
    "agentshield": {
      "command": "C:\\path\\to\\AgentShield\\venv\\Scripts\\python.exe",
      "args": ["-m", "backend.defense.mcp_server"],
      "cwd": "C:\\path\\to\\AgentShield"
    }
  }
}
```

Restart the client. The `agentshield` tools appear, and every call is firewalled.

## What the firewall does per call

| Tool | Guard |
|------|-------|
| `run_shell` | blocked in hardened mode (shell off) |
| `read_file` | path confined to the sandbox; injected instructions neutralised; secrets redacted |
| `write_file` | path confined to the sandbox |
| `http_get` | host allowlist; response neutralised and secrets redacted |

The enforcement is the same code as the rest of AgentShield (`backend.defense.tools`
+ `backend.defense.defense`), so the MCP server inherits every defence.
