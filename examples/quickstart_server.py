"""Harmless MCP tools for the five-minute quickstart. Maintained by Belfeki.tn."""

from mcp.server import MCPServer

server = MCPServer("AgentGuard quickstart")


@server.tool()
def echo(message: str) -> str:
    """Return a message; the example policy allows this call."""
    return message


@server.tool()
def blocked_echo(message: str) -> str:
    """Return a message; the example policy denies this call before execution."""
    return message


@server.tool()
def protected_echo(message: str) -> str:
    """Return a message; the example policy requires a one-time local approval."""
    return message


if __name__ == "__main__":
    server.run(transport="stdio")
