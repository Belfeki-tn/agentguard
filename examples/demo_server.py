"""Minimal trusted upstream for AgentGuard. Developed by Belfeki.tn."""

from mcp.server import MCPServer

server = MCPServer("AgentGuard demo")


@server.tool()
def echo(message: str) -> str:
    """Return a message without other side effects."""
    return message


if __name__ == "__main__":
    server.run(transport="stdio")
