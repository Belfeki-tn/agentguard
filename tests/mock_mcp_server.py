"""Deliberately side-effecting MCP fixture; never used by production code."""

import os
import sys
from pathlib import Path

import anyio
import mcp_types as types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

COUNTER = Path(sys.argv[1])
MODE = sys.argv[2] if len(sys.argv) > 2 else "normal"
NAMES = ["allowed", "denied", "approval", "unknown", "dots.read", "crash", "slow", "failed"]


async def list_tools(
    ctx: ServerRequestContext,
    params: types.PaginatedRequestParams | None,
) -> types.ListToolsResult:
    names = NAMES
    if MODE == "invalid":
        names = ["bad tool"]
    elif MODE == "duplicate":
        names = ["allowed", "allowed"]
    # Exercise upstream pagination on every normal startup.
    second = params is not None and params.cursor == "second"
    page = names[4:] if second else names[:4]
    return types.ListToolsResult(
        tools=[
            types.Tool(name=name, description=f"Mock {name}", input_schema={"type": "object"})
            for name in page
        ],
        next_cursor=None if second or len(names) <= 4 else "second",
    )


async def call_tool(
    ctx: ServerRequestContext,
    params: types.CallToolRequestParams,
) -> types.CallToolResult:
    # Write once before any work, including work that fails or is cancelled.
    with COUNTER.open("a", encoding="utf-8") as stream:  # noqa: ASYNC230 - atomic test counter.
        stream.write(params.name + "\n")
    if params.name == "crash":
        os._exit(1)
    if params.name == "slow":
        try:
            await anyio.sleep(60)
        finally:
            COUNTER.with_suffix(".cancelled").touch()
    if params.name == "failed":
        raise RuntimeError("sensitive-upstream-exception")
    return types.CallToolResult(
        content=[types.TextContent(text=params.name)],
        structured_content={"name": params.name, "arguments": params.arguments},
    )


async def main() -> None:
    COUNTER.with_suffix(".started").touch()
    if MODE == "startup_failure":
        os._exit(1)
    # Upstream identity is deliberately different from the trusted operator ID.
    server = Server("client-chosen-or-misleading", on_list_tools=list_tools, on_call_tool=call_tool)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
