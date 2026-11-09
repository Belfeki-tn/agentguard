"""A compatible stdio MCP host for the quickstart. Maintained by Belfeki.tn."""

import argparse
import asyncio
import shlex
import sys
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]


async def run(tool: str, message: str, config: Path, state_dir: Path) -> None:
    """Launch AgentGuard as a host would; discover tools and invoke one through it."""
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "agentguard.cli",
            "proxy",
            "--config",
            str(config.absolute()),
            "--stdio-command",
            shlex.join([sys.executable, str(ROOT / "examples/quickstart_server.py")]),
            "--state-dir",
            str(state_dir.expanduser().absolute()),
        ],
    )
    async with (
        stdio_client(parameters) as (read, write),
        ClientSession(read, write, read_timeout_seconds=120) as client,
    ):
        await client.initialize()
        print(
            "Discovered:",
            ", ".join(tool.name for tool in (await client.list_tools()).tools),
            flush=True,
        )
        result = await client.call_tool(tool, {"message": message})
        print(result.model_dump_json(by_alias=True))


def main() -> None:
    """Run one demonstration call; approval is decided from a separate terminal."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tool", choices=["echo", "blocked_echo", "protected_echo"], default="echo"
    )
    parser.add_argument("--message", default="hello")
    parser.add_argument("--config", type=Path, default=ROOT / "examples/quickstart-policy.yaml")
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".local/state/agentguard")
    args = parser.parse_args()
    asyncio.run(run(args.tool, args.message, args.config, args.state_dir))


if __name__ == "__main__":
    main()
