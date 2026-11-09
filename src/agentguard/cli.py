"""AgentGuard command line interface. Developed and maintained by Belfeki.tn."""

from pathlib import Path
from typing import Annotated

import anyio
import typer

from agentguard.policy import load_policy
from agentguard.proxy import ProxySettings, parse_command, run_proxy

app = typer.Typer(
    help="AgentGuard MCP permission gateway by Belfeki.tn.", pretty_exceptions_enable=False
)


@app.command()
def status() -> None:
    """Show implementation status."""
    typer.echo("AgentGuard by Belfeki.tn — stdio tool enforcement; approvals unavailable.")


@app.command()
def proxy(
    config: Annotated[Path, typer.Option("--config", help="Version 1 policy YAML file.")],
    stdio_command: Annotated[
        str, typer.Option("--stdio-command", help="Trusted upstream command.")
    ],
    server_id: str = typer.Option(
        "upstream", "--server-id", help="Trusted policy server namespace."
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Startup and call timeout in seconds."),
) -> None:
    """Serve a single trusted upstream over stdio, enforcing policy on every tool call."""
    try:
        policy = load_policy(config)
        settings = ProxySettings(parse_command(stdio_command), server_id, timeout)
    except ValueError:
        typer.echo("Invalid policy or proxy settings; upstream was not started.", err=True)
        raise typer.Exit(2) from None
    typer.echo(
        "AgentGuard by Belfeki.tn: launching trusted upstream with policy enforcement.", err=True
    )
    try:
        anyio.run(run_proxy, policy, settings)
    except KeyboardInterrupt:
        raise typer.Exit(130) from None
    except Exception:  # noqa: BLE001 - CLI boundary must sanitize SDK errors and nested groups.
        typer.echo(
            "Proxy stopped after an upstream or protocol failure; no retry attempted.", err=True
        )
        raise typer.Exit(1) from None


if __name__ == "__main__":
    app()
