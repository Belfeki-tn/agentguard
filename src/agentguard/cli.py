"""AgentGuard command line interface. Developed and maintained by Belfeki.tn."""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import anyio
import typer

from agentguard.approvals import live_preview
from agentguard.diagnostics import diagnose
from agentguard.policy import evaluate, load_policy
from agentguard.proxy import ProxySettings, parse_command, run_proxy
from agentguard.storage import StateStore

app = typer.Typer(
    help="AgentGuard MCP permission gateway by Belfeki.tn.", pretty_exceptions_enable=False
)


@app.command()
def status() -> None:
    """Show implementation status."""
    typer.echo("AgentGuard by Belfeki.tn — stdio enforcement, local approvals, SQLite audit.")


@app.command()
def doctor(
    config: Annotated[Path, typer.Option("--config", help="Policy YAML to inspect.")],
    stdio_command: Annotated[
        str, typer.Option("--stdio-command", help="Upstream command to check only.")
    ],
    state_dir: Annotated[Path, typer.Option("--state-dir")] = Path("~/.local/state/agentguard"),
    server_id: str = typer.Option("upstream", "--server-id"),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable diagnostics."),
) -> None:
    """Check local prerequisites without launching an upstream or calling tools."""
    checks = diagnose(config, stdio_command, state_dir, server_id)
    ok = all(check.ok for check in checks)
    if json_output:
        typer.echo(json.dumps({"ok": ok, "checks": [asdict(check) for check in checks]}))
    else:
        for check in checks:
            typer.echo(f"{'PASS' if check.ok else 'FAIL'} {check.check}: {check.message}")
        typer.echo("Preflight only: no upstream process or MCP tool was executed.")
    if not ok:
        raise typer.Exit(1)


policy_app = typer.Typer(help="Inspect deterministic policy decisions without executing tools.")
app.add_typer(policy_app, name="policy")


@policy_app.command("test")
def policy_test(
    config: Annotated[Path, typer.Option("--config", help="Policy YAML file.")],
    tool: Annotated[str, typer.Option("--tool", help="Exact server-qualified tool name.")],
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable decision."),
) -> None:
    """Simulate allow, deny, or approve using the existing pure policy engine."""
    try:
        decision = evaluate(load_policy(config), tool)
    except Exception:  # noqa: BLE001 - invalid configuration must not expose policy contents.
        if json_output:
            typer.echo(json.dumps({"error": "invalid_policy_or_tool"}))
        else:
            typer.echo("Invalid policy or tool name; check docs/POLICY_ENGINE.md.", err=True)
        raise typer.Exit(2) from None
    payload = {
        "tool": tool,
        "action": decision.action,
        "matched_rule": decision.matched_rule.id if decision.matched_rule else None,
        "explanation": decision.explanation,
    }
    if json_output:
        typer.echo(json.dumps(payload, ensure_ascii=True))
    else:
        typer.echo(
            f"Tool: {tool}\nDecision: {decision.action}\n"
            f"Matched rule: {payload['matched_rule'] or '(none)'}\n"
            f"Explanation: {decision.explanation}"
        )


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
    state_dir: Annotated[
        Path, typer.Option("--state-dir", help="Private approval/audit directory.")
    ] = Path("~/.local/state/agentguard"),
    approval_timeout: float = typer.Option(
        60.0, "--approval-timeout", help="Approval lifetime in seconds."
    ),
) -> None:
    """Serve a single trusted upstream over stdio, enforcing policy on every tool call."""
    try:
        policy = load_policy(config)
        settings = ProxySettings(
            parse_command(stdio_command), server_id, timeout, state_dir, approval_timeout
        )
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


approvals_app = typer.Typer(
    help="Inspect and decide approvals from a separate trusted terminal.",
    pretty_exceptions_enable=False,
)
app.add_typer(approvals_app, name="approvals")


@approvals_app.callback()
def approvals_options(
    ctx: typer.Context,
    state_dir: Annotated[Path, typer.Option("--state-dir")] = Path("~/.local/state/agentguard"),
) -> None:
    """Authorize the operator through owner-only POSIX storage permissions."""
    try:
        ctx.obj = StateStore(state_dir)
    except Exception:  # noqa: BLE001 - do not expose SQLite paths or exception payloads.
        typer.echo("Approval storage unavailable or unsafe.", err=True)
        raise typer.Exit(1) from None


@approvals_app.command("list")
def approvals_list(ctx: typer.Context) -> None:
    """List pending request metadata without arguments."""
    try:
        typer.echo(json.dumps(ctx.obj.list_pending(), ensure_ascii=True, indent=2))
    except Exception:  # noqa: BLE001 - sanitize operator storage errors.
        typer.echo("Cannot list approvals.", err=True)
        raise typer.Exit(1) from None


@approvals_app.command("show")
def approvals_show(ctx: typer.Context, request_id: str) -> None:
    """Display live exact arguments and risk context; output may contain secrets."""
    try:
        preview = anyio.run(live_preview, ctx.obj, request_id)
        typer.echo(json.dumps(preview, ensure_ascii=True, indent=2))
    except Exception:  # noqa: BLE001 - sanitize preview and storage errors.
        typer.echo("Live approval preview unavailable; request may no longer be pending.", err=True)
        raise typer.Exit(1) from None


@approvals_app.command("approve")
def approvals_approve(ctx: typer.Context, request_id: str) -> None:
    """Explicitly approve one live request after reviewing it with 'show'."""
    try:
        # Check the originating proxy is still alive and serving this exact ID.
        anyio.run(live_preview, ctx.obj, request_id)
        ctx.obj.decide(request_id, True)
        typer.echo("Approved for one execution by the originating request.")
    except Exception:  # noqa: BLE001 - any approval failure must refuse authorization.
        typer.echo("Approval refused: request unavailable, expired, or already decided.", err=True)
        raise typer.Exit(1) from None


@approvals_app.command("reject")
def approvals_reject(ctx: typer.Context, request_id: str) -> None:
    """Reject one pending request; it can never execute under this approval."""
    try:
        ctx.obj.decide(request_id, False)
        typer.echo("Rejected.")
    except Exception:  # noqa: BLE001 - sanitize operator errors.
        typer.echo("Rejection refused: request expired or already decided.", err=True)
        raise typer.Exit(1) from None


if __name__ == "__main__":
    app()
