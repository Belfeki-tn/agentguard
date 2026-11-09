import typer

app = typer.Typer(help="AgentGuard (scaffold; MCP enforcement not implemented).")


@app.command()
def status() -> None:
    """Show implementation status."""
    typer.echo("AgentGuard scaffold by Belfeki.tn — MCP proxy not yet implemented.")


if __name__ == "__main__":
    app()
