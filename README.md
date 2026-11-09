# AgentGuard

**The permission firewall for AI agents.**

Developed and maintained by **Belfeki.tn**.

> Status: early-stage scaffold. The MCP proxy and enforcement are **not implemented yet**. Do not rely on this project for production security.

AgentGuard aims to provide a local-first MCP gateway with deterministic allow/deny/approve policies, human approval, redacted audit logs, and policy simulation.

## Problem
AI agents can call powerful tools. Developers need enforceable, inspectable controls before sensitive actions execute.

## Planned v0.1 scope
- MCP stdio proxy with pre-execution interception
- YAML rules with deny-by-default behavior
- Terminal approval tied to exact tool-call arguments
- Local redacted audit trail
- Offline policy simulation

## Development setup
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e '.[dev]'
pytest
agentguard --help
```

The current CLI is a scaffold and does not proxy or secure MCP calls.

## Configuration
See `examples/agentguard.yaml`. The sample format is provisional.

## Security boundary
The future gateway will only control tool calls actually routed through it. It is not a sandbox, a substitute for least-privilege credentials, or a guarantee against compromised upstream servers. Do not expose a proxy to untrusted networks by default.

## Community
See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License
Apache-2.0. Copyright 2026 Belfeki.tn.
