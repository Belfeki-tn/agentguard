# AgentGuard

**The permission firewall for AI agents.**

Developed and maintained by **Belfeki.tn**.

> Status: deterministic policy engine and single-upstream MCP stdio tool proxy implemented. Approval workflows are not implemented. Do not rely on this early project for production security.

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
ruff check .
agentguard --help
```

Launch a trusted MCP server behind the proxy:

```bash
agentguard proxy --config examples/proxy-policy.yaml \
  --stdio-command "python examples/demo_server.py"
```

Configure your MCP host to launch this command. See [MCP_PROXY.md](docs/MCP_PROXY.md)
for a working SDK client example, server identities, failure behavior, and limitations.

## Configuration
See `examples/agentguard.yaml` and [the policy engine guide](docs/POLICY_ENGINE.md).
Version 1 policies support exact server-qualified tool names and `allow`, `deny`,
and `approve` (approval required). Unmatched tools are denied. Conflicting rules
use `deny > approve > allow`; the first rule wins ties. Invalid configuration is rejected.

The standalone Python API evaluates policies without executing tools:

```python
from agentguard.policy import evaluate, load_policy

policy = load_policy("examples/agentguard.yaml")
decision = evaluate(policy, "filesystem.read_file")
print(decision.model_dump(mode="json"))
```

The proxy blocks `approve` calls with an approval-required result; approval collection
and approval-based execution are planned.

## Security boundary
The gateway only controls tool calls actually routed through it. It is not a sandbox, a substitute for least-privilege credentials, or a guarantee against compromised upstream servers. Only stdio transport is implemented.

## Community
See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License
Apache-2.0. Copyright 2026 Belfeki.tn.
