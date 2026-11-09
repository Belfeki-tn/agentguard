# AgentGuard

**The permission firewall for AI agents.**

Developed and maintained by **Belfeki.tn**.

> Status: policy engine, MCP stdio proxy, local POSIX approvals, and metadata-only SQLite audit implemented. Do not rely on this early project for production security.

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
ruff format --check .
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

The proxy waits for an explicit local decision on `approve` calls. Review requests
from a separate trusted terminal using `agentguard approvals list`,
`agentguard approvals show <request-id>`, and `agentguard approvals approve <request-id>`
or `reject <request-id>`. Approvals expire and can be consumed only once.
See [the approval workflow](docs/APPROVAL_WORKFLOW.md) for a working example and
the same-UID trust boundary, and [audit logging](docs/AUDIT_LOGGING.md) for storage,
privacy, and uncertain execution outcomes. State defaults to `~/.local/state/agentguard`;
use `--state-dir` for a different private location. POSIX filesystem protection
and FIFOs are required for this release.

## Security boundary
The gateway only controls tool calls actually routed through it. It is not a sandbox, a substitute for least-privilege credentials, or a guarantee against compromised upstream servers. Only stdio transport is implemented.

## Community
See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License
Apache-2.0. Copyright 2026 Belfeki.tn.
