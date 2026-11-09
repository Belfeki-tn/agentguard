# AgentGuard

**A local permission gateway for MCP tool calls.**

Developed and maintained by **Belfeki.tn**. Apache-2.0.

AgentGuard sits between an MCP client and one trusted stdio server. It evaluates
every handled tool call against deterministic YAML policy, blocks denied calls,
and waits for a one-time local approval when required. SQLite records metadata
without storing tool arguments or results.

> Early implementation, not a production security assurance. Only calls routed
> through AgentGuard are governed. The gateway is not a sandbox, and same-UID
> processes are trusted by the approval interface.

## Start here

Follow the [five-minute quickstart](docs/QUICKSTART.md) to install from a source
checkout, run a real SDK client through the proxy, verify allow/deny, approve a
protected call, and inspect audit metadata. No public PyPI release is assumed.

Linux/macOS and Python 3.11+ are required for the full gateway. CI targets Python
3.11–3.14 on both platforms; see the validation report for what was run locally.
Windows proxy/approval support is not implemented.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
cp examples/quickstart-policy.yaml agentguard.yaml
chmod 600 agentguard.yaml
agentguard doctor --config agentguard.yaml --stdio-command "python examples/quickstart_server.py"
agentguard policy test --config agentguard.yaml --tool upstream.echo --json
python examples/quickstart_client.py --config agentguard.yaml --tool echo
```

The included SDK host launches AgentGuard as its MCP stdio server. For another
compatible host, configure it to launch:

```bash
agentguard proxy --config /absolute/path/to/agentguard.yaml \
  --stdio-command "/absolute/path/to/.venv/bin/python /absolute/path/to/server.py"
```

Use only trusted upstream commands and remove direct upstream connections from
that host. The proxy's stdout is protocol-only; diagnostics go to stderr.

## Architecture and policy

```text
MCP client → AgentGuard stdio server → guarded tool handler → policy engine
                                           ↕          ↓ allow / consumed approval
                                 approvals + audit   SDK client → trusted upstream
```

The policy engine is pure and independent of MCP. Policies use exact,
case-sensitive `server.tool` identities. The operator configures the server ID;
client arguments cannot override it. Unmatched tools are denied. Conflicts use
`deny > approve > allow`, with the first rule breaking equal-action ties.

```yaml
version: 1
defaults:
  action: deny
rules:
  - id: allow-echo
    tools: ["upstream.echo"]
    action: allow
```

The public API remains `parse_policy`, `load_policy`, and `evaluate` from
`agentguard.policy`. See [policy semantics](docs/POLICY_ENGINE.md) and
[proxy architecture](docs/MCP_PROXY.md).

## Feature status

| Feature | Status |
| --- | --- |
| Strict YAML schema, exact matching, default denial | Implemented |
| Single-upstream official SDK stdio tool adapter | Implemented |
| Exact-request approvals with expiration and atomic single use | Implemented, POSIX/same-UID trust boundary |
| Metadata-only SQLite audit | Implemented, local and unencrypted |
| Doctor preflight and offline policy simulation, JSON output | Implemented |
| Dashboard, HTTP gateway, cloud service, multiple upstream orchestration | Not implemented |
| Sandbox, argument safety analysis, cross-account approval broker | Not implemented |

## Approvals and audit

From a separate trusted terminal:

```bash
agentguard approvals list
agentguard approvals show <request-id>
agentguard approvals approve <request-id>
# Or: agentguard approvals reject <request-id>
```

Approvals bind the exact tool, arguments, server, and originating execution
context. They expire and cannot be reused. No approval input uses MCP stdin.
The default private state directory is `~/.local/state/agentguard`; use the same
`--state-dir` across proxy, doctor, and approval commands when overriding it.
For approvals, the option comes before the subcommand:
`agentguard approvals --state-dir /private/path list`.

Audit excludes all arguments, credentials, results, and raw exception messages.
Live `show` output deliberately displays exact arguments to the operator. Protect
terminal scrollback. Read [approval workflow](docs/APPROVAL_WORKFLOW.md) and
[audit logging](docs/AUDIT_LOGGING.md) for permissions, lifecycle, and failure behavior.

## Security limits

Upstreams can act during startup and allowed calls; run them with least-privilege
OS access and credentials. Same-UID agents can access approvals or alter state.
Cancellation cannot undo submitted side effects, and an interrupted request may
have an unknown outcome. AgentGuard never retries automatically. SQLite audit is
not a tamper-proof ledger. Doctor checks local prerequisites without launching
the upstream; it does not certify MCP compatibility or safe tool behavior.

See [SECURITY.md](SECURITY.md) before routing real tools. Public release remains a
manual maintainer decision subject to the [release checklist](docs/RELEASE_CHECKLIST.md).

## Develop and contribute

```bash
python -m pip install -e '.[dev]'
python -m pytest -v
ruff check .
ruff format --check .
python -m pip check
git diff --check
python -m hatchling build
python scripts/check_artifacts.py dist
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md),
[roadmap](docs/ROADMAP.md), and the [Milestone 4 validation report](docs/MILESTONE_4_VALIDATION.md).

Copyright 2026 **Belfeki.tn**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
