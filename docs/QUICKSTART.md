# AgentGuard in five minutes

Developed and maintained by **Belfeki.tn**. This is an early local-first security
gateway, not a sandbox or a production security assurance. These examples use
harmless local echo tools. The full proxy needs Linux/macOS, Python 3.11+, POSIX
ownership, and named FIFOs. Windows proxy/approval support is not implemented.

## 1. Install from a source checkout

Obtain the repository source and run these commands from its root. No public PyPI
release is assumed. Use a normal terminal and a private OS account you trust:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
agentguard --help
```

Keep the checkout: its `examples/` files are source-distribution examples, not
installed console commands. In a second terminal, enter the same checkout and
activate the same `.venv` before using the approval commands below.

## 2. Create a policy and check your environment

```bash
cat > agentguard.yaml <<'YAML'
version: 1
defaults:
  action: deny
rules:
  - id: allow-echo
    tools: ["upstream.echo"]
    action: allow
  - id: deny-echo
    tools: ["upstream.blocked_echo"]
    action: deny
  - id: review-echo
    tools: ["upstream.protected_echo"]
    action: approve
YAML
chmod 600 agentguard.yaml
agentguard doctor --config agentguard.yaml --stdio-command "python examples/quickstart_server.py"
agentguard policy test --config agentguard.yaml --tool upstream.echo
agentguard policy test --config agentguard.yaml --tool upstream.protected_echo --json
```

Doctor checks Python/platform, policy validity, file permissions, executable
availability, and the approval/audit environment. It briefly creates private
temporary SQLite/FIFO probes and removes them. It does **not** launch the command,
initialize an upstream, execute a tool, initialize your audit database, or expire
approvals. Success is a local preflight, not a guarantee of MCP compatibility.
The default state location is `~/.local/state/agentguard`; doctor does not create it.

Executable checks follow symlinks to an executable regular file. Group/world-writable
executables fail, except when the resolved file is the same interpreter already
running AgentGuard. Hosted toolcaches and macOS framework installers can give Python
these permissions. Reusing that interpreter passes with an explicit warning;
file identity, not its name, directory prefix, or a CI environment flag, determines
this narrow exception. Use a private Python installation on shared hosts. Doctor
does not certify executable provenance, directory-chain safety, ACLs, or protection
against replacement after the check. Proxy policy/approval enforcement is unchanged.

Policy simulation is offline. It prints the qualified tool, action, matched rule
ID (or null), and explanation. `--json` emits one JSON object. Simulation exits 0
for every valid decision, including deny/approve, and 2 for invalid policy/tool
input. Doctor exits 0 on all-pass, 1 on failed checks, and 2 for CLI usage errors.
Neither command executes tools or asks for approvals.

The server ID is operator-configured (`upstream` by default). Client arguments
cannot change it. Tool matching is exact and case-sensitive; precedence is
`deny > approve > allow`, with deny as the unmatched default.

## 3. Launch through a compatible MCP client and verify allow/deny

The repository includes a small host using the official MCP Python SDK. It starts
AgentGuard as its stdio server; AgentGuard then starts the example upstream.
This is a real client → proxy → upstream connection, not a policy-only simulation:

```bash
python examples/quickstart_client.py --config agentguard.yaml --tool echo --message hello
python examples/quickstart_client.py --config agentguard.yaml --tool blocked_echo --message hello
```

Both runs print discovered tool names. `echo` returns `hello` with `isError: false`.
`blocked_echo` returns `isError: true` and an `agentguard.code` of `denied`, without
executing the upstream tool. The host script itself exits successfully after
printing this expected MCP tool-error result. Tool listing does not grant permission.

To use another compatible stdio MCP host, configure it to launch:

```bash
agentguard proxy --config /absolute/path/to/agentguard.yaml \
  --stdio-command "/absolute/path/to/.venv/bin/python /absolute/path/to/examples/quickstart_server.py"
```

Use absolute paths and the correct virtual environment interpreter. Host-specific
configuration formats vary; the included SDK client is the tested, copy-pasteable
host example. Remove direct upstream connections from the host. The proxy's stdout
is exclusively MCP protocol; gateway diagnostics go to stderr. The demonstration
client's own stdout intentionally prints results for you to inspect.

## 4. Approve one protected call

In terminal A:

```bash
python examples/quickstart_client.py --config agentguard.yaml --tool protected_echo --message hello
```

It waits without executing upstream. Within 60 seconds, in terminal B (same
checkout, virtual environment, and trusted OS user):

```bash
agentguard approvals list
```

Copy the pending request's `request_id` and substitute it below; do not type the
angle brackets literally:

```bash
agentguard approvals show <request-id>
agentguard approvals approve <request-id>
# To reject instead:
# agentguard approvals reject <request-id>
```

Review the server, tool, exact arguments, and risk context before approving.
Terminal A returns `hello` after one approved invocation. Approval cannot be reused;
a second `approve` fails. Rejection, timeout, and cancellation do not execute the
tool. Keep the host's request timeout longer than the approval wait plus execution;
the example host allows 120 seconds.

`show` deliberately reveals exact arguments, which may contain secrets. Protect
your terminal and avoid redirecting previews to shared logs. The approval channel
does not use MCP stdin. Same-UID processes are trusted and can approve or edit
state; this is not human attestation or OS-level agent isolation.

For a different state directory, use the same `--state-dir /private/path` with
doctor, proxy, and the example client. The approval syntax is
`agentguard approvals --state-dir /private/path list` (the group option precedes
`list`, `show`, `approve`, or `reject`). Existing state must be owner-only (0700),
with a 0600 database and safe, non-symlink ancestors.

## 5. Inspect audit metadata

After the example clients exit, this stdlib-only command reads the default audit
database without requiring the external SQLite CLI:

```bash
python - <<'PY'
import sqlite3
from contextlib import closing
from pathlib import Path

path = Path.home() / ".local/state/agentguard/audit.sqlite3"
with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
    for row in db.execute(
        "SELECT qualified_tool,decision,rule_id,approval_state,outcome "
        "FROM requests ORDER BY timestamp"
    ):
        print(row)
PY
```

Expect allow/success, deny/denied, and approve/consumed/success rows for the three
calls. Arguments, credentials, tool results, and raw exceptions are not audit
fields. `execution_started` without completion means the outcome may be unknown;
investigate before retrying non-idempotent operations. No automatic retries occur.

## Troubleshooting and next steps

- Doctor rejects writable policies: use a regular file and `chmod go-w agentguard.yaml`.
- Doctor rejects state: choose a private owned location; do not weaken filesystem checks.
  Existing directories need 0700, database files 0600, and ancestors must not be
  symlinks or group/world writable (trusted sticky temporary directories are allowed).
- Executable missing: activate `.venv` or use an absolute executable path. Doctor
  checks the executable, not script arguments, upstream behavior, or credentials.
- Approval preview unavailable: the original call must still be pending in a live
  proxy. Expired or abandoned requests cannot be resumed.
- Proxy startup/tool errors are sanitized by design. Inspect doctor results and
  audit metadata; do not enable raw protocol logging to collect secrets.

Only routed tool calls are protected. Upstreams are trusted programs and can act
at startup; policy is not a sandbox or argument safety check. See
[security](../SECURITY.md), [policy semantics](POLICY_ENGINE.md),
[proxy scope](MCP_PROXY.md), [approvals](APPROVAL_WORKFLOW.md), and
[audit logging](AUDIT_LOGGING.md) before using real tools.
