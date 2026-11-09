# Local human approval workflow

Developer and maintainer: **Belfeki.tn**.

The stdio proxy now waits for an explicit local decision when policy returns
`approve`. The policy API and precedence remain unchanged. No approval input is
read from MCP stdin. Use the approval CLI in a separate trusted terminal.

## Start and review

Configure your MCP host to launch the proxy with a trusted upstream:

```bash
agentguard proxy --config examples/approval-policy.yaml \
  --stdio-command "python examples/demo_server.py" --approval-timeout 60
```

When the host calls `echo`, the invocation waits without executing upstream.
In a separate terminal, using the same OS account:

```bash
agentguard approvals list
agentguard approvals show <request-id>
agentguard approvals approve <request-id>
# Or:
agentguard approvals reject <request-id>
```

`show` displays exact arguments, server identity, qualified tool name, rule ID,
and risk context. Review every argument before issuing `approve`. The approve
command is the explicit operator decision; it does not prompt or read stdin.
It verifies that the originating proxy still serves a live preview before
committing the decision. `reject` invalidates a pending request directly.
Duplicate decisions exit unsuccessfully. Operator errors are sanitized.

The default state directory is `~/.local/state/agentguard`. To use another
private location, supply the same path to both processes:

```bash
agentguard proxy --config examples/approval-policy.yaml \
  --stdio-command "python examples/demo_server.py" --state-dir /private/path/agentguard
agentguard approvals --state-dir /private/path/agentguard list
agentguard approvals --state-dir /private/path/agentguard show <request-id>
agentguard approvals --state-dir /private/path/agentguard approve <request-id>
```

The `approvals` group option precedes its subcommand. Startup refuses unsafe or
unavailable storage before launching upstream. Audit storage is required for
both automatically allowed and approval-gated calls. Existing `allow` and `deny`
policy behavior is unchanged; `approve` now waits instead of immediately returning
approval-required. Timeouts/rejections retain a sanitized `approval_required`
tool error. Approval or audit infrastructure failures produce `audit_error`.

`--approval-timeout` defaults to 60 seconds and must be finite and positive.
`--timeout` still independently bounds initialization/discovery and upstream
execution. Configure the MCP host's request timeout to accommodate the approval
wait plus execution time; an earlier host cancellation safely abandons approval.

## Exact request binding

Each handled call receives a cryptographically random 256-bit identifier. Each
proxy session has its own random identifier and in-memory HMAC key. Approval
binds the request ID, session, configured upstream server identity, full qualified
tool name, canonical arguments, and originating SDK request/execution context.
Neither client arguments nor upstream handshake names select the server identity.

Canonicalization uses sorted string object keys and compact ASCII-escaped JSON.
It preserves array order, null versus an empty object, and booleans versus
integers. Non-JSON values, non-string object keys, NaN, and Infinity are rejected.
This is a local deterministic encoding, not a claim of RFC 8785 interoperability.
Approval-gated arguments are limited to 32 KiB of canonical JSON so previews
remain bounded. The proxy snapshots these arguments before waiting and forwards
that snapshot, preventing mutable input substitution. The database stores only
a keyed binding digest, not the arguments or a reusable bearer token.

## Lifecycle

| Current state | Permitted next states |
| --- | --- |
| Pending | Approved, Rejected, Expired, Cancelled |
| Approved | Consumed, Expired, Cancelled |
| Rejected, Expired, Cancelled, Consumed | None |

Decisions use conditional SQLite updates inside write transactions. Consumption
matches the request, live session, binding, approved state, and unexpired deadline
in one transaction, and records execution intent before committing. Exactly one
consumer can succeed. The coordinator also enforces a monotonic deadline, so a
wall-clock rollback cannot extend a live request. A forward clock jump can expire
a request early, which fails closed.

Pending requests are cancelled on task cancellation, coordinator failures, or
normal client disconnection. The proxy checks for cancellation again before
submission. Cancellation after consumption leaves authorization spent even if
execution has not begun. A session transport failure taints the session; later
calls are refused. There are no retries or automatic replay after restart.

An abrupt kill may leave pending/approved metadata until its recorded deadline;
listing or reading state expires it lazily. A restarted process cannot consume
it: the originating task, session, and HMAC key no longer exist. Consumed records
never return to approved. A consumed approval does not prove that execution
completed; consult its audit outcome and investigate uncertain side effects.

## Private local IPC

This release requires POSIX ownership, `O_NOFOLLOW`, and named FIFOs; Windows
approval/audit storage is not implemented. The state directory and per-session
directories are owner-only (0700). SQLite and FIFO objects are owner-only (0600).
Symlinked paths, hard-linked database/FIFO objects, wrong owners, group/world
access, and unsafe writable ancestors are refused. Normal system sticky temporary
directories are supported. The trusted principal is the effective OS user ID.

SQLite coordinates metadata and decisions across processes. For previews, the
operator creates a random private FIFO in the active session directory and opens
its read end. The live coordinator validates the FIFO descriptor's type, owner,
permissions, and link count before writing. It unlinks the FIFO name once opened.
Arguments travel only through the kernel pipe buffer; no regular preview file
or argument column is created. JSON escaping prevents terminal control characters
from being interpreted by the display. Broken preview channels, oversized data,
and unavailable coordinators fail closed. The CLI cleans up its FIFO on exit.

Exact arguments may contain secrets. `show` deliberately reveals them to the
authorized operator, so protect terminal scrollback and do not redirect previews
to logs or shared files. Arguments also exist in process memory and may be
exposed by OS swap/core dumps; memory locking and encrypted swap are not supplied.

## Trust boundary

Owner-only access verifies the approving OS principal; it does not prove that a
human, rather than a program running as that principal, typed the command. Any
process with the same UID, and privileged OS administrators, are trusted. An
agent with shell/file access under that UID could approve requests or edit state.
Keep untrusted clients and workloads outside this account/security boundary;
this milestone does not provide cross-account delegation or a hardened broker.
The launched upstream is also trusted and is not sandboxed.

Only calls routed through AgentGuard are protected. Approval grants one attempt
for the originating invocation, not general permission to use a tool. Cancellation
cannot undo side effects already submitted upstream, and new client calls are new
requests. [AUDIT_LOGGING.md](AUDIT_LOGGING.md) explains durable intent and uncertain
outcomes. No dashboard, HTTP transport, or cloud service is involved.
