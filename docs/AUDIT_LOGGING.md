# Local SQLite audit logging

Developer and maintainer: **Belfeki.tn**.

Every tool call handled by the running proxy is recorded in
`~/.local/state/agentguard/audit.sqlite3`, or the directory selected by
`--state-dir`. Protocol messages rejected by the MCP SDK before reaching the
tool handler are outside this call audit. The standalone policy API remains pure
and does not create audit records. Audit storage is mandatory in the proxy CLI.

## Records

`requests` stores the latest state for each cryptographically random request ID.
`audit_events` appends a metadata snapshot on receipt, policy evaluation, approval
transitions, execution intent, and completion/failure. Each event contains:

- Request identifier and UTC Unix timestamp (seconds).
- Configured server identity and exact qualified tool name.
- Policy decision and matched rule ID, or null if no rule matched.
- Approval state, or null for calls that did not require approval.
- Sanitized execution outcome.

Request rows additionally contain the random proxy session ID, expiry time, and
keyed approval binding digest. The HMAC key exists only in the proxy's memory.
Invalid tool names are represented as `<invalid>` rather than recording arbitrary
malformed input. Names and rule identifiers are treated as metadata; avoid placing
secrets in names. An evaluation failure is initially represented as decision
`error`, and default denials have no matched rule ID.

Raw arguments, request bodies, upstream command arguments, credentials, raw
exception messages, approval previews, and tool results are never audit fields.
The logger does not guess which argument names are sensitive: it omits every
argument. Upstream structured content cannot supply audit outcome labels.
The preview IPC described in [APPROVAL_WORKFLOW.md](APPROVAL_WORKFLOW.md) holds
arguments only in memory/kernel buffers and is separate from audit storage.

## Execution and failure semantics

Before any upstream call, the proxy durably records `execution_started`. For
approval-gated calls, atomic consumption also records this intent in the same
transaction as the transition to `consumed`. Completion adds `success`,
`tool_error`, or a sanitized gateway outcome such as `denied`, `approval_required`,
`upstream_error`, or `upstream_unavailable`. Gateway errors and normal upstream
tool-error results are distinguished internally; upstream content is not logged.

SQLite connections are operation-local, use parameterized statements, a short
100 ms lock timeout, and `synchronous=FULL`. Write transactions serialize state
changes; transitions and their corresponding events commit together. Busy,
corrupt, unreadable, or unwritable storage never results in allow-all behavior.
No automatic migration, replacement, or repair of corrupt databases is attempted.

If recording receipt or intent fails, execution is refused. If recording completion
fails after an upstream side effect, that effect cannot be rolled back: the
proxy returns a sanitized `audit_error`, taints its session, and never retries.
The durable record may remain at `execution_started`, indicating an uncertain
outcome. Cancellation records `cancelled_outcome_unknown` conservatively, even
when cancellation occurred before submission. Approval state separately shows
whether authorization was cancelled or had already been consumed.

If SQLite is unavailable, no system can guarantee that the failure itself is
persisted there. Best-effort cancellation still runs, the live request stops,
and a later database recovery cannot resurrect that originating task. Investigate
upstream state before manually retrying any uncertain non-idempotent operation.

## Filesystem protection and inspection

State directories must be owned by the effective user and private (0700); database
files are created with 0600 and checked before use. Symlinks, hard links, wrong
ownership, broad permissions, and unsafe writable ancestors are rejected rather
than silently chmodding an existing shared path. SQLite rollback journals inherit
the private database's permissions and reside inside the protected directory.
The database is local and unencrypted. OS account isolation and disk protection
remain the operator's responsibility; this is not a tamper-proof audit ledger.

For read-only investigation with the SQLite CLI, close the proxy first or account
for lock contention. For example:

```bash
sqlite3 -readonly ~/.local/state/agentguard/audit.sqlite3 \
  'SELECT request_id,datetime(timestamp,"unixepoch"),server_id,qualified_tool,decision,rule_id,approval_state,outcome FROM audit_events ORDER BY event_id;'
```

Do not share database files or put them in a directory writable by untrusted
accounts. There is no retention/rotation service in this milestone; operators
must manage disk usage and private backups. Removing or corrupting active storage
causes calls to fail closed. Same-UID processes and administrators can alter
records, and tools accessed outside the proxy are not audited.
