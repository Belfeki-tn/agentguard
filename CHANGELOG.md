# Changelog

Developed and maintained by **Belfeki.tn**.

## Unreleased

Package metadata currently identifies version `0.0.1`. No public package or GitHub
release is implied by this changelog.

### Implemented

- Strict version 1 YAML policies, deterministic exact matching, structured decisions,
  deny-by-default, and deny > approve > allow conflict precedence.
- Official MCP SDK stdio adapter for one trusted upstream, guarded tool calls,
  discovery, cancellation, timeouts, sanitized failures, and no automatic retries.
- Local POSIX approval CLI with exact-call/session binding, expiration, atomic
  single-use consumption, and private diskless FIFO previews.
- Persistent metadata-only SQLite audit, including durable execution intent.
- Local `doctor` preflight and offline `policy test` simulation with JSON output.
- Executable quickstart client/server/policy, source/wheel verification, expanded
  Linux/macOS CI matrix, and Apache-2.0 license/maintainer notice inclusion.

### Limitations

- Early implementation, not a production security assurance.
- No Windows proxy/approval support, HTTP gateway, multiple upstream orchestration,
  dashboard, cloud service, sandbox, or cross-account approval broker.
- Same-UID processes are trusted; audit is local, unencrypted, and not tamper-proof.
- Only routed calls are governed; cancellation cannot undo submitted side effects.
