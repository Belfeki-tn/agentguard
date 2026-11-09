# Milestone 3 validation report

Developer and maintainer: **Belfeki.tn**.

Validated on 2026-11-09 using the project's `.venv`, Python 3.12.3, official MCP
SDK 2.3.0, AnyIO 4.15.1, pytest 9.2.0, and Ruff 0.17.4. SQLite comes from Python's
standard library; no new third-party dependencies were needed.

| Required gate | Result |
| --- | --- |
| `python -m pytest -v` | 169 passed, with the sandbox workaround below |
| `ruff check .` | Passed |
| `ruff format --check .` | Passed |
| `python -m pip check` | Passed; no broken requirements |
| `git diff --check` | Passed |

No tests were skipped and no dependency-related checks were unavailable. No
changes were committed or pushed. The standalone policy implementation and its
public API were preserved.

## Evidence

The suite includes all previous policy/proxy tests and 43 new approval/audit
tests. A separate real CLI subprocess inspects exact arguments over the private
FIFO and approves a real stdio MCP call. The upstream counter proves one execution,
with a consumed approval and one durable execution-intent event. Rejection,
expiration, pending-call cancellation, and proxy disconnection prove zero upstream
executions. Concurrent approvals consume only their own exact calls.

Unit and integration checks also cover:

- Every approval state and duplicate/expired decisions.
- Concurrent decision and consumption attempts, with one winner.
- Server/tool/argument/session/origin substitution and mutable request snapshots.
- Cancellation between consumption and submission, with zero execution.
- Monotonic expiration despite a wall-clock rollback.
- Audit persistence and absence of argument secrets from SQLite.
- SQLite lock/corruption failures, unavailable approval state, and completion-audit
  failure after execution without retry.
- Prevention of upstream content injecting audit outcome labels.
- Ownership, permission, symlink, hard-link validation in the implementation,
  regular-file FIFO substitution, unsafe ancestors, and private creation under a
  permissive umask. Ownership checks were exercised by mocking a different UID;
  a separate real OS account was not used.

A concurrency run exposed a lock race when setting connection durability before
starting a write transaction. The implementation now obtains `BEGIN IMMEDIATE`
first and verifies SQLite's FULL-or-stronger synchronous mode inside the
reservation; locked stores still fail closed. The final suite passed after that
change.

## Environment caveat and limits

As documented for Milestone 2, this sandbox blocks writes to asyncio's internal
wake-up socket. An initial ordinary stdio test attempt therefore failed during
initialization, before exercising approvals. Validation used a temporary module
and `.pth` bootstrap in the ignored `.venv` to cap epoll waits at 10 milliseconds.
This lets event loops observe completed work despite the blocked wake-up socket.
It does not replace tool handlers, mock the approval channel, or change assertions,
MCP messages, policy evaluation, SQLite transitions, or execution counters. The
temporary files were removed after the quality gates. No workaround is shipped
in project source. Rerunning stdio tests in this same restricted sandbox requires
that environment accommodation again.

This validation covers Linux/POSIX on Python 3.12. It does not establish Windows
support, cross-UID approval delegation, OS-level agent isolation, power-loss
durability, or production readiness. Same-UID processes are trusted, and local
audit is not tamper-proof. See [APPROVAL_WORKFLOW.md](APPROVAL_WORKFLOW.md) and
[AUDIT_LOGGING.md](AUDIT_LOGGING.md) for security boundaries and uncertain outcomes.
