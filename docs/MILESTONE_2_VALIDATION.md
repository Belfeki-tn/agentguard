# Milestone 2 validation report

Developer and maintainer: **Belfeki.tn**.

Validated on 2026-11-09 with Python 3.12.3, MCP SDK 2.3.0, AnyIO 4.15.1,
pytest 9.2.0, and Ruff 0.17.4. MCP dependencies were installed from the existing
local package cache because the environment could not access the package index.

| Check | Result |
| --- | --- |
| `python -m pytest -v` | 126 passed in 22.29 seconds, with the sandbox workaround below |
| `ruff check .` | Passed |
| `git diff --check` | Passed |
| Ruff formatting of new/edited Python files | Passed |
| `python -m pip check` | Passed |

Commands used the project's `.venv` executables. The full suite includes existing
policy tests and 41 new proxy tests. Integration tests launch real stdio SDK
client, gateway, and mock-server subprocesses. The mock writes an execution
counter before any tool work; assertions demonstrate that blocked calls never
execute. Tests also cover cancellation, upstream crashes, timeouts, startup
failure, pagination, identity isolation, concurrency, dotted names, unsupported
execution paths, sanitized diagnostics, and the documented demo server.

## Environment caveat

The initial unmodified stdio runs timed out during initialization. A minimal
AnyIO thread-call reproduction showed `PermissionError: Operation not permitted`
when asyncio tried to write to its internal self-pipe socket. This sandbox's
network restriction prevents the event loop from waking on thread completion.

For validation only, a temporary `.pth` bootstrap and selector hook were placed
in the ignored virtual environment. The hook capped epoll wait intervals at
10 milliseconds, allowing the loop to observe completed work despite the blocked
wake-up socket. It did not change the proxy, SDK protocol, policy evaluation,
tool handlers, or assertions. Both temporary files were removed after validation;
no workaround is included in project source. Integration tests in this same
restricted sandbox need that environment workaround again. A normal environment
must still run the quality gates before release; Windows and other Python
versions were not exercised here.
