# Milestone 4 validation report

Developer and maintainer: **Belfeki.tn**.

Validated locally on 2026-11-09 with Linux, Python 3.12.3, MCP SDK 2.3.0,
Hatchling 1.33.0, pytest 9.2.0, and Ruff 0.17.4. Package version remains `0.0.1`;
no publication, release, commit, or push was performed.

| Check | Result |
| --- | --- |
| `python -m pytest -v` | 208 passed in 45.74 seconds; selector workaround noted below |
| `ruff check .` | Passed |
| `ruff format --check .` | Passed |
| `python -m pip check` | Passed |
| `git diff --check` | Passed |
| Wheel and source-distribution build | Passed |
| Artifact contents, metadata, license, version and entry-point inspection | Passed |
| Fresh wheel install with runtime dependencies, outside checkout | Passed |
| Fresh isolated sdist build/install with runtime dependencies, outside checkout | Passed |
| Editable development install with pip build isolation | Passed |
| Installed console help/status, doctor and JSON simulation smoke checks | Passed |
| Hosted Linux/macOS Python 3.11–3.14 matrix | Configured, not executed here |

## Test evidence

All 169 earlier policy, proxy, approval, and audit tests remain. The 39 new tests
cover diagnostic success/failure, unsupported platform/Python reporting, missing
and malformed policy, unsafe permissions/symlinks, corrupt SQLite, failed probes,
invalid commands/server IDs, CLI exit codes, deterministic decisions, JSON output,
and real package/entry-point behavior. A FIFO policy is rejected before reading
it, avoiding a blocked preflight read. Sentinel/spies prove doctor and simulation
never start an upstream or initialize an approval store. Existing database bytes
are unchanged by doctor; disposable probes are removed.

The documented quickstart uses a compatible official SDK host. Tests run its real
CLI with allowed and denied tools, then show/approve a protected call through a
separate operator process and inspect audit metadata. The policy heredoc from
QUICKSTART.md was also used for installed-entry-point smoke checks. State paths
were overridden to private temporary locations because this workspace cannot
write the default home-state location. Normal-host default-path onboarding still
requires the manual release check.

## Packaging evidence

Hatchling builds `agentguard_mcp-0.0.1-py3-none-any.whl` and
`agentguard_mcp-0.0.1.tar.gz`. `scripts/check_artifacts.py` checks both archives,
runtime modules, version consistency, `Requires-Python`, Apache-2.0 license
expression, LICENSE/NOTICE inclusion, Belfeki.tn author/maintainer metadata,
console entry point, source docs/examples/tests, and exclusion of caches/private
state. The source archive can rebuild its wheel without the repository checkout.

Separate new virtual environments under `/tmp/agentguard-m4-final-wheel` and
`/tmp/agentguard-m4-final-sdist` each installed the artifact and its complete runtime
dependency set (37 distributions including AgentGuard). Imports resolved from
those environments' site-packages, not editable source. Commands were run from
`/tmp` with `PYTHONPATH`/`PYTHONHOME` unset, without system site-packages. Both
environments passed `pip check`, doctor, and simulation.

The live package index is unavailable in this sandbox. Builds and clean installs
used existing cached wheels, Hatchling's actual backend, and uv's offline installer;
the sdist build ran in isolation. pip additionally verified an isolated editable
development install using the local wheelhouse. Cache-layout and wheel-tag
recovery were needed locally before the final fresh installs succeeded; no
package implementation or dependency requirement was relaxed. A live-index
installation and other OS/Python combinations were not executed here. CI uses
normal pip installation and has no cache-recovery or selector workaround.

## Sandbox accommodation and remaining release gates

As in earlier milestones, this sandbox blocks asyncio's internal wake-up socket.
The stdio integration suite used a temporary `.pth` bootstrap and selector hook
in the ignored development `.venv`, capping epoll waits at 10 ms. No handlers,
protocol messages, state transitions, assertions, or counters were replaced.
The hook was removed after validation, and no workaround is included in wheel
or source artifacts. The separate clean-install environments did not contain it;
their doctor/simulation smoke checks do not need the stdio accommodation.

GitHub Actions now defines eight full test jobs (Linux/macOS × Python 3.11–3.14)
and a separate artifact/build/install job, with read-only repository permissions
and no publication steps. Hosted results have not been observed from this local
workspace. Passing local checks is not evidence of every configured platform.

Before a public release, the maintainer must verify a monitored private security
reporting route (no fallback contact is currently published), review/pin action
SHAs, run hosted CI and normal-host onboarding, and approve the exact artifacts.
See [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md). Windows proxy support, production
readiness, sandboxing, and stronger approval-account isolation are not claimed.
