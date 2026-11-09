# Doctor interpreter portability fix

Developer and maintainer: **Belfeki.tn**.

## Evidence and cause

[Run 42592336637](https://github.com/Belfeki-tn/agentguard/actions/runs/42592336637)
has eight failed test jobs and a passing packaging job. Ubuntu Python 3.12 and
macOS Python 3.12 logs were inspected directly: both report only the three doctor
failures, with 205 other tests passing. Packaging smoke checks did not call doctor.

The failure is the blanket resolved-executable write-mode predicate, not an MCP
invocation. The local system interpreter is mode 0755 and passes. With disposable
copies representing the current interpreter, modes 0775 and 0777 reproduce the
failure. Tracing the original source's exception event reports exactly
`StateError("Unsafe upstream executable.")`; command parsing, ProxySettings,
executable lookup, and target resolution succeed first. No credentials, command
arguments, or arbitrary exception payloads were emitted by this inspection.

The installation layouts explain the platform dependence:

- GitHub's [Ubuntu image provisioning](https://github.com/actions/runner-images/blob/main/images/ubuntu/scripts/build/configure-system.sh)
  makes `/opt` recursively writable, including preinstalled toolcache interpreters.
- The [CPython macOS package builder](https://github.com/python/cpython/blob/3.12/Mac/BuildScript/build-installer.py)
  adds group-write permission to framework files. Its
  [framework installation aliases](https://github.com/actions/python-versions/blob/main/installers/macos-pkg-setup-template.sh)
  resolve to those files.

The original predicate rejects both installation classes. The hosted logs do not
include per-interpreter `stat` values, so the exact mode/owner for each failed
job was not directly measured. The sources, matching failure branch, and local
mode reproductions support the diagnosis; the hosted matrix still needs rerunning.

## Minimal change and security boundary

Only doctor executable preflight logic changes. Strict command parsing,
ProxySettings validation, lookup, and sanitized errors remain. Resolved targets
must be executable regular files. Broken links, loops, missing files, directories,
non-executable files, and executable-mode FIFOs are refused.

Group/world-writable executables still fail unless `samefile(sys.executable)`
identifies the interpreter already running AgentGuard. That narrow existing-runtime
trust choice passes with an explicit permission warning. Symlink aliases work in
either toolcache/framework layouts; filenames, directory prefixes, and CI
environment variables grant no exception. Unrelated writable binaries remain
blocked even when named Python.

Doctor starts no upstream process. Proxy enforcement, approvals, audit storage,
policy APIs, and the workflow configuration are unchanged. This does not certify
provenance, ACLs, directory chains, or protection from replacement after the check.
Shared writable interpreters require a private installation on untrusted/shared
hosts. Same-UID trust limitations from earlier milestones still apply.

## Regression tests and local gates

Before the code change, the new reproductions produced five failures: four
current-interpreter 0775/0777 direct/symlink cases and an executable-mode FIFO
incorrectly accepted as an executable. After the change, all pass. The 23 added
tests cover current and unrelated executable modes, symlinks, quoted paths with
spaces, broken/looping links, directories, FIFOs, malformed/missing commands,
shell operators, control characters, and sanitized identity-check exceptions.
Existing invalid-server-ID and no-upstream-execution tests remain enabled.

Validated on Linux / Python 3.12.3 with the project's `.venv`:

| Gate | Result |
| --- | --- |
| `python -m pytest -v` | 231 passed in 39.69 seconds |
| `ruff check .` | Passed |
| `ruff format --check .` | Passed |
| `python -m pip check` | Passed |
| `git diff --check` | Passed |

No tests were skipped. The full stdio suite required the same temporary local
selector-polling accommodation described in the Milestone 2–4 reports because
this sandbox blocks asyncio wake-up socket writes. The ignored virtual-environment
hook was removed afterward. It does not replace doctor checks or assertions, is
not a CI bypass, and is absent from product code and workflow files. Doctor-only
regressions also passed without that accommodation.

macOS and Python 3.11/3.13/3.14 were not executed locally; their portable filesystem
cases were exercised on Linux, but the hosted matrix has not been rerun with this
working-tree change. No automatic commit, push, release, or workflow dispatch was
performed. Belfeki.tn attribution is preserved.
