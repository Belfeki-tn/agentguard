# Contributing to AgentGuard

Developer and maintainer: **Belfeki.tn**. Contributions retain Apache-2.0 licensing
and the project's developer/maintainer attribution.

## Set up and run checks

Use Linux/macOS with Python 3.11+; CI targets 3.11–3.14. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -v
ruff check .
ruff format --check .
python -m pip check
git diff --check
```

Tests use synthetic data and temporary state directories. Integration tests
launch harmless local mock MCP servers and verify execution counters. They do
not require a cloud account or external MCP server. Owner-only directories and
POSIX FIFOs are part of the tested boundary; do not bypass permission checks to
make a test pass. On macOS, use canonical filesystem paths when symlinks such as
`/var` are involved. Windows full-gateway testing is not supported.

The restricted coding sandbox used during development blocks asyncio wake-up
socket writes; prior validation reports describe a temporary test-environment
selector workaround. That workaround is not part of the product and must not
ship. Normal-host CI must pass without it. Report skipped/blocked checks honestly.

## Keep changes focused

Read [policy architecture](docs/POLICY_ENGINE.md), [proxy architecture](docs/MCP_PROXY.md),
[approvals](docs/APPROVAL_WORKFLOW.md), and [audit logging](docs/AUDIT_LOGGING.md)
before changing security paths. Keep the policy engine independent of transport,
preserve its public API, and use exact identities and deterministic precedence.
Never replace denied/approval/error cases with an allow fallback or add automatic
retries for non-idempotent tool calls.

Discuss large changes in an issue first, except vulnerabilities, which must use
[SECURITY.md](SECURITY.md). Use small testable changes, type public interfaces,
and explain behavior, validation, limitations, and security implications in the
pull request. Add meaningful tests for boundary changes. Preserve existing
policy, proxy, approval, and audit coverage; update the quickstart when CLI or
examples change. Respect [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Package checks

```bash
python -m hatchling build
python scripts/check_artifacts.py dist
```

Use an empty artifact directory. Verify clean wheel and sdist installs outside
the checkout as described in [RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md).
Builds must include Apache-2.0 LICENSE, NOTICE, maintainer metadata, and the CLI
entry point, while excluding credentials, local databases, and caches. CI runs
artifact inspection and clean installation but never publishes or creates a
release. Publishing, tagging, committing, or pushing requires an explicit task
or maintainer decision; completing checks does not authorize those actions.
