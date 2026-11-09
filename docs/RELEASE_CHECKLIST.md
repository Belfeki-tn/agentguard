# Manual release checklist

Developer and maintainer: **Belfeki.tn**. This checklist does not authorize
publication. CI never uploads packages to PyPI or creates GitHub releases.

## Before declaring a release candidate

- Review [SECURITY.md](../SECURITY.md) and the same-UID approval trust boundary.
- Establish and test a private vulnerability-reporting route monitored by the
  maintainer. The current fallback contact is not configured; this blocks a public
  release until a verified route is documented. Do not invent a reporting email.
- Confirm package/repository naming, Apache-2.0 licensing, and any third-party
  obligations. Preserve `LICENSE`, `NOTICE`, and Belfeki.tn authorship/maintenance.
- Review dependency bounds, advisories, supported SDK APIs, and build tooling.
- Pin GitHub Actions to reviewed immutable commit SHAs before a public release.
- Run the full hosted CI matrix: Python 3.11–3.14 on Linux and macOS. A configured
  matrix is not evidence of a successful run. No Windows proxy support is claimed.
- Exercise the [quickstart](QUICKSTART.md) manually on a normal trusted host.
- Review deferred features and known limitations; do not describe this as production-ready.

## Build and inspect locally

Use a clean checkout and a disposable virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -v
ruff check .
ruff format --check .
python -m pip check
git diff --check
python -m hatchling build
python scripts/check_artifacts.py dist
```

Build into an empty `dist/`; the artifact checker intentionally requires exactly
one wheel and one source archive. Archive names must match package metadata.
Verify the package version agrees with `agentguard.__version__`, update the
changelog only for an actual release, and inspect all distribution files for
credentials, local SQLite state, caches, `.env`, and unintended repository files.
The artifact checker asserts runtime modules, license/notice, CLI entry point,
maintainer metadata, and source examples/docs/tests.

The build uses [Hatch file selection](https://hatch.pypa.io/latest/config/build/).
The wheel contains the runtime package; the sdist additionally contains docs,
tests, examples, CI, and verification scripts. Build caches and local state must
not ship. The build backend is constrained separately from runtime dependencies.

## Install both artifacts independently

Create each environment outside the checkout; install dependencies normally or
from a reviewed offline wheelhouse. Do not use `--system-site-packages`, editable
installs, or `PYTHONPATH` to claim a clean install.

```bash
python3 -m venv /tmp/agentguard-wheel-check
/tmp/agentguard-wheel-check/bin/python -m pip install dist/*.whl
python3 -m venv /tmp/agentguard-sdist-check
/tmp/agentguard-sdist-check/bin/python -m pip install dist/*.tar.gz
(
  cd /tmp
  /tmp/agentguard-wheel-check/bin/agentguard --help
  /tmp/agentguard-wheel-check/bin/agentguard status
  /tmp/agentguard-wheel-check/bin/python -m pip check
  /tmp/agentguard-sdist-check/bin/agentguard policy test --help
  /tmp/agentguard-sdist-check/bin/python -m pip check
)
```

Use unused private environment paths. Run doctor and JSON simulation against a
known policy with the installed entry points. Test the rebuilt sdist wheel as
well as the checkout wheel. Keep logs of checks, dependency versions, platform,
and environment restrictions in the milestone/release validation report.

## Publication is a separate maintainer action

- Require explicit maintainer authorization before tagging, publishing to PyPI,
  pushing changes, or creating a GitHub release.
- Review and sign off the exact built artifacts, version, release notes, and
  successful CI results. Record artifact hashes for the authorized release.
- A release must not include the temporary sandbox selector workaround described
  in validation reports. Run integration tests without it on a normal host.
- Do not publish while any reporting-channel, licensing, naming, security,
  platform, or installation checks remain unresolved.
