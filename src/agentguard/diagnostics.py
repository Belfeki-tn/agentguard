"""Local preflight diagnostics; never start upstream processes. Maintained by Belfeki.tn."""

import os
import shutil
import sqlite3
import stat
import sys
import tempfile
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from agentguard.policy import load_policy
from agentguard.proxy import ProxySettings, parse_command
from agentguard.storage import StateError, check_private


@dataclass(frozen=True)
class Diagnostic:
    """A sanitized, actionable result without raw paths, policy data, or command arguments."""

    check: str
    ok: bool
    message: str


def _inspect_state(directory: Path) -> Path:
    """Check existing permissions without creating state; return the nearest writable ancestor."""
    directory = directory.expanduser().absolute()
    nearest = None
    for path in reversed((directory, *directory.parents)):
        if path.is_symlink():
            raise StateError("Symlinked state path.")
        if not path.exists():
            continue
        info = path.lstat()
        trusted_sticky = info.st_mode & stat.S_ISVTX and info.st_uid in {
            os.geteuid(),
            Path("/").stat().st_uid,
        }
        if not stat.S_ISDIR(info.st_mode) or (info.st_mode & 0o022 and not trusted_sticky):
            raise StateError("Unsafe state ancestor.")
        nearest = path
    if directory.exists():
        check_private(directory, directory=True)
    if nearest is None or not os.access(nearest, os.W_OK | os.X_OK):
        raise StateError("State location is not writable.")
    database = directory / "audit.sqlite3"
    if database.exists() or database.is_symlink():
        check_private(database)
        if not os.access(database, os.R_OK | os.W_OK):
            raise StateError("Audit database is not readable and writable.")
        # Read-only inspection neither initializes schema nor expires approvals.
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=0.1)) as db:
            if db.execute("PRAGMA quick_check(1)").fetchone() != ("ok",):
                raise StateError("Audit database is corrupt.")
    return nearest


def _probe_prerequisites(parent: Path) -> None:
    """Probe FIFO creation and durable SQLite transactions in a disposable private directory."""
    with tempfile.TemporaryDirectory(prefix=".agentguard-doctor-", dir=parent) as temporary:
        root = Path(temporary)
        database = root / "probe.sqlite3"
        fd = os.open(database, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(database)) as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("PRAGMA synchronous").fetchone()[0] < 2:
                raise StateError("SQLite FULL synchronous durability is required.")
            db.execute("CREATE TABLE probe (value INTEGER)")
            db.execute("INSERT INTO probe VALUES (?)", (1,))
            db.commit()
        fifo = root / "probe.fifo"
        os.mkfifo(fifo, 0o600)
        fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        try:
            if not stat.S_ISFIFO(os.fstat(fd).st_mode):
                raise StateError("FIFO support is unavailable.")
        finally:
            os.close(fd)


def diagnose(
    config: Path, command: str, state_dir: Path, server_id: str = "upstream"
) -> list[Diagnostic]:
    """Check local prerequisites without starting an upstream or modifying persistent state.

    Temporary FIFO/SQLite probes are removed afterward. Success is a preflight
    result, not a claim of upstream MCP compatibility or a security assurance.
    """
    results = [
        Diagnostic(
            "python",
            sys.version_info >= (3, 11),
            "Python 3.11+ is required; use a supported Python environment.",
        )
    ]
    platform_ok = (
        os.name == "posix"
        and sys.platform in {"linux", "darwin"}
        and all(hasattr(os, name) for name in ("geteuid", "mkfifo", "O_NOFOLLOW", "O_NONBLOCK"))
    )
    results.append(
        Diagnostic(
            "platform",
            platform_ok,
            "Proxy/approvals require Linux or macOS with POSIX ownership and FIFOs.",
        )
    )
    try:
        if not stat.S_ISREG(config.lstat().st_mode):
            raise StateError("Policy must be a regular file.")
        load_policy(config)
        results.append(Diagnostic("policy", True, "Policy YAML and schema are valid."))
    except Exception:  # noqa: BLE001 - never display policy input or exception payloads.
        results.append(
            Diagnostic(
                "policy",
                False,
                "Cannot validate policy. Check file access and docs/POLICY_ENGINE.md.",
            )
        )
    try:
        info = config.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise StateError("Unsafe policy file.")
        results.append(
            Diagnostic(
                "policy_permissions",
                True,
                "Policy is a regular file without group/world write access.",
            )
        )
    except OSError:
        results.append(
            Diagnostic(
                "policy_permissions",
                False,
                "Policy file unavailable; check its path and read permissions.",
            )
        )
    except StateError:
        results.append(
            Diagnostic(
                "policy_permissions",
                False,
                "Use a regular policy file without symlinks or group/world write access.",
            )
        )
    try:
        settings = ProxySettings(parse_command(command), server_id)
        executable = shutil.which(settings.command[0])
        if executable is None:
            raise StateError("Upstream executable is unavailable.")
        resolved = Path(executable).resolve(strict=True)
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
            raise StateError("Upstream must be an executable regular file.")
        message = "Upstream executable is available; it was not launched."
        if info.st_mode & 0o022:
            # Toolcache/framework Python installs can be writable. Reusing the
            # interpreter already running this process introduces no new binary
            # trust choice; compare file identity, never names or CI variables.
            if not resolved.samefile(sys.executable):
                raise StateError("Unsafe upstream executable.")
            message = (
                "Warning: the current Python interpreter is group/world writable. "
                "Reusing the already-running interpreter; nothing was launched. "
                "Use a private Python installation on shared hosts."
            )
        results.append(Diagnostic("upstream", True, message))
    except Exception:  # noqa: BLE001 - command arguments can contain credentials.
        results.append(
            Diagnostic(
                "upstream",
                False,
                "Check executable availability, permissions, command quoting, and server ID.",
            )
        )
    if not platform_ok:
        results.append(
            Diagnostic("state", False, "Approval/audit checks require a supported POSIX platform.")
        )
        return results
    try:
        parent = _inspect_state(state_dir)
        results.append(
            Diagnostic(
                "state_permissions",
                True,
                "State location and existing audit permissions are acceptable.",
            )
        )
    except Exception:  # noqa: BLE001 - sanitize paths and SQLite diagnostics.
        results.append(
            Diagnostic(
                "state_permissions",
                False,
                "Use a private owned state directory (0700), database (0600), and safe "
                "non-symlink ancestors. Check free space, access, and database health.",
            )
        )
        return results
    try:
        _probe_prerequisites(parent)
        results.append(
            Diagnostic(
                "approval_audit",
                True,
                "Private FIFO creation and durable SQLite writes succeeded; probes removed.",
            )
        )
    except Exception:  # noqa: BLE001 - do not leak filesystem or SQLite exception details.
        results.append(
            Diagnostic(
                "approval_audit",
                False,
                "FIFO/SQLite probe failed. Check write access, free space, and SQLite "
                "FULL durability support on this filesystem.",
            )
        )
    return results
