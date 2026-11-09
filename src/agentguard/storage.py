"""Private SQLite approval coordination and metadata-only audit. Belfeki.tn."""

import os
import secrets
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal

ApprovalState = Literal["pending", "approved", "rejected", "expired", "cancelled", "consumed"]


class StateError(ValueError):
    """Unsafe storage, missing request, or invalid approval transition."""


def check_private(path: Path, *, directory: bool = False) -> None:
    """Require a non-symlink, owner-only POSIX object owned by the effective UID."""
    if os.name != "posix":
        raise StateError("Approval storage requires POSIX ownership and permissions.")
    info = path.lstat()
    valid_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_type or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise StateError("Unsafe state ownership, permissions, or object type.")
    if not directory and info.st_nlink != 1:
        raise StateError("State files must not have hard links.")


def private_directory(path: Path) -> Path:
    """Create a private directory, rejecting symlinked path components."""
    path = path.expanduser().absolute()
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise StateError("Symlinked state paths are not supported.")
        if not parent.exists():
            # Create every missing ancestor privately, independent of the umask.
            parent.mkdir(mode=0o700)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise StateError("State paths must be directories.")
        trusted_sticky = info.st_mode & stat.S_ISVTX and info.st_uid in {
            os.geteuid(),
            Path("/").stat().st_uid,
        }
        if info.st_mode & 0o022 and not trusted_sticky:
            raise StateError("State ancestors must not be group/world writable.")
    check_private(path, directory=True)
    return path


def new_request_id() -> str:
    """Return an unpredictable 256-bit request identifier."""
    return secrets.token_hex(32)


class StateStore:
    """Short SQLite transactions; no arguments, credentials, results, or raw exceptions.

    Approval transitions and their audit events commit together. Connections are
    operation-local, allowing separate operator processes and concurrent callers.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = private_directory(directory)
        self.path = self.directory / "audit.sqlite3"
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        check_private(self.path)
        with self._transaction() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                    session_id TEXT NOT NULL, server_id TEXT NOT NULL,
                    qualified_tool TEXT NOT NULL, decision TEXT NOT NULL,
                    rule_id TEXT, approval_state TEXT, outcome TEXT NOT NULL,
                    binding TEXT, expires_at REAL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id INTEGER PRIMARY KEY, request_id TEXT NOT NULL,
                    timestamp REAL NOT NULL, server_id TEXT NOT NULL,
                    qualified_tool TEXT NOT NULL, decision TEXT NOT NULL,
                    rule_id TEXT, approval_state TEXT, outcome TEXT NOT NULL
                );
            """)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        check_private(self.directory, directory=True)
        check_private(self.path)
        db = sqlite3.connect(self.path, timeout=0.1)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            # Acquire the writer reservation before reading connection settings:
            # changing PRAGMA synchronous first can race a concurrent commit.
            if db.execute("PRAGMA synchronous").fetchone()[0] < 2:
                raise StateError("SQLite FULL synchronous durability is required.")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _event(db: sqlite3.Connection, request_id: str) -> None:
        db.execute(
            """INSERT INTO audit_events
            (request_id,timestamp,server_id,qualified_tool,decision,rule_id,approval_state,outcome)
            SELECT request_id,?,server_id,qualified_tool,decision,rule_id,approval_state,outcome
            FROM requests WHERE request_id=?""",
            (time.time(), request_id),
        )

    def start(self, request_id: str, session_id: str, server_id: str, tool: str) -> None:
        """Persist receipt before policy evaluation or execution."""
        with self._transaction() as db:
            db.execute(
                "INSERT INTO requests VALUES (?,?,?,?,?,'error',NULL,NULL,'received',NULL,NULL)",
                (request_id, time.time(), session_id, server_id, tool),
            )
            self._event(db, request_id)

    def policy(self, request_id: str, decision: str, rule_id: str | None) -> None:
        """Record the deterministic policy result without its arguments or explanation."""
        with self._transaction() as db:
            db.execute(
                "UPDATE requests SET decision=?,rule_id=? WHERE request_id=?",
                (decision, rule_id, request_id),
            )
            self._event(db, request_id)

    def pending(self, request_id: str, binding: str, lifetime: float) -> None:
        """Create a single approval attached to an existing request."""
        with self._transaction() as db:
            changed = db.execute(
                """UPDATE requests SET approval_state='pending',binding=?,expires_at=?,
                outcome='awaiting_approval' WHERE request_id=? AND decision='approve'
                AND approval_state IS NULL AND outcome='received'""",
                (binding, time.time() + lifetime, request_id),
            ).rowcount
            if changed != 1:
                raise StateError("Cannot create approval.")
            self._event(db, request_id)

    def _expire(self, db: sqlite3.Connection) -> None:
        rows = db.execute(
            """SELECT request_id FROM requests WHERE approval_state IN ('pending','approved')
            AND expires_at<=?""",
            (time.time(),),
        ).fetchall()
        for row in rows:
            db.execute(
                "UPDATE requests SET approval_state='expired',outcome='blocked' WHERE request_id=?",
                (row[0],),
            )
            self._event(db, row[0])

    def get(self, request_id: str) -> dict[str, Any]:
        """Read current state, expiring overdue approvals first."""
        with self._transaction() as db:
            self._expire(db)
            row = db.execute("SELECT * FROM requests WHERE request_id=?", (request_id,)).fetchone()
            if row is None:
                raise StateError("Unknown request.")
            return dict(row)

    def list_pending(self) -> list[dict[str, Any]]:
        """List pending approvals; never expose binding digests or raw arguments."""
        with self._transaction() as db:
            self._expire(db)
            return [
                dict(row)
                for row in db.execute(
                    """SELECT request_id,timestamp,server_id,qualified_tool,rule_id,approval_state,
                expires_at,session_id FROM requests WHERE approval_state='pending'
                ORDER BY timestamp""",
                )
            ]

    def decide(self, request_id: str, approve: bool) -> None:
        """Atomically approve/reject a pending, unexpired request exactly once."""
        if type(approve) is not bool:
            raise StateError("Decision must be an explicit boolean.")
        with self._transaction() as db:
            self._expire(db)
            state = "approved" if approve else "rejected"
            changed = db.execute(
                "UPDATE requests SET approval_state=? WHERE request_id=? "
                "AND approval_state='pending' AND expires_at>?",
                (state, request_id, time.time()),
            ).rowcount
            if changed != 1:
                # Expiration updates must commit even when this decision is refused.
                db.commit()
                raise StateError("Approval is not pending or has expired.")
            self._event(db, request_id)

    def consume(self, request_id: str, session_id: str, binding: str) -> bool:
        """Atomically spend an approved exact request and persist execution intent."""
        with self._transaction() as db:
            self._expire(db)
            changed = db.execute(
                """UPDATE requests SET approval_state='consumed',outcome='execution_started'
                WHERE request_id=? AND session_id=? AND binding=?
                AND approval_state='approved' AND expires_at>?""",
                (request_id, session_id, binding, time.time()),
            ).rowcount
            if changed:
                self._event(db, request_id)
            return changed == 1

    def cancel(self, request_id: str) -> None:
        """Invalidate pending or approved authorization; consumed requests stay consumed."""
        with self._transaction() as db:
            changed = db.execute(
                "UPDATE requests SET approval_state='cancelled',outcome='blocked' "
                "WHERE request_id=? AND approval_state IN ('pending','approved')",
                (request_id,),
            ).rowcount
            if changed:
                self._event(db, request_id)

    def finish(self, request_id: str, outcome: str) -> None:
        """Append a sanitized outcome, preserving the approval lifecycle state."""
        with self._transaction() as db:
            db.execute("UPDATE requests SET outcome=? WHERE request_id=?", (outcome, request_id))
            self._event(db, request_id)

    def expire(self, request_id: str) -> None:
        """Expire a live request when its monotonic deadline has elapsed."""
        with self._transaction() as db:
            changed = db.execute(
                "UPDATE requests SET approval_state='expired',outcome='blocked' WHERE request_id=? "
                "AND approval_state IN ('pending','approved')",
                (request_id,),
            ).rowcount
            if changed:
                self._event(db, request_id)

    def cancel_session(self, session_id: str) -> None:
        """Invalidate all unspent approvals belonging to a disconnected proxy session."""
        with self._transaction() as db:
            rows = db.execute(
                "SELECT request_id FROM requests WHERE session_id=? AND "
                "approval_state IN ('pending','approved')",
                (session_id,),
            ).fetchall()
            for row in rows:
                db.execute(
                    "UPDATE requests SET approval_state='cancelled',outcome='blocked' "
                    "WHERE request_id=?",
                    (row[0],),
                )
                self._event(db, row[0])
