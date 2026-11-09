"""Single-use approval coordination and private, diskless FIFO previews. Belfeki.tn."""

import errno
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio

from agentguard.storage import StateError, StateStore, check_private, private_directory

_ID = re.compile(r"[a-f0-9]{64}")
MAX_PREVIEW = 65536


def canonical_arguments(arguments: dict[str, Any] | None) -> str:
    """Snapshot exact finite JSON values with sorted keys, preserving null vs {}.

    Numeric and Unicode values are not normalized. Non-string object keys and
    Python-only values are rejected rather than silently coerced.
    """

    def validate(value: Any) -> None:
        if value is None or type(value) in (str, bool, int):
            return
        if type(value) is float and math.isfinite(value):
            return
        if type(value) is list:
            for item in value:
                validate(item)
            return
        if type(value) is dict and all(type(key) is str for key in value):
            for item in value.values():
                validate(item)
            return
        raise StateError("Arguments must be finite JSON values with string object keys.")

    validate(arguments)
    result = json.dumps(
        arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    if len(result.encode()) > MAX_PREVIEW // 2:
        raise StateError("Arguments exceed the approval review limit.")
    return result


@dataclass(frozen=True)
class ApprovalRequest:
    """Live immutable context; canonical arguments never enter persistent storage."""

    request_id: str
    session_id: str
    server_id: str
    qualified_tool: str
    arguments: str
    context: str
    binding: str
    deadline: float
    rule_id: str | None

    def preview(self) -> dict[str, Any]:
        """Operator review data transferred only through a private kernel FIFO."""
        return {
            "request_id": self.request_id,
            "server_id": self.server_id,
            "qualified_tool": self.qualified_tool,
            "arguments": json.loads(self.arguments),
            "rule_id": self.rule_id,
            "risk": "Policy requires human review. This tool may perform irreversible actions. "
            "Approval authorizes only this invocation; review every argument.",
        }


def _fifo(path: Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if (
        not stat.S_ISFIFO(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        os.close(fd)
        raise StateError("Untrusted approval channel.")
    return fd


class ApprovalCoordinator:
    """Own pending requests for one proxy session; approvals cannot migrate sessions."""

    def __init__(self, store: StateStore, session_id: str, timeout: float = 60) -> None:
        if not _ID.fullmatch(session_id):
            raise StateError("Invalid proxy session identifier.")
        if isinstance(timeout, bool) or not math.isfinite(timeout) or timeout <= 0:
            raise StateError("Approval timeout must be finite and positive.")
        self.store = store
        self.session_id = session_id
        self.timeout = timeout
        self._secret = secrets.token_bytes(32)
        self.directory = private_directory(store.directory / session_id)

    def request(
        self,
        request_id: str,
        server_id: str,
        tool: str,
        arguments: str,
        context: str,
        rule_id: str | None,
    ) -> ApprovalRequest:
        """Bind to server, exact arguments, originating request, and live session."""
        payload = json.dumps([request_id, self.session_id, server_id, tool, arguments, context])
        binding = hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()
        self.store.pending(request_id, binding, self.timeout)
        return ApprovalRequest(
            request_id,
            self.session_id,
            server_id,
            tool,
            arguments,
            context,
            binding,
            time.monotonic() + self.timeout,
            rule_id,
        )

    def binding_valid(self, request: ApprovalRequest) -> bool:
        """Detect any substitution of the execution context before consumption."""
        payload = json.dumps(
            [
                request.request_id,
                request.session_id,
                request.server_id,
                request.qualified_tool,
                request.arguments,
                request.context,
            ]
        )
        expected = hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()
        return request.session_id == self.session_id and hmac.compare_digest(
            expected, request.binding
        )

    async def _views(self, request: ApprovalRequest) -> None:
        # Ownership authenticates the operator UID. Raw arguments are written
        # only to FIFO kernel buffers, never a regular file or SQLite.
        check_private(self.directory, directory=True)
        for path in self.directory.glob(f"{request.request_id}-*.fifo"):
            suffix = path.name[len(request.request_id) + 1 : -5]
            if not _ID.fullmatch(suffix):
                continue
            try:
                fd = _fifo(path, os.O_WRONLY)
            except OSError as exc:
                if exc.errno in (errno.ENXIO, errno.ENOENT):
                    continue
                raise
            try:
                path.unlink()
                payload = json.dumps(request.preview(), ensure_ascii=True).encode() + b"\n"
                with anyio.fail_after(min(2, max(0.001, request.deadline - time.monotonic()))):
                    while payload:
                        try:
                            written = os.write(fd, payload[:4096])
                            payload = payload[written:]
                        except BlockingIOError:
                            await anyio.sleep(0.01)
            finally:
                os.close(fd)

    async def wait(self, request: ApprovalRequest) -> bool:
        """Wait and atomically consume; cancellation invalidates unspent authorization."""
        consumed = False
        try:
            while time.monotonic() < request.deadline:
                await anyio.lowlevel.checkpoint()
                row = self.store.get(request.request_id)
                if row["approval_state"] == "approved":
                    if not self.binding_valid(request) or time.monotonic() >= request.deadline:
                        return False
                    consumed = self.store.consume(
                        request.request_id, self.session_id, request.binding
                    )
                    return consumed
                if row["approval_state"] != "pending":
                    return False
                await self._views(request)
                await anyio.sleep(0.025)
            self.store.expire(request.request_id)
            return False
        finally:
            if not consumed:
                self.store.cancel(request.request_id)


async def live_preview(store: StateStore, request_id: str, timeout: float = 3) -> dict[str, Any]:
    """Read exact live arguments over an owner-only FIFO without using stdin.

    Filesystem ownership authorizes the UID; processes running as that UID are
    inside the trust boundary. No raw arguments are written to disk.
    """
    if not _ID.fullmatch(request_id):
        raise StateError("Invalid request identifier.")
    row = store.get(request_id)
    if row["approval_state"] != "pending" or not _ID.fullmatch(row["session_id"]):
        raise StateError("Approval is not pending.")
    directory = store.directory / row["session_id"]
    check_private(directory, directory=True)
    path = directory / f"{request_id}-{secrets.token_hex(32)}.fifo"
    os.mkfifo(path, 0o600)
    fd = _fifo(path, os.O_RDONLY)
    try:
        data = b""
        with anyio.fail_after(timeout):
            while not data.endswith(b"\n"):
                try:
                    data += os.read(fd, 4096)
                except BlockingIOError:
                    pass
                if len(data) > MAX_PREVIEW:
                    raise StateError("Oversized approval preview.")
                await anyio.sleep(0.01)
        result = json.loads(data)
        if result["request_id"] != request_id:
            raise StateError("Approval preview identity mismatch.")
        return result
    finally:
        os.close(fd)
        path.unlink(missing_ok=True)
