"""Guarded, single-upstream MCP stdio adapter. Maintained by Belfeki.tn.

Only tools/list and guarded tools/call are exposed. Policy evaluation remains
independent of this transport layer. There is no generic forwarding path.
"""

import json
import logging
import math
import os
import re
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import mcp_types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from pydantic import TypeAdapter

from agentguard import __version__
from agentguard.approvals import ApprovalCoordinator, canonical_arguments
from agentguard.policy import Policy, evaluate
from agentguard.policy.models import ToolName
from agentguard.storage import StateStore, new_request_id

_QUALIFIED_TOOL = TypeAdapter(ToolName)


class ProxyConfigurationError(ValueError):
    """Invalid proxy settings; messages deliberately omit command arguments."""


@dataclass(frozen=True)
class ProxySettings:
    """Trusted operator settings, validated before a subprocess is started.

    server_id supplies the policy namespace; upstream handshake names and client
    arguments never override it. command is an argv tuple, never shell source.
    """

    command: tuple[str, ...]
    server_id: str = "upstream"
    timeout: float = 30.0
    state_dir: Path | None = None
    approval_timeout: float = 60.0

    def __post_init__(self) -> None:
        if not isinstance(self.server_id, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]+", self.server_id
        ):
            raise ProxyConfigurationError("Invalid server ID.")
        if (
            not isinstance(self.command, tuple)
            or not self.command
            or any(
                not isinstance(arg, str) or any(ord(char) < 32 for char in arg)
                for arg in self.command
            )
            or not self.command[0]
        ):
            raise ProxyConfigurationError("Invalid upstream command.")
        if shutil.which(self.command[0]) is None:
            raise ProxyConfigurationError("Upstream executable was not found or is not executable.")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise ProxyConfigurationError("Timeout must be finite and positive.")
        if not math.isfinite(self.approval_timeout) or self.approval_timeout <= 0:
            raise ProxyConfigurationError("Approval timeout must be finite and positive.")


def parse_command(source: str) -> tuple[str, ...]:
    """Split a quoted command into argv without shell expansion or execution.

    Intended for POSIX-style quoting, including on Windows. Shell operators are
    rejected to catch accidental use of shell syntax in the proposed CLI.
    """
    try:
        command = tuple(shlex.split(source))
    except ValueError:
        raise ProxyConfigurationError("Invalid command quoting.") from None
    if any(arg in {"|", "||", "&", "&&", ";", ">", ">>", "<"} for arg in command):
        raise ProxyConfigurationError("Shell operators are not supported.")
    return command


class _GatewayError(types.CallToolResult):
    """Internal marker so untrusted upstream content cannot impersonate audit outcomes."""


def _error(code: str, message: str) -> types.CallToolResult:
    return _GatewayError(
        is_error=True,
        content=[types.TextContent(text=message)],
        structured_content={"agentguard": {"code": code}},
    )


class GuardedTools:
    """A fixed discovered catalogue and the only upstream invocation path.

    At most one upstream invocation is issued for each allowed handler call.
    Transport errors or cancellation taint this session; later calls are refused.
    There are no automatic retries, reconnects, or result caches.
    """

    def __init__(
        self,
        policy: Policy,
        settings: ProxySettings,
        session: ClientSession,
        tools: list[types.Tool],
        store: StateStore | None = None,
        approvals: ApprovalCoordinator | None = None,
    ) -> None:
        self._policy = policy
        self._settings = settings
        self._session = session
        self._tools = {tool.name: tool.model_copy(deep=True) for tool in tools}
        self._available = True
        self._store = store
        self._approvals = approvals
        self._session_id = approvals.session_id if approvals else new_request_id()

    async def list_tools(
        self,
        ctx: ServerRequestContext[Any],
        params: types.PaginatedRequestParams | None,
    ) -> types.ListToolsResult:
        """Return the startup catalogue; denied tools may be visible but never executable."""
        return types.ListToolsResult(tools=list(self._tools.values()))

    async def call_tool(
        self,
        ctx: ServerRequestContext[Any],
        params: types.CallToolRequestParams,
    ) -> types.CallToolResult:
        """Audit every handled call and fail closed on storage or approval failures."""
        request_id = new_request_id()
        try:
            try:
                tool = _QUALIFIED_TOOL.validate_python(f"{self._settings.server_id}.{params.name}")
            except ValueError:
                tool = "<invalid>"
            if self._store:
                self._store.start(request_id, self._session_id, self._settings.server_id, tool)
            result = await self._call_tool(ctx, params, request_id)
            if self._store:
                outcome = "tool_error" if result.is_error else "success"
                if isinstance(result, _GatewayError):
                    outcome = result.structured_content["agentguard"]["code"]
                self._store.finish(request_id, outcome)
            return result
        except anyio.get_cancelled_exc_class():
            self._available = False
            if self._store:
                try:
                    self._store.cancel(request_id)
                    self._store.finish(request_id, "cancelled_outcome_unknown")
                except Exception:  # noqa: BLE001, S110 - preserve cancellation, never log secrets.
                    pass
            raise
        except Exception:  # noqa: BLE001 - storage/coordination boundary must fail closed.
            self._available = False
            if self._store:
                try:
                    self._store.cancel(request_id)
                except Exception:  # noqa: BLE001, S110 - broken store; return sanitized error below.
                    pass
            return _error(
                "audit_error",
                "Approval or audit storage failed. Execution may have occurred; "
                "no retry was attempted.",
            )

    async def _call_tool(
        self,
        ctx: ServerRequestContext[Any],
        params: types.CallToolRequestParams,
        request_id: str,
    ) -> types.CallToolResult:
        """Keep evaluation, approval consumption, and submission on one guarded path."""
        tool_name = params.name
        try:
            qualified = _QUALIFIED_TOOL.validate_python(f"{self._settings.server_id}.{tool_name}")
            decision = evaluate(self._policy, qualified)
            if self._store:
                self._store.policy(
                    request_id,
                    decision.action,
                    decision.matched_rule.id if decision.matched_rule else None,
                )
            if decision.action == "deny":
                return _error("denied", "Tool call denied by policy.")
            if decision.action not in ("allow", "approve"):
                return _error("enforcement_error", "Policy enforcement failed; call refused.")
            if tool_name not in self._tools:
                return _error("unknown_tool", "Unknown tool; call refused.")
            # Do not forward task execution, resumptions, client identity, or metadata.
            if (
                params.task is not None
                or params.request_state is not None
                or (params.input_responses is not None)
            ):
                return _error("unsupported_request", "Tasks and resumptions are not supported.")
        except Exception:  # noqa: BLE001 - any enforcement failure must refuse execution.
            return _error("enforcement_error", "Policy enforcement failed; call refused.")

        arguments = params.arguments
        if not self._available:
            return _error("upstream_unavailable", "Upstream session unavailable; call refused.")
        if decision.action == "approve":
            if self._approvals is None:
                return _error(
                    "approval_required", "Approval required; approval service unavailable."
                )
            canonical = canonical_arguments(arguments)
            arguments = json.loads(canonical)
            context = json.dumps([self._session_id, getattr(ctx, "request_id", None), request_id])
            request = self._approvals.request(
                request_id,
                self._settings.server_id,
                qualified,
                canonical,
                context,
                decision.matched_rule.id if decision.matched_rule else None,
            )
            if not await self._approvals.wait(request):
                return _error("approval_required", "Approval was rejected, expired, or cancelled.")

        try:
            # A pending cancellation must be observed before submitting any side effect.
            await anyio.lowlevel.checkpoint()
            # Recheck after yielding: another concurrent call may have tainted the session.
            if not self._available:
                return _error("upstream_unavailable", "Upstream session unavailable; call refused.")
            # Approval consumption already committed intent in its atomic transaction.
            if self._store and decision.action == "allow":
                self._store.finish(request_id, "execution_started")
            with anyio.fail_after(self._settings.timeout):
                result = await self._session.call_tool(tool_name, arguments)
            if not isinstance(result, types.CallToolResult):
                raise TypeError("Unsupported upstream result")
            return result
        except anyio.get_cancelled_exc_class():
            self._available = False
            raise
        except Exception:  # noqa: BLE001 - sanitize upstream failures, never retry.
            self._available = False
            return _error(
                "upstream_error",
                "Upstream call failed; execution outcome may be unknown. No retry was attempted.",
            )


async def discover_tools(session: ClientSession, server_id: str) -> list[types.Tool]:
    """Read all catalogue pages, rejecting invalid identities and ambiguous duplicates."""
    tools: dict[str, types.Tool] = {}
    cursors: set[str] = set()
    params = None
    for _ in range(100):
        page = await session.list_tools(params=params)
        for tool in page.tools:
            _QUALIFIED_TOOL.validate_python(f"{server_id}.{tool.name}")
            if tool.name in tools or len(tools) >= 10000:
                raise ProxyConfigurationError("Invalid or oversized upstream catalogue.")
            # No task capability is advertised by this proxy.
            tools[tool.name] = tool.model_copy(update={"execution": None}, deep=True)
        if page.next_cursor is None:
            return list(tools.values())
        if page.next_cursor in cursors:
            raise ProxyConfigurationError("Upstream catalogue cursor repeated.")
        cursors.add(page.next_cursor)
        params = types.PaginatedRequestParams(cursor=page.next_cursor)
    raise ProxyConfigurationError("Too many upstream catalogue pages.")


def configure_safe_logging() -> None:
    """Silence SDK diagnostics that could include protocol payloads or exception details."""
    for name in ("mcp", "client"):
        logger = logging.getLogger(name)
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False
        logger.setLevel(logging.CRITICAL + 1)


async def run_proxy(policy: Policy, settings: ProxySettings) -> None:
    """Start one upstream and serve guarded tools on stdin/stdout until disconnect.

    Validate policy again at this boundary before starting any process. Upstream
    stderr is discarded because third-party diagnostics may contain credentials.
    SDK context managers own cancellation and bounded subprocess cleanup.
    """
    policy = Policy.model_validate(policy.model_dump(mode="python"))
    configure_safe_logging()
    store = StateStore(settings.state_dir or Path.home() / ".local/state/agentguard")
    approvals = ApprovalCoordinator(store, new_request_id(), settings.approval_timeout)
    parameters = StdioServerParameters(command=settings.command[0], args=list(settings.command[1:]))
    # The SDK requires a synchronous file descriptor for subprocess stderr.
    with open(os.devnull, "w", encoding="utf-8") as errlog:  # noqa: ASYNC230
        async with (
            stdio_client(parameters, errlog=errlog) as (read, write),
            ClientSession(read, write, read_timeout_seconds=settings.timeout) as session,
        ):
            with anyio.fail_after(settings.timeout):
                await session.initialize()
                tools = await discover_tools(session, settings.server_id)
            guarded = GuardedTools(policy, settings, session, tools, store, approvals)
            server = Server(
                "AgentGuard",
                version=__version__,
                on_list_tools=guarded.list_tools,
                on_call_tool=guarded.call_tool,
            )
            async with stdio_server() as (downstream_read, downstream_write):
                try:
                    await server.run(
                        downstream_read,
                        downstream_write,
                        server.create_initialization_options(),
                    )
                finally:
                    store.cancel_session(approvals.session_id)
