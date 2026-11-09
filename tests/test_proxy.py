"""Real stdio MCP client → proxy → side-effecting upstream integration tests."""

import shlex
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import anyio
import mcp_types as types
import pytest
import yaml
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.policy import Policy
from agentguard.proxy import (
    GuardedTools,
    ProxyConfigurationError,
    ProxySettings,
    discover_tools,
    parse_command,
)

MOCK = Path(__file__).with_name("mock_mcp_server.py")


@pytest.fixture
def anyio_backend():
    return "asyncio"


def write_policy(path, server_id="trusted"):
    rules = [
        {"id": name.replace(".", "-"), "tools": [f"{server_id}.{name}"], "action": action}
        for name, action in [
            ("allowed", "allow"),
            ("denied", "deny"),
            ("approval", "approve"),
            ("dots.read", "allow"),
            ("crash", "allow"),
            ("slow", "allow"),
            ("failed", "allow"),
            ("not_discovered", "allow"),
        ]
    ]
    path.write_text(yaml.safe_dump({"version": 1, "rules": rules}), encoding="utf-8")


@asynccontextmanager
async def connected(
    tmp_path,
    *,
    server_id="trusted",
    policy_id="trusted",
    timeout=5,
    mode="normal",
    approval_timeout=0.15,
):
    config = tmp_path / "policy.yaml"
    counter = tmp_path / "calls.txt"
    write_policy(config, policy_id)
    command = shlex.join([sys.executable, str(MOCK), str(counter), mode])
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "agentguard.cli",
            "proxy",
            "--config",
            str(config),
            "--stdio-command",
            command,
            "--server-id",
            server_id,
            "--timeout",
            str(timeout),
            "--state-dir",
            str(tmp_path / "state"),
            "--approval-timeout",
            str(approval_timeout),
        ],
    )
    with (tmp_path / "diagnostics.txt").open("w", encoding="utf-8") as diagnostics:
        with anyio.fail_after(25):
            async with (
                stdio_client(parameters, errlog=diagnostics) as (read, write),
                ClientSession(read, write, read_timeout_seconds=10) as client,
            ):
                await client.initialize()
                yield client, counter


def calls(counter):
    return counter.read_text().splitlines() if counter.exists() else []


def code(result):
    assert result.is_error
    return result.structured_content["agentguard"]["code"]


@pytest.mark.anyio
async def test_discovery_and_allowed_call_exactly_once(tmp_path):
    async with connected(tmp_path) as (client, counter):
        listing = await client.list_tools()
        assert {tool.name for tool in listing.tools} == {
            "allowed",
            "denied",
            "approval",
            "unknown",
            "dots.read",
            "crash",
            "slow",
            "failed",
        }
        assert all(tool.input_schema == {"type": "object"} for tool in listing.tools)
        result = await client.call_tool("allowed", {"value": 42})
        assert not result.is_error
        assert result.structured_content == {"name": "allowed", "arguments": {"value": 42}}
        assert calls(counter) == ["allowed"]


@pytest.mark.anyio
async def test_denied_approval_and_unknown_never_execute(tmp_path):
    async with connected(tmp_path) as (client, counter):
        for tool, expected in [
            ("denied", "denied"),
            ("approval", "approval_required"),
            ("unknown", "denied"),
            ("not_discovered", "unknown_tool"),
            ("missing", "denied"),
            ("bad tool", "enforcement_error"),
        ]:
            assert code(await client.call_tool(tool, {"secret": "do-not-log-me"})) == expected
        assert calls(counter) == []
    assert "do-not-log-me" not in (tmp_path / "diagnostics.txt").read_text()


@pytest.mark.anyio
async def test_dotted_tool_names_and_client_identity_are_not_reinterpreted(tmp_path):
    async with connected(tmp_path) as (client, counter):
        assert not (await client.call_tool("dots.read")).is_error
        assert code(await client.call_tool("trusted.allowed")) == "denied"
        assert (
            code(await client.call_tool("denied", {"server_id": "trusted", "name": "allowed"}))
            == "denied"
        )
        assert calls(counter) == ["dots.read"]


@pytest.mark.anyio
async def test_server_identity_isolation(tmp_path):
    async with connected(tmp_path, server_id="other") as (client, counter):
        assert code(await client.call_tool("allowed", {"server_id": "trusted"})) == "denied"
        assert calls(counter) == []


@pytest.mark.anyio
async def test_concurrent_calls_each_execute_once_and_blocks_never_execute(tmp_path):
    async with connected(tmp_path) as (client, counter):
        results = []

        async def invoke(name):
            results.append(await client.call_tool(name))

        async with anyio.create_task_group() as group:
            for _ in range(4):
                for name in ("allowed", "denied", "approval", "dots.read"):
                    group.start_soon(invoke, name)
        assert len(results) == 16
        assert sum(not result.is_error for result in results) == 8
        assert sorted(calls(counter)) == ["allowed"] * 4 + ["dots.read"] * 4


@pytest.mark.anyio
async def test_upstream_disconnect_is_not_retried(tmp_path):
    async with connected(tmp_path) as (client, counter):
        assert code(await client.call_tool("crash")) == "upstream_error"
        assert code(await client.call_tool("allowed")) == "upstream_unavailable"
        assert calls(counter) == ["crash"]


@pytest.mark.anyio
async def test_upstream_protocol_failure_is_sanitized_and_not_retried(tmp_path):
    async with connected(tmp_path) as (client, counter):
        result = await client.call_tool("failed", {"secret": "do-not-log-me"})
        assert code(result) == "upstream_error"
        assert "sensitive-upstream-exception" not in result.model_dump_json()
        assert calls(counter) == ["failed"]
    diagnostics = (tmp_path / "diagnostics.txt").read_text()
    assert "do-not-log-me" not in diagnostics
    assert "sensitive-upstream-exception" not in diagnostics


@pytest.mark.anyio
async def test_timeout_taints_session_without_retry(tmp_path):
    async with connected(tmp_path, timeout=1) as (client, counter):
        assert code(await client.call_tool("slow")) == "upstream_error"
        assert code(await client.call_tool("allowed")) == "upstream_unavailable"
        assert calls(counter) == ["slow"]


@pytest.mark.anyio
async def test_cancellation_propagates_without_retry(tmp_path):
    async with connected(tmp_path) as (client, counter):
        with anyio.CancelScope() as scope:
            async with anyio.create_task_group() as group:

                async def cancel_after_start():
                    while not calls(counter):
                        await anyio.sleep(0.01)
                    scope.cancel()

                group.start_soon(cancel_after_start)
                await client.call_tool("slow")
        with anyio.fail_after(3):
            while not counter.with_suffix(".cancelled").exists():
                await anyio.sleep(0.01)
        assert code(await client.call_tool("allowed")) == "upstream_unavailable"
        assert calls(counter) == ["slow"]


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["invalid", "duplicate", "startup_failure"])
async def test_invalid_catalogue_prevents_startup(tmp_path, mode):
    with pytest.raises(ExceptionGroup):
        async with connected(tmp_path, mode=mode):
            pytest.fail("Invalid catalogue was exposed")
    assert calls(tmp_path / "calls.txt") == []


@pytest.mark.parametrize("source", ["version: 2", "version: 1\ndefaults: {action: allow}", "["])
def test_invalid_config_does_not_start_upstream(tmp_path, source):
    config = tmp_path / "policy.yaml"
    config.write_text(source)
    counter = tmp_path / "calls.txt"
    result = CliRunner().invoke(
        app,
        [
            "proxy",
            "--config",
            str(config),
            "--stdio-command",
            shlex.join([sys.executable, str(MOCK), str(counter)]),
        ],
    )
    assert result.exit_code == 2
    assert result.stdout == ""
    assert not counter.with_suffix(".started").exists()


@pytest.mark.parametrize(
    "source",
    [
        "",
        "   ",
        "missing-agentguard-executable",
        '"unterminated',
        "python server.py | cat",
        "python\x00bad",
    ],
)
def test_invalid_command_rejected(source):
    with pytest.raises(ProxyConfigurationError):
        ProxySettings(parse_command(source))


@pytest.mark.parametrize("identity", ["", "a.b", "*", "a\n", " a", 1])
def test_invalid_server_identity_rejected(identity):
    with pytest.raises(ProxyConfigurationError):
        ProxySettings((sys.executable,), identity)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True, "1"])
def test_invalid_timeout_rejected(timeout):
    with pytest.raises(ProxyConfigurationError):
        ProxySettings((sys.executable,), timeout=timeout)


def test_quoted_arguments_preserved_without_shell_expansion():
    assert parse_command('python "server path.py" "$SECRET"') == (
        "python",
        "server path.py",
        "$SECRET",
    )


@pytest.mark.anyio
async def test_evaluator_exception_never_invokes_upstream(monkeypatch):
    def broken(*args):
        raise RuntimeError("secret")

    monkeypatch.setattr("agentguard.proxy.evaluate", broken)

    async def must_not_call(*args):
        pytest.fail("upstream called after enforcement error")

    guarded = GuardedTools(
        Policy(version=1),
        ProxySettings((sys.executable,)),
        SimpleNamespace(call_tool=must_not_call),
        [],
    )
    assert (
        code(await guarded.call_tool(None, types.CallToolRequestParams(name="allowed")))
        == "enforcement_error"
    )


@pytest.mark.anyio
async def test_repeated_discovery_cursor_rejected():
    async def repeated(**kwargs):
        return types.ListToolsResult(tools=[], next_cursor="again")

    with pytest.raises(ProxyConfigurationError):
        await discover_tools(SimpleNamespace(list_tools=repeated), "trusted")


@pytest.mark.anyio
async def test_no_alternate_resource_or_prompt_execution_path(tmp_path):
    async with connected(tmp_path) as (client, counter):
        capabilities = client.initialize_result.capabilities
        assert capabilities.tools is not None
        assert capabilities.resources is None
        assert capabilities.prompts is None
        with pytest.raises(MCPError):
            await client.get_prompt("allowed")
        with pytest.raises(MCPError):
            await client.read_resource("mock://allowed")
        assert calls(counter) == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "extra",
    [
        {"task": types.TaskMetadata(ttl=1000)},
        {"request_state": "untrusted-resumption"},
        {"input_responses": {}},
    ],
)
async def test_tasks_and_resumptions_never_invoke_upstream(extra):
    async def must_not_call(*args):
        pytest.fail("Unsupported request reached upstream")

    policy = Policy.model_validate(
        {
            "version": 1,
            "rules": [
                {"id": "a", "tools": ["upstream.allowed"], "action": "allow"},
            ],
        }
    )
    guarded = GuardedTools(
        policy,
        ProxySettings((sys.executable,)),
        SimpleNamespace(call_tool=must_not_call),
        [types.Tool(name="allowed", input_schema={"type": "object"})],
    )
    params = types.CallToolRequestParams(name="allowed", **extra)
    assert code(await guarded.call_tool(None, params)) == "unsupported_request"


@pytest.mark.anyio
async def test_documented_demo_server(tmp_path):
    root = Path(__file__).parents[1]
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "agentguard.cli",
            "proxy",
            "--config",
            str(root / "examples/proxy-policy.yaml"),
            "--state-dir",
            str(tmp_path / "state"),
            "--stdio-command",
            shlex.join([sys.executable, str(root / "examples/demo_server.py")]),
        ],
    )
    with (tmp_path / "demo-diagnostics.txt").open("w", encoding="utf-8") as diagnostics:
        async with (
            stdio_client(parameters, errlog=diagnostics) as (read, write),
            ClientSession(read, write, read_timeout_seconds=10) as client,
        ):
            await client.initialize()
            assert [tool.name for tool in (await client.list_tools()).tools] == ["echo"]
            result = await client.call_tool("echo", {"message": "hello"})
            assert not result.is_error
            assert result.content[0].text == "hello"
