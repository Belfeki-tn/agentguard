"""Lifecycle, binding, private IPC, persistence, and approval enforcement tests."""

import json
import os
import sqlite3
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace

import anyio
import mcp_types as types
import pytest
from mcp.shared.exceptions import MCPError
from test_proxy import calls, code, connected
from typer.testing import CliRunner

from agentguard.approvals import ApprovalCoordinator, canonical_arguments, live_preview
from agentguard.cli import app
from agentguard.policy import Policy
from agentguard.proxy import GuardedTools, ProxySettings
from agentguard.storage import StateError, StateStore, new_request_id


@pytest.fixture
def anyio_backend():
    return "asyncio"


def pending(tmp_path, timeout=2):
    store = StateStore(tmp_path / "state")
    session_id, request_id = new_request_id(), new_request_id()
    store.start(request_id, session_id, "trusted", "trusted.approval")
    store.policy(request_id, "approve", "review")
    coordinator = ApprovalCoordinator(store, session_id, timeout)
    request = coordinator.request(
        request_id,
        "trusted",
        "trusted.approval",
        canonical_arguments({"path": "/example", "token": "secret-value"}),
        "original-request",
        "review",
    )
    return store, coordinator, request


def test_approval_consumption_is_single_use_and_audited(tmp_path):
    store, _, request = pending(tmp_path)
    store.decide(request.request_id, True)
    with pytest.raises(StateError):
        store.decide(request.request_id, True)
    assert store.consume(request.request_id, request.session_id, request.binding)
    assert not store.consume(request.request_id, request.session_id, request.binding)
    store.finish(request.request_id, "success")
    reopened = StateStore(store.directory)
    assert reopened.get(request.request_id)["approval_state"] == "consumed"
    with sqlite3.connect(store.path) as db:
        states = [row[0] for row in db.execute("SELECT approval_state FROM audit_events")]
    assert states == [None, None, "pending", "approved", "consumed", "consumed"]
    for path in store.directory.glob("audit.sqlite3*"):
        assert b"secret-value" not in path.read_bytes()
        assert b"/example" not in path.read_bytes()


@pytest.mark.parametrize("approve", [True, False])
def test_expired_decision_is_rejected(tmp_path, approve):
    store, _, request = pending(tmp_path, timeout=0.001)
    time.sleep(0.01)
    with pytest.raises(StateError):
        store.decide(request.request_id, approve)
    assert store.get(request.request_id)["approval_state"] == "expired"
    assert not store.consume(request.request_id, request.session_id, request.binding)


def test_concurrent_decisions_and_consumptions_have_one_winner(tmp_path):
    store, _, request = pending(tmp_path)

    def approve(_):
        try:
            StateStore(store.directory).decide(request.request_id, True)
            return True
        except StateError:
            return False

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert sum(executor.map(approve, range(4))) == 1
        results = list(
            executor.map(
                lambda _: store.consume(request.request_id, request.session_id, request.binding),
                range(4),
            )
        )
    assert sum(results) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("arguments", '{"path":"/substituted"}'),
        ("qualified_tool", "other.approval"),
        ("server_id", "other"),
        ("session_id", "other-session"),
        ("context", "other-request"),
        ("request_id", "a" * 64),
    ],
)
def test_request_substitution_invalidates_binding(tmp_path, field, value):
    store, coordinator, request = pending(tmp_path)
    altered = replace(request, **{field: value})
    assert coordinator.binding_valid(request)
    assert not coordinator.binding_valid(altered)
    store.decide(request.request_id, True)
    assert not store.consume(request.request_id, "other-session", request.binding)
    assert not store.consume(request.request_id, request.session_id, "wrong-binding")
    assert store.get(request.request_id)["approval_state"] == "approved"


def test_canonicalization_is_exact_and_deterministic():
    assert canonical_arguments({"b": 1, "a": [True, None]}) == canonical_arguments(
        {"a": [True, None], "b": 1}
    )
    assert canonical_arguments(None) != canonical_arguments({})
    assert canonical_arguments({"x": 1}) != canonical_arguments({"x": True})
    assert canonical_arguments({"x": [1, 2]}) != canonical_arguments({"x": [2, 1]})


@pytest.mark.parametrize(
    "value",
    [
        {1: "bad"},
        {"x": float("nan")},
        {"x": float("inf")},
        {"x": (1, 2)},
        {"x": b"secret"},
        {"x": "a" * 40000},
    ],
)
def test_invalid_canonical_arguments_rejected(value):
    with pytest.raises(StateError):
        canonical_arguments(value)


@pytest.mark.anyio
async def test_fifo_preview_and_explicit_rejection(tmp_path):
    store, coordinator, request = pending(tmp_path)
    results = []

    async def wait():
        results.append(await coordinator.wait(request))

    async with anyio.create_task_group() as group:
        group.start_soon(wait)
        preview = await live_preview(store, request.request_id)
        assert preview["arguments"] == {"path": "/example", "token": "secret-value"}
        assert preview["qualified_tool"] == "trusted.approval"
        assert "irreversible" in preview["risk"]
        assert not list(coordinator.directory.iterdir())
        store.decide(request.request_id, False)
    assert results == [False]
    assert store.get(request.request_id)["approval_state"] == "rejected"


@pytest.mark.anyio
async def test_timeout_and_cancellation_cannot_later_approve(tmp_path):
    store, coordinator, request = pending(tmp_path, timeout=0.05)
    assert not await coordinator.wait(request)
    assert store.get(request.request_id)["approval_state"] == "expired"
    with pytest.raises(StateError):
        store.decide(request.request_id, True)

    store, coordinator, request = pending(tmp_path)
    with anyio.move_on_after(0.02):
        await coordinator.wait(request)
    assert store.get(request.request_id)["approval_state"] == "cancelled"
    with pytest.raises(StateError):
        store.decide(request.request_id, True)


@pytest.mark.anyio
async def test_approved_request_cancellation_never_consumes(tmp_path):
    store, coordinator, request = pending(tmp_path)
    store.decide(request.request_id, True)
    with anyio.CancelScope() as scope:
        scope.cancel()
        await coordinator.wait(request)
    assert store.get(request.request_id)["approval_state"] == "cancelled"


def test_permissions_symlinks_and_owner_are_checked(tmp_path, monkeypatch):
    store, _, _ = pending(tmp_path)
    assert store.directory.stat().st_mode & 0o777 == 0o700
    assert store.path.stat().st_mode & 0o777 == 0o600
    store.path.chmod(0o644)
    with pytest.raises(StateError):
        store.list_pending()
    store.path.chmod(0o600)
    monkeypatch.setattr(os, "geteuid", lambda: 999999)
    with pytest.raises(StateError):
        store.list_pending()


def test_symlink_state_path_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(StateError):
        StateStore(link)


def test_sql_injection_is_data_and_cancel_session_is_scoped(tmp_path):
    store, _, request = pending(tmp_path)
    with pytest.raises(StateError):
        store.decide("'; DROP TABLE requests; --", True)
    store.cancel_session("different-session")
    assert store.get(request.request_id)["approval_state"] == "pending"
    store.cancel_session(request.session_id)
    assert store.get(request.request_id)["approval_state"] == "cancelled"


async def wait_pending(store, count=1):
    with anyio.fail_after(5):
        while len(rows := store.list_pending()) < count:
            await anyio.sleep(0.01)
    return rows


@pytest.mark.anyio
async def test_successful_approval_via_real_operator_cli_executes_once(tmp_path):
    async with connected(tmp_path, approval_timeout=5) as (client, counter):
        store = StateStore(tmp_path / "state")
        results = []

        async def invoke():
            results.append(await client.call_tool("approval", {"credential": "never-on-disk"}))

        async with anyio.create_task_group() as group:
            group.start_soon(invoke)
            row = (await wait_pending(store))[0]
            rid = row["request_id"]
            assert calls(counter) == []
            base = [
                sys.executable,
                "-m",
                "agentguard.cli",
                "approvals",
                "--state-dir",
                str(store.directory),
            ]
            shown = await anyio.run_process([*base, "show", rid])
            assert json.loads(shown.stdout)["arguments"] == {"credential": "never-on-disk"}
            await anyio.run_process([*base, "approve", rid])
        assert not results[0].is_error
        assert calls(counter) == ["approval"]
        assert store.get(rid)["approval_state"] == "consumed"
        assert store.get(rid)["outcome"] == "success"
        with sqlite3.connect(store.path) as db:
            assert (
                db.execute(
                    "SELECT COUNT(*) FROM audit_events WHERE request_id=? AND outcome='execution_started'",
                    (rid,),
                ).fetchone()[0]
                == 1
            )
        with pytest.raises(StateError):
            store.decide(rid, True)
        assert b"never-on-disk" not in store.path.read_bytes()
    assert "never-on-disk" not in (tmp_path / "diagnostics.txt").read_text()


@pytest.mark.anyio
async def test_rejection_and_expiration_never_execute_upstream(tmp_path):
    async with connected(tmp_path, approval_timeout=1) as (client, counter):
        store = StateStore(tmp_path / "state")
        results = []

        async def invoke():
            results.append(await client.call_tool("approval"))

        async with anyio.create_task_group() as group:
            group.start_soon(invoke)
            rid = (await wait_pending(store))[0]["request_id"]
            result = CliRunner().invoke(
                app, ["approvals", "--state-dir", str(store.directory), "reject", rid]
            )
            assert result.exit_code == 0
        assert code(results[0]) == "approval_required"
        assert store.get(rid)["approval_state"] == "rejected"
        assert code(await client.call_tool("approval")) == "approval_required"
        assert calls(counter) == []


@pytest.mark.anyio
async def test_pending_proxy_call_cancellation_never_executes(tmp_path):
    async with connected(tmp_path, approval_timeout=5) as (client, counter):
        store = StateStore(tmp_path / "state")
        with anyio.CancelScope() as scope:
            async with anyio.create_task_group() as group:

                async def cancel_pending():
                    await wait_pending(store)
                    scope.cancel()

                group.start_soon(cancel_pending)
                await client.call_tool("approval")
        with anyio.fail_after(3):
            while store.list_pending():
                await anyio.sleep(0.01)
        assert calls(counter) == []
        with sqlite3.connect(store.path) as db:
            rid = db.execute("SELECT request_id FROM requests").fetchone()[0]
        with pytest.raises(StateError):
            store.decide(rid, True)


@pytest.mark.anyio
async def test_sqlite_failure_blocks_before_upstream_and_after_pending(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state")
    policy = Policy.model_validate(
        {"version": 1, "rules": [{"id": "a", "tools": ["upstream.allowed"], "action": "allow"}]}
    )

    async def must_not_call(*args):
        pytest.fail("Upstream invoked despite failed audit")

    guarded = GuardedTools(
        policy,
        ProxySettings((sys.executable,)),
        SimpleNamespace(call_tool=must_not_call),
        [types.Tool(name="allowed", input_schema={})],
        store,
    )

    def broken(*args):
        raise sqlite3.OperationalError("sensitive-error")

    monkeypatch.setattr(store, "start", broken)
    result = await guarded.call_tool(None, types.CallToolRequestParams(name="allowed"))
    assert code(result) == "audit_error"
    assert "sensitive-error" not in result.model_dump_json()


@pytest.mark.anyio
async def test_concurrent_exact_approvals_execute_only_their_own_calls(tmp_path):
    async with connected(tmp_path, approval_timeout=4) as (client, counter):
        store = StateStore(tmp_path / "state")
        results = []

        async def invoke(number):
            results.append(await client.call_tool("approval", {"number": number}))

        async with anyio.create_task_group() as group:
            for number in range(3):
                group.start_soon(invoke, number)
            rows = await wait_pending(store, 3)
            for index, row in enumerate(rows):
                store.decide(row["request_id"], index != 1)
        assert len(calls(counter)) == 2
        assert calls(counter) == ["approval", "approval"]
        assert sum(not result.is_error for result in results) == 2


@pytest.mark.anyio
async def test_proxy_disconnect_invalidates_pending_approval(tmp_path):
    async with (
        anyio.create_task_group() as group,
        connected(tmp_path, approval_timeout=5) as (client, counter),
    ):
        store = StateStore(tmp_path / "state")

        async def invoke():
            try:
                await client.call_tool("approval")
            except MCPError:
                return

        group.start_soon(invoke)
        rid = (await wait_pending(store))[0]["request_id"]
        assert calls(counter) == []
    assert store.get(rid)["approval_state"] == "cancelled"
    assert calls(counter) == []
    with pytest.raises(StateError):
        store.decide(rid, True)


@pytest.mark.anyio
async def test_approval_storage_failure_invalidates_pending_request(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state")
    coordinator = ApprovalCoordinator(store, new_request_id(), 1)
    policy = Policy.model_validate(
        {"version": 1, "rules": [{"id": "a", "tools": ["upstream.approval"], "action": "approve"}]}
    )
    executed = []

    async def upstream(*args):
        executed.append(args)
        return types.CallToolResult(content=[])

    guarded = GuardedTools(
        policy,
        ProxySettings((sys.executable,)),
        SimpleNamespace(call_tool=upstream),
        [types.Tool(name="approval", input_schema={})],
        store,
        coordinator,
    )

    def broken(*args):
        raise sqlite3.OperationalError("private-error")

    monkeypatch.setattr(store, "get", broken)
    result = await guarded.call_tool(None, types.CallToolRequestParams(name="approval"))
    assert code(result) == "audit_error"
    assert not executed
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT approval_state FROM requests").fetchone()[0] == "cancelled"


@pytest.mark.anyio
async def test_completion_audit_failure_never_retries_and_keeps_intent(tmp_path, monkeypatch):
    store = StateStore(tmp_path / "state")
    policy = Policy.model_validate(
        {"version": 1, "rules": [{"id": "a", "tools": ["upstream.allowed"], "action": "allow"}]}
    )
    executed = []

    async def upstream(*args):
        executed.append(args)
        return types.CallToolResult(content=[])

    original = store.finish

    def fail_completion(rid, outcome):
        if outcome == "success":
            raise sqlite3.OperationalError("private-error")
        original(rid, outcome)

    monkeypatch.setattr(store, "finish", fail_completion)
    guarded = GuardedTools(
        policy,
        ProxySettings((sys.executable,)),
        SimpleNamespace(call_tool=upstream),
        [types.Tool(name="allowed", input_schema={})],
        store,
    )
    assert (
        code(await guarded.call_tool(None, types.CallToolRequestParams(name="allowed")))
        == "audit_error"
    )
    assert (
        code(await guarded.call_tool(None, types.CallToolRequestParams(name="allowed")))
        == "upstream_unavailable"
    )
    assert len(executed) == 1
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute(
                "SELECT COUNT(*) FROM requests WHERE outcome='execution_started'"
            ).fetchone()[0]
            == 1
        )


@pytest.mark.anyio
async def test_preview_regular_file_substitution_fails_closed(tmp_path):
    store, coordinator, request = pending(tmp_path)
    fake = coordinator.directory / f"{request.request_id}-{'a' * 64}.fifo"
    fake.write_text("not-a-pipe")
    fake.chmod(0o600)
    with pytest.raises(StateError):
        await coordinator.wait(request)
    assert store.get(request.request_id)["approval_state"] == "cancelled"
    assert fake.read_text() == "not-a-pipe"


def test_cli_list_never_displays_arguments_and_rejects_duplicate(tmp_path):
    store, _, request = pending(tmp_path)
    runner = CliRunner()
    base = ["approvals", "--state-dir", str(store.directory)]
    listed = runner.invoke(app, [*base, "list"])
    assert listed.exit_code == 0
    assert request.request_id in listed.stdout
    assert "secret-value" not in listed.stdout
    assert runner.invoke(app, [*base, "reject", request.request_id]).exit_code == 0
    assert runner.invoke(app, [*base, "reject", request.request_id]).exit_code == 1


@pytest.mark.anyio
async def test_upstream_cannot_inject_audit_outcomes_or_sensitive_data(tmp_path):
    store = StateStore(tmp_path / "state")
    policy = Policy.model_validate(
        {"version": 1, "rules": [{"id": "a", "tools": ["upstream.allowed"], "action": "allow"}]}
    )

    async def upstream(*args):
        return types.CallToolResult(
            is_error=True,
            content=[],
            structured_content={"agentguard": {"code": "sensitive-upstream-content"}},
        )

    guarded = GuardedTools(
        policy,
        ProxySettings((sys.executable,)),
        SimpleNamespace(call_tool=upstream),
        [types.Tool(name="allowed", input_schema={})],
        store,
    )
    await guarded.call_tool(None, types.CallToolRequestParams(name="allowed"))
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT outcome FROM requests").fetchone()[0] == "tool_error"
    assert b"sensitive-upstream-content" not in store.path.read_bytes()


def test_corrupt_sqlite_is_not_silently_replaced(tmp_path):
    store = StateStore(tmp_path / "state")
    store.path.write_bytes(b"invalid-database")
    with pytest.raises(sqlite3.DatabaseError):
        StateStore(store.directory)
    assert store.path.read_bytes() == b"invalid-database"


def test_locked_sqlite_fails_instead_of_bypassing(tmp_path):
    store = StateStore(tmp_path / "state")
    with sqlite3.connect(store.path) as db:
        db.execute("BEGIN EXCLUSIVE")
        with pytest.raises(sqlite3.OperationalError):
            store.start(new_request_id(), new_request_id(), "trusted", "trusted.allowed")


def test_unsafe_state_ancestor_rejected(tmp_path):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    with pytest.raises(StateError):
        StateStore(unsafe / "state")


@pytest.mark.anyio
async def test_mutated_request_cannot_substitute_tool_or_arguments_after_review(tmp_path):
    store = StateStore(tmp_path / "state")
    coordinator = ApprovalCoordinator(store, new_request_id(), 2)
    policy = Policy.model_validate(
        {"version": 1, "rules": [{"id": "a", "tools": ["upstream.approval"], "action": "approve"}]}
    )
    executed = []

    async def upstream(name, arguments):
        executed.append((name, arguments))
        return types.CallToolResult(content=[])

    guarded = GuardedTools(
        policy,
        ProxySettings((sys.executable,)),
        SimpleNamespace(call_tool=upstream),
        [types.Tool(name="approval", input_schema={})],
        store,
        coordinator,
    )
    params = types.CallToolRequestParams(name="approval", arguments={"nested": {"value": 1}})
    async with anyio.create_task_group() as group:
        group.start_soon(guarded.call_tool, None, params)
        row = (await wait_pending(store))[0]
        params.name = "substituted"
        params.arguments["nested"]["value"] = 2
        store.decide(row["request_id"], True)
    assert executed == [("approval", {"nested": {"value": 1}})]


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["cancel_after_consume", "consume_error"])
async def test_failure_at_consumption_boundary_never_executes(tmp_path, monkeypatch, failure):
    store = StateStore(tmp_path / "state")
    coordinator = ApprovalCoordinator(store, new_request_id(), 2)
    policy = Policy.model_validate(
        {"version": 1, "rules": [{"id": "a", "tools": ["upstream.approval"], "action": "approve"}]}
    )
    executed = []

    async def upstream(*args):
        executed.append(args)
        return types.CallToolResult(content=[])

    guarded = GuardedTools(
        policy,
        ProxySettings((sys.executable,)),
        SimpleNamespace(call_tool=upstream),
        [types.Tool(name="approval", input_schema={})],
        store,
        coordinator,
    )
    original_wait = coordinator.wait

    async def decide_and_wait(request):
        store.decide(request.request_id, True)
        allowed = await original_wait(request)
        scope.cancel()
        return allowed

    def broken_consume(*args):
        raise sqlite3.OperationalError("storage-failed")

    if failure == "consume_error":
        monkeypatch.setattr(store, "consume", broken_consume)
    monkeypatch.setattr(coordinator, "wait", decide_and_wait)
    with anyio.CancelScope() as scope:
        result = await guarded.call_tool(None, types.CallToolRequestParams(name="approval"))
        assert failure == "consume_error"
        assert code(result) == "audit_error"
    assert not executed
    with sqlite3.connect(store.path) as db:
        rid, state = db.execute("SELECT request_id,approval_state FROM requests").fetchone()
    assert state == ("consumed" if failure == "cancel_after_consume" else "cancelled")
    with pytest.raises(StateError):
        store.decide(rid, True)


@pytest.mark.anyio
async def test_monotonic_deadline_survives_wall_clock_rollback(tmp_path, monkeypatch):
    store, coordinator, request = pending(tmp_path, timeout=0.04)
    earlier = time.time() - 3600
    monkeypatch.setattr(time, "time", lambda: earlier)
    assert not await coordinator.wait(request)
    assert store.get(request.request_id)["approval_state"] == "expired"


def test_approved_but_expired_request_cannot_be_consumed(tmp_path):
    store, _, request = pending(tmp_path, timeout=0.05)
    store.decide(request.request_id, True)
    time.sleep(0.06)
    assert not store.consume(request.request_id, request.session_id, request.binding)
    assert store.get(request.request_id)["approval_state"] == "expired"


def test_new_state_ancestors_are_private_even_with_permissive_umask(tmp_path):
    previous_umask = os.umask(0)
    try:
        store = StateStore(tmp_path / "new-parent" / "state")
    finally:
        os.umask(previous_umask)
    assert store.directory.parent.stat().st_mode & 0o777 == 0o700
    assert store.directory.stat().st_mode & 0o777 == 0o700
    assert store.path.stat().st_mode & 0o777 == 0o600
