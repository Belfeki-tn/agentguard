"""Diagnostic/simulation CLI contracts and the executable quickstart."""

import json
import os
import shlex
import shutil
import stat
import sys
from pathlib import Path

import anyio
import pytest
from typer.testing import CliRunner

from agentguard.cli import app
from agentguard.storage import StateStore

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def anyio_backend():
    return "asyncio"


def doctor_args(tmp_path, command=None):
    config = tmp_path / "policy.yaml"
    config.write_text("version: 1\n")
    config.chmod(0o600)
    return [
        "doctor",
        "--config",
        str(config),
        "--stdio-command",
        command or sys.executable,
        "--state-dir",
        str(tmp_path / "state"),
    ]


def test_doctor_success_uses_disposable_probes_not_persistent_state(tmp_path):
    result = CliRunner().invoke(app, [*doctor_args(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["ok"] is True
    assert all(check["ok"] for check in data["checks"])
    assert not (tmp_path / "state").exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["policy.yaml"]


def test_doctor_does_not_change_existing_audit_or_expire_approvals(tmp_path):
    store = StateStore(tmp_path / "state")
    before = store.path.read_bytes()
    result = CliRunner().invoke(app, doctor_args(tmp_path))
    assert result.exit_code == 0, result.output
    assert store.path.read_bytes() == before
    assert sorted(path.name for path in store.directory.iterdir()) == ["audit.sqlite3"]


@pytest.mark.parametrize("mode", [0o755, 0o775, 0o777])
@pytest.mark.parametrize("alias", [False, True])
def test_doctor_reuses_current_interpreter_with_hosted_permissions(
    tmp_path, monkeypatch, mode, alias
):
    # Real files reproduce framework/toolcache modes; never chmod the real host Python.
    binary = tmp_path / "python runtime"
    shutil.copyfile(Path(sys.executable).resolve(), binary)
    binary.chmod(mode)
    command_path = tmp_path / "python-link" if alias else binary
    if alias:
        command_path.symlink_to(binary)
        assert command_path.is_symlink()
    monkeypatch.setattr(sys, "executable", str(binary))

    def forbidden(*args, **kwargs):
        pytest.fail("Doctor launched an upstream")

    monkeypatch.setattr("agentguard.proxy.stdio_client", forbidden)
    monkeypatch.setattr("agentguard.cli.run_proxy", forbidden)
    result = CliRunner().invoke(
        app, [*doctor_args(tmp_path, shlex.quote(str(command_path))), "--json"]
    )
    assert result.exit_code == 0, result.output
    upstream = next(
        check for check in json.loads(result.stdout)["checks"] if check["check"] == "upstream"
    )
    assert upstream["ok"] is True
    assert ("Warning" in upstream["message"]) == bool(mode & 0o022)


@pytest.mark.parametrize("mode", [0o755, 0o775, 0o777, 0o644])
@pytest.mark.parametrize("alias", [False, True])
def test_doctor_checks_unrelated_executable_target_permissions(tmp_path, mode, alias):
    binary = tmp_path / "unrelated-python"
    binary.write_text("#!/bin/sh\nexit 97\n")
    binary.chmod(mode)
    command_path = tmp_path / "alias" if alias else binary
    if alias:
        command_path.symlink_to(binary)
    assert stat.S_IMODE(binary.stat().st_mode) == mode
    result = CliRunner().invoke(
        app, [*doctor_args(tmp_path, shlex.quote(str(command_path))), "--json"]
    )
    upstream = next(
        check for check in json.loads(result.stdout)["checks"] if check["check"] == "upstream"
    )
    assert upstream["ok"] is (mode == 0o755)
    assert result.exit_code == (0 if mode == 0o755 else 1)


@pytest.mark.parametrize("kind", ["broken_link", "link_loop", "directory", "fifo"])
def test_doctor_rejects_invalid_executable_paths(tmp_path, kind):
    path = tmp_path / "unsafe-command"
    if kind == "broken_link":
        path.symlink_to(tmp_path / "missing")
    elif kind == "link_loop":
        path.symlink_to(path)
    elif kind == "directory":
        path.mkdir(mode=0o755)
    else:
        os.mkfifo(path, 0o700)
    result = CliRunner().invoke(app, [*doctor_args(tmp_path, shlex.quote(str(path))), "--json"])
    upstream = next(
        check for check in json.loads(result.stdout)["checks"] if check["check"] == "upstream"
    )
    assert not upstream["ok"]
    assert result.exit_code == 1


@pytest.mark.parametrize(
    "command",
    [
        "missing-agentguard-executable SECRET",
        '"unterminated SECRET',
        "python | cat SECRET",
        "python\x00SECRET",
    ],
)
def test_doctor_invalid_commands_remain_sanitized(tmp_path, command):
    result = CliRunner().invoke(app, [*doctor_args(tmp_path, command), "--json"])
    assert result.exit_code == 1
    upstream = next(
        check for check in json.loads(result.stdout)["checks"] if check["check"] == "upstream"
    )
    assert not upstream["ok"]
    assert "SECRET" not in result.output


def test_doctor_identity_check_exception_is_sanitized(tmp_path, monkeypatch):
    binary = tmp_path / "credential-in-filename"
    binary.write_text("not-executed")
    binary.chmod(0o775)

    def broken(*args):
        raise PermissionError("credential-in-exception")

    monkeypatch.setattr(Path, "samefile", broken)
    result = CliRunner().invoke(app, [*doctor_args(tmp_path, shlex.quote(str(binary))), "--json"])
    assert result.exit_code == 1
    assert "credential-in-filename" not in result.output
    assert "credential-in-exception" not in result.output


@pytest.mark.parametrize(
    "failure",
    [
        "policy",
        "command",
        "state_mode",
        "state_symlink",
        "database_mode",
        "database_corrupt",
        "policy_mode",
    ],
)
def test_doctor_failure_is_actionable_and_sanitized(tmp_path, failure):
    args = doctor_args(tmp_path)
    secret = "SECRET-DO-NOT-PRINT"
    if failure == "policy":
        (tmp_path / "policy.yaml").write_text(f"version: 1\nunknown: {secret}")
    elif failure == "command":
        args[args.index("--stdio-command") + 1] = f"missing-agentguard-executable {secret}"
    elif failure == "state_mode":
        (tmp_path / "state").mkdir(mode=0o755)
    elif failure == "state_symlink":
        target = tmp_path / "other"
        target.mkdir(mode=0o700)
        (tmp_path / "state").symlink_to(target)
    elif failure.startswith("database_"):
        store = StateStore(tmp_path / "state")
        if failure == "database_mode":
            store.path.chmod(0o644)
        else:
            store.path.write_bytes(secret.encode())
    else:
        (tmp_path / "policy.yaml").chmod(0o666)
    result = CliRunner().invoke(app, [*args, "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["ok"] is False
    assert secret not in result.output
    assert "Traceback" not in result.output


def test_doctor_reports_probe_failure_without_raw_exception(tmp_path, monkeypatch):
    def broken(*args):
        raise OSError("private-path-and-credential")

    monkeypatch.setattr("agentguard.diagnostics._probe_prerequisites", broken)
    result = CliRunner().invoke(app, doctor_args(tmp_path))
    assert result.exit_code == 1
    assert "FIFO/SQLite probe failed" in result.output
    assert "private-path-and-credential" not in result.output


def test_doctor_refuses_fifo_policy_without_reading_it(tmp_path):
    args = doctor_args(tmp_path)
    path = tmp_path / "policy.yaml"
    path.unlink()
    os.mkfifo(path, 0o600)
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    assert "FAIL policy" in result.stdout


def test_doctor_missing_config_and_invalid_server_id(tmp_path):
    args = doctor_args(tmp_path)
    (tmp_path / "policy.yaml").unlink()
    result = CliRunner().invoke(app, [*args, "--server-id", "invalid.id", "--json"])
    assert result.exit_code == 1
    checks = {item["check"]: item["ok"] for item in json.loads(result.stdout)["checks"]}
    assert checks["policy"] is False
    assert checks["upstream"] is False


@pytest.mark.parametrize("field,value", [("platform", "win32"), ("version_info", (3, 10))])
def test_doctor_reports_unsupported_environment(tmp_path, monkeypatch, field, value):
    monkeypatch.setattr(f"agentguard.diagnostics.sys.{field}", value)
    result = CliRunner().invoke(app, [*doctor_args(tmp_path), "--json"])
    assert result.exit_code == 1
    assert not json.loads(result.stdout)["ok"]


@pytest.mark.parametrize(
    "tool,action,rule",
    [
        ("upstream.echo", "allow", "allow-echo"),
        ("upstream.blocked_echo", "deny", "deny-echo"),
        ("upstream.protected_echo", "approve", "review-echo"),
        ("other.echo", "deny", None),
    ],
)
@pytest.mark.parametrize("json_output", [False, True])
def test_simulation_decisions_and_output(tool, action, rule, json_output):
    args = [
        "policy",
        "test",
        "--config",
        str(ROOT / "examples/quickstart-policy.yaml"),
        "--tool",
        tool,
    ]
    result = CliRunner().invoke(app, [*args, *(["--json"] if json_output else [])])
    assert result.exit_code == 0, result.output
    if json_output:
        data = json.loads(result.stdout)
        assert data == {
            "tool": tool,
            "action": action,
            "matched_rule": rule,
            "explanation": data["explanation"],
        }
        assert data["explanation"]
    else:
        assert f"Tool: {tool}" in result.stdout
        assert f"Decision: {action}" in result.stdout
        assert f"Matched rule: {rule or '(none)'}" in result.stdout
        assert "Explanation:" in result.stdout


@pytest.mark.parametrize("source", ["version: 2", "version: 1\nextra: SECRET", "[", ""])
def test_simulation_invalid_config_json_exit_code(tmp_path, source):
    policy = tmp_path / "policy.yaml"
    policy.write_text(source)
    result = CliRunner().invoke(
        app, ["policy", "test", "--config", str(policy), "--tool", "upstream.echo", "--json"]
    )
    assert result.exit_code == 2
    assert json.loads(result.stdout) == {"error": "invalid_policy_or_tool"}
    assert "SECRET" not in result.output


@pytest.mark.parametrize("tool", ["echo", "upstream.*", "bad tool", "upstream.echo\n"])
def test_simulation_invalid_tool_exit_code(tool):
    result = CliRunner().invoke(
        app,
        [
            "policy",
            "test",
            "--config",
            str(ROOT / "examples/quickstart-policy.yaml"),
            "--tool",
            tool,
        ],
    )
    assert result.exit_code == 2
    assert "Invalid policy or tool" in result.output


def test_doctor_and_simulation_never_launch_upstream(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Preflight or simulation started a process/store")

    monkeypatch.setattr("agentguard.cli.run_proxy", forbidden)
    monkeypatch.setattr("agentguard.proxy.stdio_client", forbidden)
    monkeypatch.setattr("agentguard.cli.StateStore", forbidden)
    sentinel = tmp_path / "executed.txt"
    command = f"{sys.executable} -c \"open('{sentinel}', 'w').write('executed')\""
    assert CliRunner().invoke(app, doctor_args(tmp_path, command)).exit_code == 0
    assert (
        CliRunner()
        .invoke(
            app,
            [
                "policy",
                "test",
                "--config",
                str(tmp_path / "policy.yaml"),
                "--tool",
                "upstream.echo",
            ],
        )
        .exit_code
        == 0
    )
    assert not sentinel.exists()


@pytest.mark.parametrize("args", [["doctor"], ["policy", "test"], ["policy", "unknown"]])
def test_cli_usage_exit_codes(args):
    assert CliRunner().invoke(app, args).exit_code == 2


@pytest.mark.anyio
@pytest.mark.parametrize(
    "tool,expected_error", [("echo", False), ("blocked_echo", True), ("protected_echo", False)]
)
async def test_quickstart_client_actual_cli_and_audit(tmp_path, tool, expected_error):
    state = (tmp_path / "state").resolve()
    store = StateStore(state)

    async def operator():
        with anyio.fail_after(10):
            while not (rows := store.list_pending()):
                await anyio.sleep(0.025)
        rid = rows[0]["request_id"]
        base = [sys.executable, "-m", "agentguard.cli", "approvals", "--state-dir", str(state)]
        shown = await anyio.run_process([*base, "show", rid])
        assert json.loads(shown.stdout)["arguments"] == {"message": "hello"}
        await anyio.run_process([*base, "approve", rid])

    async with anyio.create_task_group() as group:
        if tool == "protected_echo":
            group.start_soon(operator)
        completed = await anyio.run_process(
            [
                sys.executable,
                str(ROOT / "examples/quickstart_client.py"),
                "--tool",
                tool,
                "--state-dir",
                str(state),
            ]
        )
        result = json.loads(completed.stdout.decode().splitlines()[-1])
        assert result["isError"] == expected_error
        if expected_error:
            assert result["structuredContent"]["agentguard"]["code"] == "denied"
        else:
            assert result["content"][0]["text"] == "hello"
    import sqlite3

    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT qualified_tool FROM requests").fetchone()[0] == f"upstream.{tool}"
