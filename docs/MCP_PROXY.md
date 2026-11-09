# MCP stdio security proxy

Developer and maintainer: **Belfeki.tn**.

AgentGuard serves one trusted local upstream MCP server over stdio. It uses the
[official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)
2.3 release series for typed client/server sessions, initialization, tool
discovery, request correlation, cancellation, and subprocess lifecycle management.
It does not relay arbitrary JSON-RPC messages.

## Architecture

```text
MCP client → AgentGuard SDK server → GuardedTools → policy engine
                                      ↓ allow only
                              SDK client session → upstream subprocess
```

`agentguard.policy` remains independent of MCP. `agentguard.proxy` contains the
transport adapter, trusted operator settings, startup discovery, and the guarded
invocation handler. `agentguard.cli` validates inputs before launching the proxy
and reports sanitized diagnostics on stderr.

Startup validates the policy and executable, launches the upstream without a
shell, performs the SDK initialization handshake, and reads every tool catalogue
page. Invalid names, duplicate names, repeated pagination cursors, more than 100
pages, or more than 10,000 tools abort startup. A total startup deadline applies
to initialization and discovery. No downstream tool service is exposed before
discovery succeeds.

The downstream SDK server exposes `tools/list`, `tools/call`, and protocol
initialization/ping. No resources, prompts, task execution, or generic forwarding
methods are registered. The startup catalogue is a fixed snapshot; list-change
notifications are not relayed. Restart the proxy when the catalogue changes.
Tools retain their original names, descriptions, and schemas; task execution
metadata is removed. Denied tools can appear in discovery: listing is not permission
to execute them.

Every handled tool call constructs `server_id + "." + original_tool_name` and
evaluates it before any upstream invocation. The operator supplies `server_id`;
neither client arguments/metadata nor the upstream's handshake name can replace
it. A tool named `files.read` on server `workspace` is evaluated as
`workspace.files.read` and forwarded upstream as `files.read`, without splitting
or stripping dots.

## Configuration and CLI

The config file is the existing version 1 policy format. See
[POLICY_ENGINE.md](POLICY_ENGINE.md) for validation rules and precedence
(`deny > approve > allow`). It does not contain executable commands or new proxy
configuration keys.

```bash
agentguard proxy --config agentguard.yaml --stdio-command "python server.py"
agentguard proxy --config agentguard.yaml --stdio-command "python server.py" \
  --server-id workspace --timeout 30
```

`--server-id` defaults to `upstream`, so the first command matches policy names
such as `upstream.read_file`. Set this option explicitly when using another
namespace, for example `--server-id filesystem` for the filesystem rule in
`examples/agentguard.yaml`. Each proxy process has one namespace and one upstream.
Do not reuse a namespace for servers with different trust levels.

`--stdio-command` uses POSIX-style quoting and runs an argv vector with no shell
expansion, pipelines, redirects, or environment substitutions. Use an absolute
interpreter path when necessary. The executable must exist and be executable;
script arguments remain the upstream's responsibility. Commands are trusted
operator input: explicitly launching a shell still runs that shell with your
permissions. The upstream inherits the SDK's restricted default environment,
not the entire gateway environment. Custom credential environment configuration
is not implemented.

`--timeout` must be finite and positive (default 30 seconds). It bounds the total
initialization/discovery phase and each tool invocation. Invalid policy or settings
exit with code 2 before launching the subprocess; startup/protocol failures exit
with code 1. Ctrl-C exits with code 130. Diagnostics never include the command's
arguments, raw requests, configuration contents, or exception traces.

## Decisions and failure behavior

- `allow`: a discovered tool is invoked once through the SDK client.
- `deny`: returns an MCP tool error, with no upstream invocation.
- `approve`: returns an approval-required tool error, with no upstream invocation.
- Unknown or invalid identities, unsupported tasks/resumptions, and enforcement
  exceptions are rejected. Unknown tools remain blocked even if a policy allows
  their names.

Errors use `CallToolResult.is_error` and structured content, for example the wire
form `{"agentguard": {"code": "approval_required"}}` inside `structuredContent`.
Other codes include `denied`, `unknown_tool`, `enforcement_error`,
`unsupported_request`, `upstream_error`, and `upstream_unavailable`. Policy
explanations and sensitive arguments are not included in errors.

Client metadata is not forwarded. Task and interactive resumption parameters are
rejected; sampling, elicitation, roots, progress bridging, and human approval are
not implemented. The upstream SDK client offers no arbitrary downstream callback
path. Normal allowed tool results, including upstream tool error results, are
returned to the client. Protocol/transport exceptions are sanitized.

Concurrent calls are supported. There are no automatic retries, reconnects,
execution caches, or duplicate invocations caused by error handling. An upstream
exception, timeout, or cancellation taints the session and refuses subsequent
calls. Calls already in flight may finish. SDK cancellation is propagated and
context managers clean up the upstream subprocess on disconnect or shutdown.

A cancelled or failed request may already have changed upstream state. This is
not an exactly-once execution guarantee: cancellation cannot roll back a side
effect, and a new client request can repeat a completed action. Investigate an
uncertain outcome before restarting or retrying a non-idempotent operation.

## Working example

From the repository root, after `pip install -e '.[dev]'`, configure your MCP host
to launch:

```bash
agentguard proxy --config examples/proxy-policy.yaml \
  --stdio-command "python examples/demo_server.py"
```

The host can list `echo` and call it with `{"message": "hello"}`. The example
policy permits only `upstream.echo`. Changing that rule's action to `deny` or
`approve` rejects the call; restart the proxy after changing configuration.

For a reproducible SDK-client demonstration, run this Python code from the root:

```python
import asyncio
import shlex
import sys

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main():
    command = shlex.join([sys.executable, "examples/demo_server.py"])
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "agentguard.cli",
            "proxy",
            "--config",
            "examples/proxy-policy.yaml",
            "--stdio-command",
            command,
        ],
    )
    async with stdio_client(parameters) as (read, write):
        async with ClientSession(read, write) as client:
            await client.initialize()
            print(await client.list_tools())
            print(await client.call_tool("echo", {"message": "hello"}))


asyncio.run(main())
```

## Security limitations

Only calls routed through the proxy are protected. Configure the host to use
AgentGuard and remove direct upstream connections. This is not a sandbox: a
malicious upstream can act during startup, discovery, or any allowed call, and
cannot be constrained by policy evaluation alone. Run only trusted commands,
review tool schemas/descriptions, and use least-privilege OS access and credentials.
Policy names do not authenticate an upstream binary, and policy decisions do not
inspect arguments or validate the safety of returned content.

Stdout is exclusively the SDK protocol channel. Upstream stderr is discarded
and SDK payload diagnostics are suppressed to avoid logging secrets. Allowed
tool content still reaches the client unchanged and may itself contain sensitive
data. There is no audit database or persistent request logging in this milestone.

This is an early implementation, not a production security assurance. HTTP/SSE
gateway transports, multiple upstreams, live reload, dashboard, cloud services,
and approval workflows are outside this milestone.

## Tests

Run `python -m pytest -v`, `ruff check .`, and `git diff --check` in the development
environment. Integration tests use a real SDK stdio mock subprocess and a file
counter that records every upstream execution before it performs work. They verify
allow-once behavior, blocked and approval calls with zero executions, identity
isolation, dotted names, pagination, concurrent requests, cancellation, timeouts,
disconnects, invalid startup inputs, and sanitized errors.
