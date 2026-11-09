# Implementation prompt for a coding agent

You are a senior Python engineer and open-source maintainer. Build **AgentGuard**, a local-first MCP tool permission gateway developed and maintained by **Belfeki.tn**.

## Problem
AI agents invoke MCP tools that can modify files, deploy code, or touch databases. Developers need pre-execution policy enforcement, human approvals, and auditable decisions without rewriting existing MCP servers.

## Product constraints
- Python 3.11+, official MCP Python SDK for integration, Typer CLI, Pydantic v2, PyYAML, SQLite, pytest, Hypothesis, Ruff.
- Local-first, no cloud dependencies, no LLM needed for policy decisions.
- v0.1 supports **stdio MCP** only. Do not claim HTTP transport support.
- The proxy is the enforcement boundary: it controls only calls routed through it.
- Fail closed for invalid config, policy engine exceptions, missing approvals, and proxy errors. Never silently bypass the proxy.
- Default action is deny. Exact server-qualified tool matching first; avoid unsafe wildcard behavior.
- Approvals must be tied to a canonicalized exact request, identity, nonce, and expiry; enforce one-time execution and concurrency safety.
- Redact sensitive fields from logs by default; never store API keys or full raw secrets.
- Do not run untrusted upstream servers without warning; document trust boundaries.
- Keep policy engine pure and independent from MCP transport internals.

## Deliverables
1. Threat model and architecture decision record.
2. Strict Pydantic schema for policy YAML with useful error messages.
3. Pure policy evaluator returning allow, deny, or approval-required with matched rule and reason.
4. stdio MCP proxy forwarding supported protocol methods and intercepting `tools/call` before forwarding. Handle errors, cancellation, initialization, and tool listing carefully.
5. Terminal-based approval mechanism with expiration and single-use protection.
6. Redacted SQLite audit events.
7. `agentguard validate`, `agentguard simulate`, `agentguard proxy`, and `agentguard status` CLI commands.
8. Integration tests with a deliberately dangerous fake MCP server; demonstrate blocked calls never reach upstream.
9. Unit tests, property tests, CI, README, SECURITY.md, CONTRIBUTING.md, and examples.

## Process
Work in small testable milestones. First inspect the repository and summarize the implementation plan. Do not invent MCP SDK APIs: check installed SDK signatures and official docs. Implement one milestone at a time, run tests and lint, and report failures honestly. Do not claim security guarantees or production readiness without evidence. Preserve attribution to Belfeki.tn. Use Apache-2.0 license with a standard license file before publishing.

## Acceptance tests
- Allowed read tool reaches upstream exactly once.
- Denied tool never reaches upstream.
- Approval-required call cannot execute before approval; rejected or expired approval cannot execute.
- Invalid config causes startup failure, not allow-all.
- Concurrent calls cannot reuse the same approval.
- Audit log omits secrets.
- A basic existing MCP stdio server works through the proxy.

Begin with the threat model, policy engine and tests, then implement the proxy. Clearly distinguish implemented from planned functionality.
