# Deterministic policy engine

Developed and maintained by **Belfeki.tn**.

This milestone implements standalone configuration validation and evaluation.
The [MCP stdio proxy](MCP_PROXY.md) now consumes this engine. The approval workflow,
audit storage, dashboard, and simulation CLI are planned. An evaluation never
executes a tool or grants an approval.

## Public interfaces

Import from `agentguard.policy`:

- `parse_policy(source: str) -> Policy` parses one YAML document.
- `load_policy(path: str | Path) -> Policy` reads a UTF-8 file and parses it.
- `evaluate(policy: Policy, tool: str) -> Decision` evaluates a qualified tool name.
- `Policy`, `Defaults`, `Rule`, and `Decision` are immutable Pydantic v2 models.
- `PolicyValidationError` identifies unreadable files or invalid configuration.

`version: 1` is required. Omitted `defaults` means `{action: deny}`; other default
actions are rejected. Omitted `rules` means an empty rule list, denying all tools.
Each rule requires a unique `id`, a nonempty list of unique `tools`, and an
`action` of `allow`, `deny`, or `approve`. Rule IDs use ASCII letters, digits,
underscores, and hyphens. Unknown fields are rejected at every model level.
Numbers, booleans, and other scalar values are never coerced into strings;
the version must be an integer, excluding booleans.

Tool names use `server.tool`: the server uses ASCII letters, digits, underscores,
and hyphens; the tool uses those characters plus dots. Matching compares the
entire qualified string exactly and is case-sensitive. Names are never trimmed,
case-folded, or expanded. Wildcards and unqualified names are rejected. Transport
adapters must supply the same qualified identity used in configuration.

YAML uses a safe loader. Duplicate mapping keys, non-string mapping keys,
aliases, merge keys, custom object tags, and multiple documents are rejected.
Overlapping rules are valid and resolved by the documented precedence, rather
than silently overwriting one another.

## Evaluation semantics

1. Find all rules containing the exact tool name.
2. Select the highest-precedence action: `deny > approve > allow`.
3. Among rules with the same action, select the first in document order.
4. If no rule matches, return `deny` with no matched rule.

For example, an allow for `deploy.production` and an approval rule for that same
name produce `approve`, regardless of their order. Adding a matching deny
produces `deny`. An unrelated deny has no effect on that tool.

Every decision contains `action`, `matched_rule` (the full immutable rule, or
`None` for default denial), and a human-readable `explanation`. Use the structured
fields for control flow. `decision.model_dump(mode="json")` produces a JSON-compatible
dictionary. `approve` means approval is required; it is never permission to execute.

Invalid tool input raises `ValueError` (Pydantic `ValidationError`). Invalid
configuration raises `PolicyValidationError` before any policy is returned.
Callers must stop on errors and must never convert exceptions into permission to
execute. Do not use Pydantic's validation-bypassing construction/copy methods for
untrusted data.

## Architecture decision

Use three small modules with a single public import surface:

- `models.py` owns strict schema validation and immutable values.
- `loader.py` owns file I/O, safe YAML parsing, and configuration errors.
- `engine.py` depends only on the models and Pydantic input validation. It performs
  a pure linear scan, with no transport, file I/O, clock, network, or mutable state.

The evaluator uses a linear scan to keep precedence visible and avoid cached
state. Immutable tuples prevent later changes to input lists from changing an
active policy. Future transport adapters can depend on this package; this
package must never depend on them. This keeps evaluation independently testable.

## Threat model for this milestone

The configuration boundary treats YAML as untrusted data and rejects ambiguous
keys, unsafe constructors, and invalid policy shapes. Conservative conflict
resolution prevents a broad set of allows from overriding an explicit deny or
approval requirement. Exact matching avoids prefix, wildcard, and cross-server
permission inheritance.

This engine assumes a trusted host and application code, with policy documents
small enough to parse in local memory. It does not impose resource limits on
hostile, arbitrarily large YAML documents. It cannot authenticate a server's
identity, constrain tool arguments, sandbox tools, prevent direct tool calls,
or enforce decisions. Those boundaries require the future proxy and approval
workflow. Only calls actually routed through that future proxy can be governed.

## Validation

Run `pytest` and `ruff check .` after installing `pip install -e '.[dev]'`.
Tests cover all actions, default denial, exact matching, every three-action
conflict order, ties, malformed YAML, invalid schema and names, immutability,
file errors, and the shipped example. Hypothesis checks precedence across action
lists, repeatability, and isolation between server names.
