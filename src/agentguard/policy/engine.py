"""Deterministic evaluation with no I/O or MCP dependencies."""

from pydantic import TypeAdapter

from .models import Decision, Policy, ToolName

_TOOL_NAME = TypeAdapter(ToolName)
_PRECEDENCE = {"allow": 0, "approve": 1, "deny": 2}


def evaluate(policy: Policy, tool: str) -> Decision:
    """Evaluate an exact, case-sensitive ``server.tool`` name against a policy.

    Deny outranks approve, which outranks allow, regardless of rule order.
    The first rule in document order wins ties. No match returns deny.
    Invalid tool names raise ValueError; callers must treat errors as a refusal
    to execute. No approvals, transport calls or side effects occur here.
    """
    qualified_tool = _TOOL_NAME.validate_python(tool)
    matches = (rule for rule in policy.rules if qualified_tool in rule.tools)
    winner = max(matches, key=lambda rule: _PRECEDENCE[rule.action], default=None)
    if winner is None:
        return Decision(
            action="deny",
            matched_rule=None,
            explanation=f"No rule matches {qualified_tool!r}; denied by default.",
        )
    return Decision(
        action=winner.action,
        matched_rule=winner,
        explanation=(
            f"Rule {winner.id!r} matches {qualified_tool!r}: {winner.action}. "
            "Precedence: deny > approve > allow; first rule wins ties."
        ),
    )
