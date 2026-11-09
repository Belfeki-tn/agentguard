"""Immutable, strict policy and decision types, independent of transport code."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StringConstraints, model_validator

Action = Literal["allow", "deny", "approve"]
ToolName = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$"),
]
RuleId = Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Za-z0-9_-]+$")]


class StrictModel(BaseModel):
    """Reject unknown fields and coercion; prevent mutation after validation."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Defaults(StrictModel):
    """Only deny is permitted as the fallback action."""

    action: Literal["deny"] = "deny"


class Rule(StrictModel):
    """An action applied to a nonempty collection of exact qualified tool names."""

    id: RuleId
    tools: tuple[ToolName, ...] = Field(min_length=1)
    action: Action

    @model_validator(mode="before")
    @classmethod
    def accept_tool_list(cls, data: object) -> object:
        """Convert YAML arrays to immutable tuples without coercing their items."""
        if isinstance(data, dict) and isinstance(data.get("tools"), list):
            return {**data, "tools": tuple(data["tools"])}
        return data

    @model_validator(mode="after")
    def unique_tools(self) -> "Rule":
        if len(set(self.tools)) != len(self.tools):
            raise ValueError("tools must not contain duplicate names")
        return self


class Policy(StrictModel):
    """Version 1 policy. Empty or omitted rules deny every tool."""

    version: StrictInt = Field(ge=1, le=1)
    defaults: Defaults = Field(default_factory=Defaults)
    rules: tuple[Rule, ...] = ()

    @model_validator(mode="before")
    @classmethod
    def accept_rule_list(cls, data: object) -> object:
        """Convert YAML rule arrays to immutable tuples."""
        if isinstance(data, dict) and isinstance(data.get("rules"), list):
            return {**data, "rules": tuple(data["rules"])}
        return data

    @model_validator(mode="after")
    def unique_rule_ids(self) -> "Policy":
        ids = [rule.id for rule in self.rules]
        if len(set(ids)) != len(ids):
            raise ValueError("rule IDs must be unique")
        return self


class Decision(StrictModel):
    """Evaluation result; approve requires approval and never grants execution."""

    action: Action
    matched_rule: Rule | None
    explanation: str
