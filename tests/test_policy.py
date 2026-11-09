"""Policy validation and fail-closed, deterministic evaluation contracts."""

from itertools import permutations
from pathlib import Path

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from agentguard.policy import (
    Policy,
    PolicyValidationError,
    Rule,
    evaluate,
    load_policy,
    parse_policy,
)


def policy_with(*actions: str) -> Policy:
    return Policy.model_validate(
        {
            "version": 1,
            "rules": [
                {"id": f"rule-{i}", "tools": ["filesystem.read_file"], "action": action}
                for i, action in enumerate(actions)
            ],
        }
    )


@pytest.mark.parametrize("action", ["allow", "deny", "approve"])
def test_each_action_returns_structured_decision(action):
    policy = policy_with(action)
    decision = evaluate(policy, "filesystem.read_file")
    assert decision.action == action
    assert decision.matched_rule == policy.rules[0]
    assert "rule-0" in decision.explanation
    assert decision.model_dump()["matched_rule"]["id"] == "rule-0"
    assert decision.model_dump_json()


@pytest.mark.parametrize("source", ["version: 1", "version: 1\nrules: []"])
def test_default_is_deny(source):
    decision = evaluate(parse_policy(source), "filesystem.read_file")
    assert decision.action == "deny"
    assert decision.matched_rule is None
    assert "default" in decision.explanation


@pytest.mark.parametrize(
    "tool",
    [
        "other.read_file",
        "filesystem.read",
        "filesystem.read_file_extra",
        "Filesystem.read_file",
        "filesystem.READ_FILE",
        "filesystem.read_file.more",
    ],
)
def test_only_exact_names_match(tool):
    assert evaluate(policy_with("allow"), tool).action == "deny"


@pytest.mark.parametrize("actions", list(permutations(["allow", "approve", "deny"])))
def test_deny_wins_in_every_order(actions):
    result = evaluate(policy_with(*actions), "filesystem.read_file")
    assert result.action == "deny"
    assert result.matched_rule.action == "deny"


@pytest.mark.parametrize("actions", [("allow", "approve"), ("approve", "allow")])
def test_approval_wins_over_allow(actions):
    assert evaluate(policy_with(*actions), "filesystem.read_file").action == "approve"


@pytest.mark.parametrize("action", ["allow", "deny", "approve"])
def test_first_rule_breaks_equal_action_ties(action):
    policy = policy_with(action, action)
    assert evaluate(policy, "filesystem.read_file").matched_rule == policy.rules[0]


def test_unrelated_denial_does_not_override_match():
    policy = Policy.model_validate(
        {
            "version": 1,
            "rules": [
                {"id": "allow", "tools": ["fs.read", "fs.stat"], "action": "allow"},
                {"id": "deny", "tools": ["fs.write"], "action": "deny"},
            ],
        }
    )
    assert evaluate(policy, "fs.read").action == "allow"
    assert evaluate(policy, "fs.stat").action == "allow"


@pytest.mark.parametrize(
    "source",
    [
        "",
        "null",
        "[]",
        "hello",
        "{}",
        "version: 2",
        "version: true",
        'version: "1"',
        "version: 1.0",
        "version: 1\nextra: true",
        "version: 1\nrules: null",
        "version: 1\nrules: {}",
        "version: 1\ndefaults: null",
        "version: 1\ndefaults: {action: allow}",
        "version: 1\ndefaults: {action: approve}",
        "version: 1\ndefaults: {action: deny, extra: true}",
        "version: 1\nversion: 1",
        "version: 1\n---\nversion: 1",
        "version: [",
        "version: 1\nrules: [{id: a, tools: [fs.read], action: allow, action: deny}]",
        "version: 1\nrules: [{id: a, tools: [fs.read], action: allow, surprise: true}]",
        "version: 1\nrules: [{id: a, tools: [fs.read]}]",
        "version: 1\nrules: [{id: a, tools: [fs.read], action: ALLOW}]",
        "version: 1\nrules: [{id: a, tools: [fs.read], action: true}]",
        "version: 1\nrules: [{id: a, tools: [fs.read], action: approval-required}]",
        "version: 1\nrules: [{id: a, tools: [], action: allow}]",
        "version: 1\nrules: [{id: a, tools: fs.read, action: allow}]",
        "version: 1\nrules: [{id: a, tools: [42], action: allow}]",
        "version: 1\nrules: [{id: a, tools: [fs.read, fs.read], action: allow}]",
        "version: 1\nrules: [{id: 42, tools: [fs.read], action: allow}]",
        "version: 1\nrules: [{id: '', tools: [fs.read], action: allow}]",
        (
            "version: 1\nrules: [{id: a, tools: [fs.read], action: allow}, "
            "{id: a, tools: [fs.read], action: deny}]"
        ),
        "version: 1\nrules: &rules []\nother: *rules",
        "version: 1\n<<: {rules: []}",
        "version: 1\n1: value",
        "!!python/object/apply:os.system ['echo unsafe']",
    ],
)
def test_invalid_yaml_policies_are_rejected(source):
    with pytest.raises(PolicyValidationError):
        parse_policy(source)


@pytest.mark.parametrize(
    "tool",
    [
        "",
        "read_file",
        "*.read_file",
        "filesystem.*",
        "filesystem.read?",
        " filesystem.read_file",
        "filesystem.read_file ",
        ".read_file",
        "filesystem.",
        "filesystem.read_file\n",
        "filesystem.read\nfile",
        1,
        None,
        True,
    ],
)
def test_invalid_names_rejected_in_configuration_and_evaluation(tool):
    with pytest.raises(ValidationError):
        Rule(id="read", tools=(tool,), action="allow")
    with pytest.raises(ValueError):
        evaluate(policy_with("allow"), tool)


def test_models_remain_strict_without_yaml_loader():
    with pytest.raises(ValidationError):
        Policy(version=True)
    with pytest.raises(ValidationError):
        Policy(version=1, unknown=True)


def test_policy_cannot_be_mutated():
    policy = policy_with("deny")
    with pytest.raises(ValidationError):
        policy.rules = ()
    with pytest.raises(ValidationError):
        policy.rules[0].action = "allow"
    with pytest.raises(ValidationError):
        policy.defaults.action = "allow"
    assert isinstance(policy.rules, tuple)
    assert isinstance(policy.rules[0].tools, tuple)


def test_input_mutations_do_not_change_policy():
    data = {
        "version": 1,
        "rules": [
            {"id": "a", "tools": ["fs.read"], "action": "allow"},
        ],
    }
    policy = Policy.model_validate(data)
    data["rules"][0]["tools"].append("fs.write")
    assert evaluate(policy, "fs.write").action == "deny"


def test_file_loading_and_errors(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1", encoding="utf-8")
    assert load_policy(path) == Policy(version=1)
    path.write_bytes(b"\xff")
    with pytest.raises(PolicyValidationError, match="Cannot read policy"):
        load_policy(path)
    with pytest.raises(PolicyValidationError):
        load_policy(tmp_path / "missing.yaml")
    with pytest.raises(PolicyValidationError):
        load_policy(tmp_path)


def test_shipped_example():
    policy = load_policy(Path(__file__).parents[1] / "examples" / "agentguard.yaml")
    assert evaluate(policy, "filesystem.read_file").action == "allow"
    assert evaluate(policy, "deploy.production").action == "approve"
    assert evaluate(policy, "database.drop").action == "deny"


@pytest.mark.parametrize("source", [None, 1, b"version: 1"])
def test_non_text_source_rejected(source):
    with pytest.raises(PolicyValidationError):
        parse_policy(source)


@given(st.lists(st.sampled_from(["allow", "approve", "deny"]), max_size=20))
def test_conflict_precedence_and_repeatability(actions):
    policy = policy_with(*actions)
    expected = (
        "deny"
        if "deny" in actions or not actions
        else ("approve" if "approve" in actions else "allow")
    )
    before = policy.model_dump()
    result = evaluate(policy, "filesystem.read_file")
    assert result.action == expected
    assert result == evaluate(policy, "filesystem.read_file")
    assert policy.model_dump() == before


@given(st.from_regex(r"[A-Za-z][A-Za-z0-9_-]{0,20}", fullmatch=True))
def test_unknown_server_never_inherits_allow(server):
    policy = policy_with("allow")
    assert evaluate(policy, f"other_{server}.read_file").action == "deny"


def test_yaml_and_direct_models_have_same_behavior():
    policy = policy_with("allow", "deny")
    source = yaml.safe_dump(policy.model_dump(mode="json"))
    assert parse_policy(source) == policy
