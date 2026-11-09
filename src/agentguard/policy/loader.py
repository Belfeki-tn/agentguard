"""Safe YAML parsing and validation at the configuration boundary."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode

from .models import Policy


class PolicyValidationError(ValueError):
    """The supplied policy cannot be used; callers must stop configuration startup."""


class _PolicyLoader(yaml.SafeLoader):
    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise PolicyValidationError("policy mapping keys must be strings")
            if key in result:
                raise PolicyValidationError(f"duplicate YAML key: {key!r}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def parse_policy(source: str) -> Policy:
    """Parse one YAML document, rejecting aliases, duplicate keys and invalid schema.

    Raise PolicyValidationError on invalid configuration. Never substitute an
    allow policy or continue using a partial configuration after a parsing error.
    """
    if not isinstance(source, str):
        raise PolicyValidationError("policy source must be a string")
    try:
        if any(isinstance(event, AliasEvent) for event in yaml.parse(source)):
            raise PolicyValidationError("YAML aliases are not supported")
        data = yaml.load(source, Loader=_PolicyLoader)
        return Policy.model_validate(data)
    except (yaml.YAMLError, ValidationError, ValueError) as exc:
        raise PolicyValidationError(f"Invalid policy: {exc}") from exc


def load_policy(path: str | Path) -> Policy:
    """Read a UTF-8 policy file; raise PolicyValidationError if unreadable or invalid."""
    try:
        source = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PolicyValidationError(f"Cannot read policy {path}: {exc}") from exc
    return parse_policy(source)
