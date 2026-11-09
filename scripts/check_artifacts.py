"""Check built release contents without publishing. Maintained by Belfeki.tn."""

import ast
import configparser
import sys
import tarfile
from email.parser import BytesParser
from pathlib import Path
from zipfile import ZipFile


def check_artifacts(directory: Path) -> None:
    """Require one wheel/sdist with runtime code, license, maintainer, docs and entry point."""
    wheels = list(directory.glob("*.whl"))
    sources = list(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sources) != 1:
        raise ValueError("Expected exactly one wheel and one source distribution.")
    with ZipFile(wheels[0]) as wheel:
        names = set(wheel.namelist())
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        prefix = metadata_name.removesuffix("METADATA")
        metadata = BytesParser().parsebytes(wheel.read(metadata_name))
        assert metadata["Name"] == "agentguard-mcp"
        assert metadata["License-Expression"] == "Apache-2.0"
        assert metadata["Author"] == "Belfeki.tn"
        assert metadata["Maintainer"] == "Belfeki.tn"
        assert metadata["Requires-Python"] == ">=3.11"
        module = ast.parse(wheel.read("agentguard/__init__.py").decode())
        version = next(
            ast.literal_eval(node.value)
            for node in module.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__version__"
                for target in node.targets
            )
        )
        assert metadata["Version"] == version
        for module in (
            "cli.py",
            "diagnostics.py",
            "proxy.py",
            "approvals.py",
            "storage.py",
            "policy/__init__.py",
            "policy/engine.py",
            "policy/loader.py",
            "policy/models.py",
        ):
            assert f"agentguard/{module}" in names, module
        for license_file in ("LICENSE", "NOTICE"):
            assert f"{prefix}licenses/{license_file}" in names
        parser = configparser.ConfigParser()
        parser.read_string(wheel.read(prefix + "entry_points.txt").decode())
        assert parser["console_scripts"]["agentguard"] == "agentguard.cli:app"
        assert not any(name.startswith(("tests/", "examples/", ".venv/")) for name in names)
    with tarfile.open(sources[0]) as source:
        names = {name.split("/", 1)[1] for name in source.getnames() if "/" in name}
        required = {
            "pyproject.toml",
            "LICENSE",
            "NOTICE",
            "README.md",
            "CHANGELOG.md",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "docs/QUICKSTART.md",
            "docs/RELEASE_CHECKLIST.md",
            "src/agentguard/cli.py",
            "tests/test_policy.py",
            "examples/quickstart_client.py",
            "examples/quickstart_server.py",
            "examples/quickstart-policy.yaml",
            "scripts/check_artifacts.py",
        }
        assert required <= names, required - names
        assert not any(
            set(Path(name).parts) & {".venv", ".git", ".aws", ".codex", ".agents", ".env"}
            or name.endswith((".pyc", ".sqlite3", ".db"))
            for name in names
        )


if __name__ == "__main__":
    check_artifacts(Path(sys.argv[1] if len(sys.argv) > 1 else "dist"))
    print("Wheel/sdist contents, license, maintainer, and CLI entry point verified.")
