"""Build real distributions and inspect the release contract."""

import importlib.metadata
import runpy
from pathlib import Path

from hatchling.build import build_sdist, build_wheel

ROOT = Path(__file__).resolve().parents[1]


def test_package_builds_with_license_metadata_and_entry_point(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    build_sdist(str(tmp_path))
    build_wheel(str(tmp_path))
    check = runpy.run_path(str(ROOT / "scripts/check_artifacts.py"))["check_artifacts"]
    check(tmp_path)


def test_installed_console_entry_point_resolves():
    entry = next(
        point
        for point in importlib.metadata.distribution("agentguard-mcp").entry_points
        if point.group == "console_scripts" and point.name == "agentguard"
    )
    from agentguard.cli import app

    assert entry.load() is app
