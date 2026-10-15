"""Packaging metadata must stay consistent with the code."""

from __future__ import annotations

import os
import re
import sys

import pytest

from jamfdisabler import __version__

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_pyproject() -> str:
    path = os.path.join(REPO_ROOT, "pyproject.toml")
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def test_version_matches_pyproject():
    match = re.search(r'^version\s*=\s*"([^"]+)"', read_pyproject(), re.MULTILINE)
    assert match, "pyproject.toml has no version field"
    assert match.group(1) == __version__


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", __version__)


def test_entry_point_target_exists():
    from jamfdisabler import cli

    assert callable(cli.entry)
    assert callable(cli.main)
    assert 'jamfdisabler = "jamfdisabler.cli:entry"' in read_pyproject()


def test_no_third_party_dependencies():
    """The tool must stay dependency-free so the single-file build stays small."""
    text = read_pyproject()
    deps = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.MULTILINE | re.DOTALL)
    assert deps is None or deps.group(1).strip() == ""


def test_build_script_is_present_and_importable():
    path = os.path.join(REPO_ROOT, "scripts", "build.py")
    assert os.path.isfile(path)
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    try:
        import build  # type: ignore

        assert callable(build.main)
        assert build.default_name().startswith("JamfDisabler")
    finally:
        sys.path.pop(0)


def test_workflows_cover_every_platform():
    workflow = os.path.join(REPO_ROOT, ".github", "workflows", "build.yml")
    with open(workflow, "r", encoding="utf-8") as fh:
        text = fh.read()
    for runner in ("macos-14", "macos-13", "ubuntu-latest", "windows-latest"):
        assert runner in text, "missing build runner: {}".format(runner)
    assert "JamfDisabler-macos-arm64" in text
    assert "JamfDisabler-windows-x86_64.exe" in text


def test_docs_mention_the_undo_command():
    with open(os.path.join(REPO_ROOT, "README.md"), "r", encoding="utf-8") as fh:
        readme = fh.read()
    assert "jamfdisabler off" in readme
    assert "does **not** do" in readme or "does *not* do" in readme


def test_workflow_yaml_is_valid():
    """A stray colon in a step name silently breaks the whole workflow."""
    yaml = pytest.importorskip("yaml")
    for name in ("tests.yml", "build.yml"):
        path = os.path.join(REPO_ROOT, ".github", "workflows", name)
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        assert isinstance(data, dict) and data.get("jobs"), "{} has no jobs".format(name)
        for spec in data["jobs"].values():
            for step in spec.get("steps", []):
                assert "name" in step or "uses" in step or "run" in step


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable bits")
def test_shell_scripts_are_executable():
    for name in ("install.sh",):
        path = os.path.join(REPO_ROOT, name)
        assert os.stat(path).st_mode & 0o111, "{} should be executable".format(name)
