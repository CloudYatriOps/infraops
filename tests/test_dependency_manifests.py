from pathlib import Path

from aep.dependency.manifests import discover_manifests
from aep.dependency.models import Ecosystem


def test_discovers_python_requirements(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3.1\n")
    found = discover_manifests(str(tmp_path))
    assert len(found) == 1
    assert found[0].ecosystem == Ecosystem.PYTHON
    assert found[0].path == "requirements.txt"


def test_discovers_multiple_ecosystems_not_python_only(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.4\n")
    (tmp_path / "package.json").write_text('{"name": "x", "dependencies": {}}\n')
    (tmp_path / "go.mod").write_text("module example.com/x\n\ngo 1.21\n")
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")

    found = discover_manifests(str(tmp_path))
    ecosystems = {m.ecosystem for m in found}
    assert ecosystems == {Ecosystem.PYTHON, Ecosystem.NODE, Ecosystem.GO, Ecosystem.CONTAINER}


def test_ignores_node_modules_and_git_and_venv(tmp_path: Path):
    (tmp_path / "node_modules" / "left-pad").mkdir(parents=True)
    (tmp_path / "node_modules" / "left-pad" / "package.json").write_text("{}")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "package.json").write_text("{}")
    (tmp_path / "venv" / "lib").mkdir(parents=True)
    (tmp_path / "venv" / "lib" / "requirements.txt").write_text("x==1\n")
    (tmp_path / "package.json").write_text('{"name": "root"}')

    found = discover_manifests(str(tmp_path))
    assert len(found) == 1
    assert found[0].path == "package.json"


def test_no_manifests_found_returns_empty_list(tmp_path: Path):
    (tmp_path / "README.md").write_text("nothing to see here\n")
    assert discover_manifests(str(tmp_path)) == []
