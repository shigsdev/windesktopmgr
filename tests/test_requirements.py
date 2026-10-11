"""requirements.txt declares everything the app imports, and requirements.lock
pins the exact versions (tech-debt #66, 2026-10-10).

The app imported anthropic, pywin32, pystray and Pillow without declaring
them, so a fresh ``pip install -r requirements.txt`` gave an app whose tray,
Diagnose and event-log probes could not start.
"""

from __future__ import annotations

import ast
import sys
from importlib.metadata import packages_distributions
from pathlib import Path

import pytest
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import lock_requirements as lr  # noqa: E402 -- scripts/ is not a package

# pywin32 ships these as loose modules that packages_distributions() can miss.
_PYWIN32 = ("win32", "pythoncom", "pywintypes")


def _third_party_imports(paths: list[Path]) -> set[str]:
    local = {p.stem for p in ROOT.glob("*.py")} | {p.stem for p in (ROOT / "scripts").glob("*.py")}
    found: set[str] = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                found.add(node.module.split(".")[0])
    return {m for m in found if m not in sys.stdlib_module_names and m not in local}


def _distribution(module: str) -> str:
    if module.startswith(_PYWIN32):
        return "pywin32"
    dists = packages_distributions().get(module)
    assert dists, f"{module} is imported but no installed package provides it"
    return dists[0]


def _declared(*files: str) -> set[str]:
    return {canonicalize_name(lr.requirement_name(r)) for f in files for r in lr.read_requirements(ROOT / f)}


def _undeclared(paths: list[Path], declared: set[str]) -> list[str]:
    return sorted(
        f"{m} (pip: {_distribution(m)})"
        for m in _third_party_imports(paths)
        if canonicalize_name(_distribution(m)) not in declared
    )


class TestDeclared:
    def test_every_app_import_is_in_requirements_txt(self):
        missing = _undeclared(list(ROOT.glob("*.py")), _declared("requirements.txt"))
        assert missing == [], f"imported by the app but not in requirements.txt: {missing}"

    def test_every_script_import_is_declared(self):
        """Developer scripts may also rely on requirements-dev.txt."""
        declared = _declared("requirements.txt", "requirements-dev.txt")
        missing = _undeclared(list((ROOT / "scripts").glob("*.py")), declared)
        assert missing == [], f"imported by scripts/ but not declared: {missing}"

    def test_lock_pins_every_declared_package(self):
        lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
        pinned = {canonicalize_name(line.split("==")[0]) for line in lock.splitlines() if "==" in line}
        for req in lr.read_requirements(ROOT / "requirements.txt"):
            assert canonicalize_name(lr.requirement_name(req)) in pinned, req


class TestResolve:
    FAKE = {
        "app": ("1.0", ["dep>=2", 'winonly; sys_platform == "win32"', 'nope; sys_platform == "nonexistent"']),
        "dep": ("2.5", ['opt; extra == "socks"', "leaf"]),
        "winonly": ("3.0", []),
        "leaf": ("0.1", ["dep"]),  # a cycle must not loop forever
    }

    def lookup(self, name):
        return self.FAKE[name]

    def test_closure_with_exact_versions(self, monkeypatch):
        monkeypatch.setattr(lr.sys, "platform", "win32")
        pins = lr.resolve(["app>=1"], lookup=self.lookup)
        assert pins == {"app": "1.0", "dep": "2.5", "leaf": "0.1", "winonly": "3.0"}

    def test_names_are_canonical_and_sorted(self):
        pins = lr.resolve(["Leaf"], lookup=lambda n: ("1", []) if canonicalize_name(n) == "leaf" else ("2", []))
        assert list(pins) == ["leaf"]

    def test_missing_package_names_it(self):
        def lookup(name):
            raise lr.PackageNotFoundError(name)

        with pytest.raises(SystemExit, match="not installed: ghost"):
            lr.resolve(["ghost"], lookup=lookup)

    def test_installed_version_outside_the_allowed_range_is_refused(self):
        """A lock must never contradict requirements.txt (anthropic<1 but 1.13 installed)."""
        with pytest.raises(SystemExit, match=r"anthropic 1\.13\.0 is installed but requirements allow anthropic<1"):
            lr.resolve(["anthropic>=0.86,<1"], lookup=lambda n: ("1.13.0", []))

    def test_render_has_header_and_pins(self):
        text = lr.render({"a": "1", "b-c": "2.0"})
        assert text.startswith("#")
        assert "a==1\n" in text and "b-c==2.0\n" in text

    def test_read_requirements_skips_comments_blanks_and_includes(self, tmp_path):
        f = tmp_path / "r.txt"
        f.write_text("# c\n\nflask>=3  # web\n-r other.txt\npsutil>=5,<8\n", encoding="utf-8")
        assert lr.read_requirements(f) == ["flask>=3", "psutil>=5,<8"]
