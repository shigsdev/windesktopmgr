"""
tests/test_architecture_html.py — Drift detection for architecture.html.

The architecture.html diagram carries claimed numbers: total test count, per-test-file
counts, and line counts for the main modules. Over time those numbers drift from reality
as code is added. This test parses the diagram, computes current reality, and fails
when drift exceeds tolerance — forcing the diagram to be refreshed alongside code.

Tolerance is intentionally generous (10%) so small churn doesn't become pre-commit noise,
but big moves (extracting a blueprint, bulk test-add/remove) will fail loudly.

All checks are pure Python — no subprocess, no psutil, no Windows-specific bits.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
ARCH_PATH = REPO_ROOT / "architecture.html"

TOLERANCE_PCT = 0.10
MIN_ABS_TOLERANCE = 5

TRACKED_FILES = {
    "windesktopmgr.py": REPO_ROOT / "windesktopmgr.py",
    "homenet.py": REPO_ROOT / "homenet.py",
    "templates/index.html": REPO_ROOT / "templates" / "index.html",
    "applogging.py": REPO_ROOT / "applogging.py",
    "tray.py": REPO_ROOT / "tray.py",
    "SystemHealthDiag.py": REPO_ROOT / "SystemHealthDiag.py",
    "dev.py": REPO_ROOT / "dev.py",
}

TEST_FILES = [
    "test_routes.py",
    "test_powershell.py",
    "test_system_health_diag.py",
    "test_summarizers.py",
    "test_pure_functions.py",
    "test_bsod_parsing.py",
    "test_cache_systems.py",
    "test_nlq.py",
    "test_tray.py",
    "test_remediation.py",
    "test_headless.py",
    "test_homenet.py",
    "test_logging.py",
    "test_snapshots.py",
    "test_e2e_smoke.py",
    "test_integration.py",
]


def _count_lines(path: Path) -> int:
    return sum(1 for _ in path.open(encoding="utf-8", errors="replace"))


def _count_test_defs(path: Path) -> int:
    content = path.read_text(encoding="utf-8", errors="replace")
    return len(re.findall(r"^\s+def test_", content, re.M))


def _unit_test_total() -> int:
    """Total def test_ count across all test files except test_integration.py.

    test_integration.py uses @pytest.mark.integration and is excluded from the
    default pytest run via pyproject.toml's -m 'not integration' addopt, so the
    '1,286 tests · 85% coverage' badge reflects unit tests only.
    """
    total = 0
    for name in TEST_FILES:
        if name == "test_integration.py":
            continue
        total += _count_test_defs(REPO_ROOT / "tests" / name)
    return total


def _within_tolerance(claimed: int, actual: int) -> bool:
    delta = abs(claimed - actual)
    allowed = max(int(actual * TOLERANCE_PCT), MIN_ABS_TOLERANCE)
    return delta <= allowed


def _drift_msg(label: str, claimed: int, actual: int) -> str:
    delta = actual - claimed
    pct = (delta / actual * 100) if actual else 0
    sign = "+" if delta >= 0 else ""
    return (
        f"{label}: architecture.html claims {claimed:,}, actual {actual:,} "
        f"({sign}{delta:,}, {sign}{pct:.1f}%) — refresh the diagram"
    )


@pytest.fixture(scope="module")
def arch_html() -> str:
    if not ARCH_PATH.exists():
        pytest.skip(f"{ARCH_PATH} not found")
    return ARCH_PATH.read_text(encoding="utf-8", errors="replace")


class TestArchitectureHtmlDriftTotalTestCount:
    """The big '1,286 tests' badge appears in several places — all should agree
    with actual source test count (within tolerance)."""

    def test_top_badge_matches_actual(self, arch_html: str):
        # Match 4+ digit numbers with comma separator (e.g. "1,286 tests") — this
        # deliberately skips per-file chips like "199 tests" which are checked elsewhere.
        matches = re.findall(r"(\d+,\d{3})\s*tests", arch_html)
        assert matches, "no aggregate 'N,NNN tests' badge found in architecture.html"
        actual = _unit_test_total()
        for claimed_str in matches:
            claimed = int(claimed_str.replace(",", ""))
            assert _within_tolerance(claimed, actual), _drift_msg("total test count badge", claimed, actual)


class TestArchitectureHtmlDriftFileLines:
    """Parses '~N,NNN lines' chips next to each major module."""

    def _claimed_for(self, html: str, module_label: str) -> int | None:
        pattern = re.escape(module_label) + r".*?[·]\s*~?([\d,]+)\s*lines"
        m = re.search(pattern, html, re.DOTALL)
        if not m:
            return None
        return int(m.group(1).replace(",", ""))

    def test_windesktopmgr_py(self, arch_html: str):
        claimed = self._claimed_for(arch_html, "windesktopmgr.py")
        assert claimed is not None, "windesktopmgr.py line count not found in diagram"
        actual = _count_lines(TRACKED_FILES["windesktopmgr.py"])
        assert _within_tolerance(claimed, actual), _drift_msg("windesktopmgr.py lines", claimed, actual)

    def test_homenet_py(self, arch_html: str):
        claimed = self._claimed_for(arch_html, "homenet.py Blueprint")
        assert claimed is not None, "homenet.py line count not found in diagram"
        actual = _count_lines(TRACKED_FILES["homenet.py"])
        assert _within_tolerance(claimed, actual), _drift_msg("homenet.py lines", claimed, actual)


class TestArchitectureHtmlDriftPerTestFile:
    """Each test file chip shows 'N tests · ...' — verify against source."""

    @pytest.mark.parametrize(
        "test_file,chip_label",
        [
            ("test_routes.py", "test_routes.py"),
            ("test_powershell.py", "test_powershell.py"),
            ("test_system_health_diag.py", "test_system_health_diag.py"),
            ("test_summarizers.py", "test_summarizers.py"),
            ("test_pure_functions.py", "test_pure_functions.py"),
            ("test_bsod_parsing.py", "test_bsod_parsing.py"),
            ("test_cache_systems.py", "test_cache_systems.py"),
            ("test_nlq.py", "test_nlq.py"),
            ("test_tray.py", "test_tray.py"),
            ("test_remediation.py", "test_remediation.py"),
            ("test_headless.py", "test_headless.py"),
            ("test_homenet.py", "test_homenet.py"),
            ("test_logging.py", "test_logging.py"),
            ("test_snapshots.py", "test_snapshots.py"),
            ("test_e2e_smoke.py", "test_e2e_smoke.py"),
            ("test_integration.py", "test_integration.py"),
        ],
    )
    def test_chip_matches_actual(self, arch_html: str, test_file: str, chip_label: str):
        pattern = re.escape(chip_label) + r'.*?<div class="test-sub">\s*(\d+)\s*tests'
        m = re.search(pattern, arch_html, re.DOTALL)
        if not m:
            pytest.skip(f"{chip_label} chip not found in architecture.html")
        claimed = int(m.group(1))
        actual = _count_test_defs(REPO_ROOT / "tests" / test_file)
        assert _within_tolerance(claimed, actual), _drift_msg(f"{chip_label} chip", claimed, actual)


class TestArchitectureHtmlExists:
    def test_file_is_present(self):
        assert ARCH_PATH.exists(), f"{ARCH_PATH} missing — architecture diagram must stay checked in"

    def test_file_is_nontrivial(self):
        assert _count_lines(ARCH_PATH) > 100, "architecture.html looks truncated"
