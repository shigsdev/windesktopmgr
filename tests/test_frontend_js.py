"""Frontend JS split (backlog #72): static/js/app.js + static/js/tabs/*.js.

The files are classic <script>s sharing globals, loaded in the order of the
<script> tags in templates/index.html. These tests keep that list, the files
on disk and the load order honest.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import codehealth
import windesktopmgr as wdm
from tests.conftest import PROJECT_ROOT, frontend_js_files, read_frontend_js

JS_DIR = Path(PROJECT_ROOT) / "static" / "js"


class TestScriptTags:
    def test_every_js_file_is_loaded_exactly_once(self):
        loaded = [Path(p).resolve() for p in frontend_js_files()]
        on_disk = sorted(p.resolve() for p in JS_DIR.rglob("*.js"))
        assert len(loaded) == len(set(loaded)), "a <script> tag is duplicated in index.html"
        assert sorted(loaded) == on_disk, "index.html <script> tags and static/js/ files differ"

    def test_app_js_loads_first(self):
        # Shared helpers (esc, escJsArg, page switching) must exist before any tab file runs.
        assert Path(frontend_js_files()[0]).name == "app.js"

    def test_split_into_tab_files(self):
        assert len(frontend_js_files()) > 20

    def test_no_file_is_over_the_large_file_limit(self):
        for path in frontend_js_files():
            with open(path, encoding="utf-8") as f:
                lines = sum(1 for _ in f)
            assert lines < codehealth.LARGE_FILE_LINE_THRESHOLD, f"{path} has {lines} lines"

    def test_read_frontend_js_covers_every_file(self):
        js = read_frontend_js()
        assert "function escHtml(" in js  # app.js
        assert "function slugifyConcern(" in js  # tabs/dashboard.js
        assert "function loadArchitecture(" in js  # last file, tabs/architecture.js


class TestServedAndVersioned:
    def test_tab_file_is_served(self, client):
        resp = client.get("/static/js/tabs/dashboard.js")
        try:
            assert resp.status_code == 200
            assert b"function slugifyConcern(" in resp.data
        finally:
            resp.close()

    def test_assets_version_changes_when_a_tab_file_changes(self, monkeypatch):
        real = os.path.getmtime
        target = os.path.join("static", "js", "tabs", "dashboard.js")
        wdm._assets_version_cache = None
        before = wdm._assets_version()

        def bumped(path):
            return real(path) + 100 if os.path.normpath(path).endswith(target) else real(path)

        monkeypatch.setattr(wdm.os.path, "getmtime", bumped)
        assert wdm._assets_version() != before


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")
class TestLoadOrder:
    SCRIPT = os.path.join(PROJECT_ROOT, "scripts", "check_js_load_order.js")

    def _run(self, files):
        proc = subprocess.run(
            ["node", "--expose-internals", self.SCRIPT, *files],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode == 2:
            pytest.skip(f"load-order checker could not run: {proc.stderr.strip()[:200]}")
        return proc

    def test_real_files_have_no_load_time_forward_references(self):
        proc = self._run(frontend_js_files())
        assert proc.returncode == 0, proc.stderr

    def test_checker_catches_a_forward_reference(self, tmp_path):
        early = tmp_path / "early.js"
        late = tmp_path / "late.js"
        early.write_text("function boot() { later(); }\nboot();\n", encoding="utf-8")
        late.write_text("function later() {}\n", encoding="utf-8")
        proc = self._run([str(early), str(late)])
        assert proc.returncode == 1
        assert "later" in proc.stderr

    def test_checker_ignores_callbacks(self, tmp_path):
        early = tmp_path / "early.js"
        late = tmp_path / "late.js"
        early.write_text('document.addEventListener("click", () => later());\n', encoding="utf-8")
        late.write_text("function later() {}\n", encoding="utf-8")
        assert self._run([str(early), str(late)]).returncode == 0
