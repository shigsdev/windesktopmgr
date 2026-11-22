"""tests/test_backlog_html.py -- scripts/backlog_html.py (readable backlog page).

Covers:
  - Done rows, including summaries that themselves contain ``|``
  - Backlog rows of every shape the real file has (5 cells, value folded into
    Feature, no effort/priority at all)
  - Open vs closed: ✅ closes a row, ⏳ (partly shipped) keeps it open
  - Ordering: open by priority then number, closed newest first
  - HTML: markdown text is escaped, closed items start collapsed
  - main(): writes the page, exits 1 on an unreadable backlog
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import backlog_html as bh  # noqa: E402

SAMPLE = """---
name: Feature Backlog
---
## Feature Backlog

### Done

| Date | Category | Feature | Summary |
|------|----------|---------|---------|
| 2026-09-10 | Bug Fix | **Older fix** (PR #1) | Short summary. |
| 2026-10-02 | Feature | **Newer feature (PR #2)** | Uses `dev.py [check|fix|test]` flags. |

### Backlog

| # | Feature | Value Statement | Effort | Priority |
|---|---------|----------------|--------|----------|
| 3 | **Shipped thing** ✅ SHIPPED 2026-04-18 (commit abc). Folded value. | Medium | P1 |
| 6 | **Packaging** | Bundle it into an exe. | Medium | P1 |
| 49 | **Security cleanup** | Rotate tokens. | Small | P0 |

| 42 | **No trailing cells** ✅ SHIPPED 2026-05-08 (PR #18) long prose with no effort or priority
| 63 | ⏳ PR 1 SHIPPED 2026-10-02 (PR #176) — **Diagnostic engine** -- more PRs to come. | Large | P1 |
| 17 | **Plugins <script>alert(1)</script>** | Future vision. | Large | P3 |

**Priority key:** P0 = do next
"""


def _by_number(items):
    return {i.number: i for i in items}


class TestParseDone:
    def test_rows_and_fields(self):
        items = bh.parse_done(SAMPLE)
        assert [i.title for i in items] == ["Older fix (PR #1)", "Newer feature (PR #2)"]
        assert items[0].date == "2026-09-10"
        assert items[0].category == "Bug Fix"
        assert all(i.closed for i in items)

    def test_title_keeps_text_outside_the_bold(self):
        older = bh.parse_done(SAMPLE)[0]
        assert (older.title, older.body) == ("Older fix (PR #1)", "Short summary.")

    def test_pipe_inside_summary_is_kept(self):
        newer = bh.parse_done(SAMPLE)[1]
        assert "`dev.py [check|fix|test]`" in newer.body

    def test_no_done_section_is_empty(self):
        assert bh.parse_done("## nothing here") == []


class TestParseBacklog:
    def test_open_row_with_all_cells(self):
        row = _by_number(bh.parse_backlog(SAMPLE))["6"]
        assert (row.title, row.body, row.effort, row.priority, row.closed) == (
            "Packaging",
            "Bundle it into an exe.",
            "Medium",
            "P1",
            False,
        )

    def test_shipped_row_with_folded_value_is_closed_and_dated(self):
        row = _by_number(bh.parse_backlog(SAMPLE))["3"]
        assert row.closed is True
        assert row.date == "2026-04-18"
        assert row.priority == "P1"
        assert "Folded value." in row.body

    def test_row_without_effort_or_priority(self):
        row = _by_number(bh.parse_backlog(SAMPLE))["42"]
        assert (row.title, row.effort, row.priority, row.closed) == ("No trailing cells", "", "", True)
        assert "long prose" in row.body

    def test_partly_shipped_stays_open_and_is_tagged(self):
        row = _by_number(bh.parse_backlog(SAMPLE))["63"]
        assert row.closed is False
        assert row.title == "Diagnostic engine"
        assert row.tags == ["partly shipped"]

    def test_priority_key_line_is_not_a_row(self):
        assert sorted(i.number for i in bh.parse_backlog(SAMPLE)) == sorted(["3", "6", "49", "42", "63", "17"])


class TestSplitOpenClosed:
    def test_open_by_priority_then_number(self):
        open_items, _ = bh.split_open_closed(bh.parse_backlog(SAMPLE))
        assert [i.number for i in open_items] == ["49", "6", "63", "17"]

    def test_closed_newest_first_undated_last(self):
        items = bh.parse_backlog(SAMPLE) + bh.parse_done(SAMPLE)
        items.append(bh.Item(title="Undated", body="", closed=True))
        _, closed = bh.split_open_closed(items)
        assert [i.date for i in closed] == ["2026-10-02", "2026-09-10", "2026-05-08", "2026-04-18", ""]


class TestRender:
    def _page(self):
        return bh.build(SAMPLE, "backlog.md", now=datetime(2026, 10, 2, 13, 0))

    def test_markup_in_backlog_text_is_escaped(self):
        page = self._page()
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page

    def test_closed_section_is_collapsed_and_counts_every_done_item(self):
        page = self._page()
        assert '<details class="closed-all" id="closed" data-total="4 items">' in page
        assert page.count('<details class="done"') == 4

    def test_open_items_come_before_closed(self):
        page = self._page()
        assert page.index("Security cleanup") < page.index('id="closed"') < page.index("Newer feature")

    def test_markdown_inside_code_is_literal(self):
        assert bh._inline("run `glob **/*.py` then **done**") == (
            "run <code>glob **/*.py</code> then <strong>done</strong>"
        )

    def test_inline_markdown(self):
        assert bh._inline("**b** `c` [x](https://e.com)") == (
            '<strong>b</strong> <code>c</code> <a href="https://e.com">x</a>'
        )

    def test_header_counts(self):
        assert "4 open · 4 closed · generated 2026-10-02 13:00" in self._page()


class TestMain:
    def test_writes_page(self, tmp_path):
        src = tmp_path / "backlog.md"
        src.write_text(SAMPLE, encoding="utf-8")
        out = tmp_path / "out.html"
        missing_inbox = tmp_path / "no-inbox.md"
        assert bh.main(["--backlog", str(src), "--inbox", str(missing_inbox), "--out", str(out)]) == 0
        assert out.read_text(encoding="utf-8").startswith("<!doctype html>")

    def test_unreadable_backlog_exits_1(self, tmp_path, capsys):
        out = tmp_path / "out.html"
        assert bh.main(["--backlog", str(tmp_path / "missing.md"), "--out", str(out)]) == 1
        assert "cannot read" in capsys.readouterr().err
        assert not out.exists()

    def test_inbox_rows_are_merged_and_tagged(self, tmp_path):
        src = tmp_path / "BACKLOG.md"
        src.write_text(SAMPLE, encoding="utf-8")
        inbox = tmp_path / "backlog_inbox.md"
        inbox.write_text(
            """### Backlog

| # | Feature | Effort | Priority |
|---|---|---|---|
| 120 | **Scan finding: F401 in a.py** found by codehealth | Small | P1 |
""",
            encoding="utf-8",
        )
        out = tmp_path / "out.html"
        assert bh.main(["--backlog", str(src), "--inbox", str(inbox), "--out", str(out)]) == 0
        page = out.read_text(encoding="utf-8")
        assert "Scan finding: F401 in a.py" in page
        assert '<span class="chip warn">inbox</span>' in page

    def test_defaults_point_at_repo_root(self):
        root = Path(__file__).resolve().parent.parent
        if "WINDESKTOPMGR_BACKLOG_PATH" not in __import__("os").environ:
            assert Path(bh.BACKLOG_PATH) == root / "BACKLOG.md"
        if "WINDESKTOPMGR_BACKLOG_INBOX_PATH" not in __import__("os").environ:
            assert Path(bh.INBOX_PATH) == root / "backlog_inbox.md"


class TestEscapedPipes:
    r"""Cells write a literal pipe as ``\|`` (GitHub's table escape; codehealth
    emits it too). It must not split columns, and renders as a plain pipe."""

    MD = r"""### Done

| Date | Category | Feature | Summary |
|---|---|---|---|
| 2026-11-22 | Bug Fix | **A \| B** (PR #9) | ran `dev.py [check\|fix]` ok |

### Backlog

| # | Feature | Value | Effort | Priority |
|---|---|---|---|---|
| 7 | **Pipe \| title** | value with \| pipe | Small | P1 |
| 8 | ✅ 2026-11-01 **Closed \| row** | body \| text |
"""

    def test_done_cells_unescape(self):
        (item,) = bh.parse_done(self.MD)
        assert item.title == "A | B (PR #9)"
        assert item.body == "ran `dev.py [check|fix]` ok"
        assert item.category == "Bug Fix"

    def test_backlog_cells_unescape_and_keep_effort_priority(self):
        items = {i.number: i for i in bh.parse_backlog(self.MD)}
        assert items["7"].title == "Pipe | title"
        assert items["7"].body == "value with | pipe"
        assert (items["7"].effort, items["7"].priority) == ("Small", "P1")
        assert items["8"].closed is True
        assert items["8"].title == "Closed | row"
        assert items["8"].date == "2026-11-01"

    def test_rsplit_matches_str_rsplit_without_escapes(self):
        assert bh._rsplit("a|b|c|d", 2) == ["a|b", "c", "d"]
        assert bh._rsplit("a|b", 0) == ["a|b"]
        assert bh._rsplit(r"a|b\|c|d", 2) == ["a", r"b\|c", "d"]


class TestRealBacklogFile:
    """BACKLOG.md is in a PUBLIC repo. Guard the redaction rules the user
    chose (2026-11-22) and that the file still parses."""

    PATH = Path(__file__).resolve().parent.parent / "BACKLOG.md"

    def _text(self):
        return self.PATH.read_text(encoding="utf-8")

    def test_parses_into_open_and_closed_items(self):
        items = bh.parse_backlog(self._text()) + bh.parse_done(self._text())
        open_items, closed = bh.split_open_closed(items)
        assert len(open_items) >= 10
        assert len(closed) >= 270

    def test_no_private_network_details(self):
        import re

        text = self._text()
        lan_ip = re.findall(r"\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", text)
        mac = re.findall(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", text)
        assert not lan_ip, f"unredacted LAN IPs: {lan_ip} -- write [redacted-ip]"
        assert not mac, f"unredacted MACs: {mac} -- write [redacted-mac]"

    def test_no_service_tag_or_secret_locations(self):
        text = self._text()
        for needle in ("9T46D14", "ConsoleHost_history", "716/718/720"):
            assert needle not in text, f"{needle!r} must stay out of the public backlog"
