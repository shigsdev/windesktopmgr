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
        assert bh.main(["--backlog", str(src), "--out", str(out)]) == 0
        assert out.read_text(encoding="utf-8").startswith("<!doctype html>")

    def test_unreadable_backlog_exits_1(self, tmp_path, capsys):
        out = tmp_path / "out.html"
        assert bh.main(["--backlog", str(tmp_path / "missing.md"), "--out", str(out)]) == 1
        assert "cannot read" in capsys.readouterr().err
        assert not out.exists()
