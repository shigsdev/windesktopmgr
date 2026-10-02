#!/usr/bin/env python3
"""backlog_html.py -- Render the project backlog as a readable HTML page.

The backlog lives in project memory as one markdown file with two very wide
tables (``### Done`` and ``### Backlog``). It is the project's record of what
shipped, but 200+ rows of pipe-delimited prose are hard to read. This script
turns it into one standalone page:

* **Open** items at the top, grouped by priority (P0 first).
* **Closed** items at the bottom inside ONE collapsed section; expanding it
  lists every done item, newest first, each expandable for its full summary.

An item is closed when it is a Done-table row, or a Backlog row whose Feature
cell carries a ``✅`` marker (``✅ SHIPPED`` / ``✅ RESOLVED``). A partly shipped
item uses ``⏳`` and stays open.

Usage::

    python scripts/backlog_html.py                 # writes ./backlog.html
    python scripts/backlog_html.py --out x.html    # elsewhere
    python scripts/backlog_html.py --backlog path/to/project_backlog.md

The output is gitignored: the backlog carries operational notes that do not
belong in the public repo. Re-run after every backlog update.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# Same source and override as codehealth.BACKLOG_PATH, so both tools always
# read the same file.
BACKLOG_PATH = os.environ.get(
    "WINDESKTOPMGR_BACKLOG_PATH",
    os.path.expanduser(r"~\.claude\projects\C--shigsapps-windesktopmgr\memory\project_backlog.md"),
)
DEFAULT_OUT = Path(__file__).resolve().parent.parent / "backlog.html"

_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_PRIORITY = re.compile(r"^P[0-3]\b")
_BOLD = re.compile(r"\*\*(.+?)\*\*")


@dataclass
class Item:
    title: str
    body: str  # the full markdown text of the row, minus the title
    closed: bool
    date: str = ""  # YYYY-MM-DD, "" when the row carries none
    number: str = ""  # backlog row number, "" for Done-table rows
    category: str = ""  # Done-table category (Bug Fix, Feature, ...)
    priority: str = ""
    effort: str = ""
    tags: list[str] = field(default_factory=list)


def _inner(line: str) -> str:
    """A markdown table row with its outer pipes dropped. Callers split it only
    as many times as the columns need, so a ``|`` inside prose survives as-is."""
    inner = line.strip()
    if inner.startswith("|"):
        inner = inner[1:]
    if inner.endswith("|"):
        inner = inner[:-1]
    return inner


def _split_title(text: str) -> tuple[str, str]:
    """First **bold** span is the title; everything else is the body."""
    m = _BOLD.search(text)
    if not m:
        return text.strip(), ""
    body = (text[: m.start()] + text[m.end() :]).strip()
    return m.group(1).strip(), body


def _section(md: str, heading: str) -> str:
    """Text under ``### heading`` up to the next ``### `` heading."""
    m = re.search(rf"^### {re.escape(heading)}\s*$", md, re.M)
    if not m:
        return ""
    rest = md[m.end() :]
    nxt = re.search(r"^### ", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def parse_done(md: str) -> list[Item]:
    """Rows of the Done table. A summary may itself contain ``|`` (e.g.
    ``[check|fix|test|all]``), so only the first three pipes split columns."""
    items = []
    for line in _section(md, "Done").splitlines():
        if not re.match(r"\|\s*\d{4}-\d{2}-\d{2}\s*\|", line):
            continue
        c = [x.strip() for x in _inner(line).split("|", 3)]
        if len(c) < 4:
            continue
        # The whole Feature cell is the title here: it is one short line, and
        # the PR reference often sits outside the bold.
        title = re.sub(r"\s+", " ", _BOLD.sub(r"\1", c[2])).strip()
        items.append(Item(title=title, body=c[3], closed=True, date=c[0], category=c[1]))
    return items


def parse_backlog(md: str) -> list[Item]:
    """Rows of the numbered Backlog table. Row shapes vary: open rows have
    ``# | Feature | Value | Effort | Priority``, shipped rows often fold the
    value into the Feature cell, and a few have no effort/priority at all. The
    last two cells are effort/priority only when the last one looks like one."""
    items = []
    for line in _section(md, "Backlog").splitlines():
        if not re.match(r"\|\s*\d+\s*\|", line):
            continue
        number, rest = _inner(line).split("|", 1)
        number = number.strip()
        effort = priority = ""
        tail = rest.rsplit("|", 2)
        if len(tail) == 3 and _PRIORITY.match(tail[2].strip()):
            rest, effort, priority = tail[0], tail[1].strip(), tail[2].strip()
        feature, _, value = (x.strip() for x in rest.partition("|"))
        title, extra = _split_title(feature)
        body = " ".join(p for p in (extra, value) if p)
        closed = "✅" in feature
        d = _DATE.search(feature)
        items.append(
            Item(
                title=title,
                body=body,
                closed=closed,
                date=d.group(0) if d else "",
                number=number,
                priority=priority,
                effort=effort,
                tags=["partly shipped"] if "⏳" in feature else [],
            )
        )
    return items


def _inline(md: str) -> str:
    """Escape, then render the few inline markdown forms the backlog uses.
    Code spans are cut out first so ``**`` or a link inside one stays literal."""
    out = []
    for part in re.split(r"(`[^`]+`)", md):
        if len(part) > 1 and part.startswith("`") and part.endswith("`"):
            out.append(f"<code>{html.escape(part[1:-1], quote=True)}</code>")
            continue
        s = html.escape(part, quote=True)
        s = _BOLD.sub(r"<strong>\1</strong>", s)
        s = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<a href="\2">\1</a>', s)
        out.append(s)
    return "".join(out)


def _prio_rank(item: Item) -> tuple[int, int]:
    p = int(item.priority[1]) if _PRIORITY.match(item.priority) else 9
    n = int(item.number) if item.number.isdigit() else 0
    return (p, n)


def split_open_closed(items: list[Item]) -> tuple[list[Item], list[Item]]:
    """Open items by priority then number; closed items newest first (undated last)."""
    open_items = sorted((i for i in items if not i.closed), key=_prio_rank)
    closed = [i for i in items if i.closed]
    closed.sort(key=lambda i: (i.date != "", i.date), reverse=True)
    return open_items, closed


def _open_card(i: Item) -> str:
    meta = []
    if i.priority:
        meta.append(f'<span class="badge p{html.escape(i.priority[1])}">{html.escape(i.priority)}</span>')
    if i.effort:
        meta.append(f'<span class="chip">{html.escape(i.effort)}</span>')
    for t in i.tags:
        meta.append(f'<span class="chip warn">{html.escape(t)}</span>')
    num = f'<span class="num">#{html.escape(i.number)}</span>' if i.number else ""
    body = f'<p class="clamp">{_inline(i.body)}</p>' if i.body else ""
    toggle = '<button type="button" class="more" aria-expanded="false">Show more</button>' if i.body else ""
    return (
        f'<article class="card" data-search="{html.escape((i.title + " " + i.body).lower())}">'
        f'<header>{num}<h3>{_inline(i.title)}</h3><div class="meta">{"".join(meta)}</div></header>'
        f"{body}{toggle}</article>"
    )


def _closed_row(i: Item) -> str:
    kind = f"#{i.number}" if i.number else (i.category or "Done")
    date = html.escape(i.date) if i.date else "—"
    body = f'<div class="detail">{_inline(i.body)}</div>' if i.body else ""
    return (
        f'<details class="done" data-search="{html.escape((i.title + " " + i.body).lower())}">'
        f'<summary><span class="date">{date}</span><span class="chip">{html.escape(kind)}</span>'
        f'<span class="t">{_inline(i.title)}</span></summary>{body}</details>'
    )


_CSS = """
:root{--bg:#f6f8fa;--panel:#fff;--text:#1f2328;--muted:#59636e;--border:#d1d9e0;
--accent:#0969da;--p0:#cf222e;--p1:#bc4c00;--p2:#0969da;--p3:#59636e;--warn:#9a6700;--code:#eff2f5}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#0d1117;--panel:#161b22;
--text:#e6edf3;--muted:#9198a1;--border:#30363d;--accent:#4493f8;--p0:#ff7b72;--p1:#ffa657;
--p2:#79c0ff;--p3:#9198a1;--warn:#d29922;--code:#1f2630}}
:root[data-theme="dark"]{--bg:#0d1117;--panel:#161b22;--text:#e6edf3;--muted:#9198a1;--border:#30363d;
--accent:#4493f8;--p0:#ff7b72;--p1:#ffa657;--p2:#79c0ff;--p3:#9198a1;--warn:#d29922;--code:#1f2630}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px}
.sub{color:var(--muted);font-size:13px;margin:0 0 16px}
input[type=search]{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:8px;
background:var(--panel);color:var(--text);font:inherit}
.group{color:var(--muted);font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;margin:20px 0 8px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 16px;margin:0 0 10px}
.card header{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px}
.card h3{font-size:16px;margin:0;flex:1 1 300px;min-width:0;overflow-wrap:anywhere}
.num{color:var(--muted);font-variant-numeric:tabular-nums}
.meta{display:flex;gap:6px;flex-wrap:wrap}
.badge,.chip{font-size:12px;padding:1px 8px;border-radius:999px;border:1px solid var(--border);white-space:nowrap}
.badge{font-weight:700;color:var(--panel)}
.p0{background:var(--p0);border-color:var(--p0)}.p1{background:var(--p1);border-color:var(--p1)}
.p2{background:var(--p2);border-color:var(--p2)}.p3{background:var(--p3);border-color:var(--p3)}
.chip{color:var(--muted)}.chip.warn{color:var(--warn);border-color:var(--warn)}
.clamp{margin:8px 0 0;color:var(--text);overflow-wrap:anywhere;display:-webkit-box;-webkit-line-clamp:3;
-webkit-box-orient:vertical;overflow:hidden}
.card.expanded .clamp{display:block;-webkit-line-clamp:unset}
.more{margin-top:6px;background:none;border:0;padding:0;color:var(--accent);font:inherit;font-size:13px;cursor:pointer}
code{background:var(--code);border-radius:4px;padding:0 4px;font-size:.9em;overflow-wrap:anywhere}
a{color:var(--accent)}
details.closed-all{background:var(--panel);border:1px solid var(--border);border-radius:10px}
details.closed-all>summary{padding:14px 16px;font-weight:600;cursor:pointer}
.done{border-top:1px solid var(--border)}
.done>summary{display:flex;gap:10px;align-items:baseline;padding:10px 16px;cursor:pointer;list-style-position:outside}
.done .date{color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap;font-size:13px}
.done .t{flex:1;min-width:0;overflow-wrap:anywhere}
.detail{padding:0 16px 14px 16px;color:var(--muted);overflow-wrap:anywhere}
.empty{color:var(--muted)}
[hidden]{display:none!important}
@media (max-width:600px){.done>summary{flex-wrap:wrap}}
"""

_JS = """
for (const b of document.querySelectorAll('.more')) {
  b.addEventListener('click', () => {
    const card = b.closest('.card');
    const on = card.classList.toggle('expanded');
    b.textContent = on ? 'Show less' : 'Show more';
    b.setAttribute('aria-expanded', String(on));
  });
}
const q = document.getElementById('q');
const closedAll = document.getElementById('closed');
q.addEventListener('input', () => {
  const term = q.value.trim().toLowerCase();
  let closedHits = 0;
  for (const el of document.querySelectorAll('[data-search]')) {
    const hit = !term || el.dataset.search.includes(term);
    el.hidden = !hit;
    if (hit && el.classList.contains('done')) closedHits++;
  }
  for (const g of document.querySelectorAll('.grp')) {
    g.hidden = !g.querySelector('.card:not([hidden])');
  }
  // Searching should find closed items too, so open the section on a match.
  if (term && closedHits) closedAll.open = true;
  document.getElementById('closed-count').textContent = term ? closedHits + ' matching' : closedAll.dataset.total;
});
"""


def render(open_items: list[Item], closed: list[Item], generated: str, source: str) -> str:
    groups: dict[str, list[Item]] = {}
    for i in open_items:
        key = i.priority[:2] if _PRIORITY.match(i.priority) else "Unprioritised"
        groups.setdefault(key, []).append(i)
    labels = {"P0": "P0 · do next", "P1": "P1 · high value", "P2": "P2 · nice to have", "P3": "P3 · future"}
    open_html = (
        "".join(
            f'<section class="grp"><div class="group">{html.escape(labels.get(k, k))}</div>'
            + "".join(_open_card(i) for i in items)
            + "</section>"
            for k, items in groups.items()
        )
        or '<p class="empty">Nothing open.</p>'
    )
    closed_html = "".join(_closed_row(i) for i in closed)
    total = f"{len(closed)} items"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WinDesktopMgr Backlog</title>
<style>{_CSS}</style></head>
<body><main>
<h1>WinDesktopMgr backlog</h1>
<p class="sub">{len(open_items)} open · {len(closed)} closed · generated {html.escape(generated)} from
<code>{html.escape(source)}</code></p>
<input id="q" type="search" placeholder="Filter open and closed items…" aria-label="Filter items">
<h2>Open</h2>
{open_html}
<h2>Closed</h2>
<details class="closed-all" id="closed" data-total="{total}">
<summary>Show all done items (<span id="closed-count">{total}</span>), newest first</summary>
{closed_html}
</details>
</main><script>{_JS}</script></body></html>
"""


def build(md: str, source: str, now: datetime | None = None) -> str:
    items = parse_backlog(md) + parse_done(md)
    open_items, closed = split_open_closed(items)
    stamp = (now or datetime.now()).strftime("%Y-%m-%d %H:%M")
    return render(open_items, closed, stamp, source)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--backlog", default=BACKLOG_PATH, help="path to project_backlog.md")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="where to write the HTML page")
    args = ap.parse_args(argv)
    try:
        md = Path(args.backlog).read_text(encoding="utf-8")
    except OSError as e:
        print(f"backlog_html: cannot read {args.backlog}: {e}", file=sys.stderr)
        return 1
    Path(args.out).write_text(build(md, args.backlog), encoding="utf-8")
    print(f"backlog_html: wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
