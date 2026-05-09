"""
report.py -- On-demand system health report generator (backlog #15).

Renders the same data the dashboard surfaces (concerns, hardware,
recent BSODs, drivers, etc.) as a shareable document. Three output
formats:

* **markdown** -- best for GitHub issues, support tickets, internal docs.
  Plain text, no styling, copy-pastes cleanly into chat / email.
* **html**     -- styled standalone document. Same structure as the
  Markdown but with CSS so it reads nicely in a browser tab.
* **json**     -- full machine-readable dump. For piping into other
  tools or pretty-printing as a record.

PII redaction (``redact_pii=True``, default ON) replaces IPs, MACs,
hostnames, and BIOS service tags with stable placeholders. The cost
of accidentally pasting a service tag into a public support post is
real; the cost of toggling OFF for a personal record is one click.

The module reuses the existing summarizers + ``_compute_dashboard_summary``
fan-out so the report content stays in lockstep with what the dashboard
shows -- if the dashboard surfaces a concern, the report shows it too.
"""

from __future__ import annotations

import html as _html
import json as _json
import re
from datetime import datetime, timezone

# ── PII redaction patterns ──────────────────────────────────────────────────
# Each pattern is (regex, replacement). Order matters: more-specific
# patterns first so they match before general fallbacks.
#
# Conservatism: false positives (over-redacting) are MUCH safer than
# false negatives (leaking PII). When in doubt, redact. The user can
# always toggle redact_pii=False if they want the unredacted version.
_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    # MAC addresses -- XX:XX:XX:XX:XX:XX or XX-XX-... (case-insensitive hex)
    (re.compile(r"\b[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}\b"), "[redacted-mac]"),
    # IPv4 -- 1-3 digit octets separated by dots. 0.0.0.0 / 127.0.0.1 stay
    # readable because they're never PII (placeholder + loopback).
    (re.compile(r"\b(?!0\.0\.0\.0\b)(?!127\.0\.0\.1\b)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "[redacted-ip]"),
    # IPv6 -- two patterns to cover both common forms without
    # false-positiving on unrelated colon-separated text:
    #   (a) :: zero-compression form: fe80::7a67:..., 2600:4041::1, ::1
    #   (b) full 8-group form: aaaa:bbbb:cccc:dddd:eeee:ffff:gggg:hhhh
    # The MAC pattern above (exactly 6 groups of 2 hex chars) is
    # checked first so it doesn't collide with the full-form IPv6.
    (re.compile(r"\b[0-9a-fA-F]{0,4}::[0-9a-fA-F:]{0,39}[0-9a-fA-F]"), "[redacted-ipv6]"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){5,7}[0-9a-fA-F]{1,4}\b"), "[redacted-ipv6]"),
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[redacted-email]"),
]


def _redact_pii(text: str, hostname: str = "", service_tag: str = "") -> str:
    """Run the PII pattern set + machine-specific identifiers over ``text``.

    ``hostname`` and ``service_tag`` are passed in by the caller from
    BIOS / OS data so we can redact them as exact-match strings even
    when they don't fit the generic regex patterns (a hostname could
    be any alphanumeric string).
    """
    if not text:
        return text
    out = text
    for pattern, replacement in _PII_PATTERNS:
        out = pattern.sub(replacement, out)
    # Exact-match redactions for machine-specific identifiers. Skip
    # empty / 1-char strings because they'd over-match (e.g. a 1-char
    # hostname would replace every occurrence of that letter).
    if hostname and len(hostname) >= 3:
        out = re.sub(re.escape(hostname), "[redacted-hostname]", out, flags=re.IGNORECASE)
    if service_tag and len(service_tag) >= 5:
        out = re.sub(re.escape(service_tag), "[redacted-servicetag]", out)
    return out


# ── Report data assembly ────────────────────────────────────────────────────


def _collect_report_data(scope: str = "full") -> dict:
    """Gather raw data for the report from the same sources the dashboard uses.

    Returns a structured dict the formatters render. Each top-level key
    is a section the report can include / omit based on ``scope``:

        scope="full"      -> every section
        scope="dashboard" -> just overall + concerns (smallest)
        scope="bsod"      -> just the BSOD section (for crash-focused tickets)
        scope="hardware"  -> just CPU/RAM/GPU/disk sections (for upgrade questions)
        scope="network"   -> just NIC/topology sections (for connectivity questions)

    All collectors are wrapped in try/except so a single broken probe
    doesn't kill the whole report; the section's ``error`` field
    surfaces the failure to the formatter instead.
    """
    # Lazy import so report.py can be imported standalone without the
    # heavy windesktopmgr.* surface (useful for unit-testing the
    # formatters without booting Flask).
    from windesktopmgr import _compute_dashboard_summary, get_bios_status, get_bsod_events

    out: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": scope,
        "tool": "WinDesktopMgr",
    }

    # Dashboard summary -- gives us overall status + concerns + most
    # of the per-area data in one fan-out call.
    if scope in ("full", "dashboard", "hardware", "network"):
        try:
            summary = _compute_dashboard_summary()
        except Exception as e:
            summary = {"error": str(e), "concerns": [], "overall": "unknown"}
        out["summary"] = summary

    # BIOS / hardware identifiers -- needed for both the hardware
    # section AND the hostname/service-tag-redaction passes.
    if scope in ("full", "hardware"):
        try:
            out["bios"] = get_bios_status()
        except Exception as e:
            out["bios"] = {"error": str(e)}

    # BSOD crashes
    if scope in ("full", "bsod"):
        try:
            crashes = get_bsod_events()
        except Exception as e:
            crashes = []
            out["_bsod_error"] = str(e)
        out["bsod"] = crashes[:25]  # cap so a system with hundreds doesn't bloat the report

    return out


# ── Renderers ───────────────────────────────────────────────────────────────


def _section_concerns(summary: dict) -> list:
    """Pull concerns out of dashboard summary, sorted by severity."""
    concerns = summary.get("concerns", []) or []
    # Order: critical -> warning -> info -> ok
    sev_rank = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    return sorted(concerns, key=lambda c: sev_rank.get(c.get("level", "info"), 99))


def render_markdown(data: dict) -> str:
    """Render the report as a Markdown document."""
    lines: list[str] = []
    lines.append("# WinDesktopMgr System Health Report")
    lines.append("")
    lines.append(f"**Generated:** {data.get('generated_at', '?')}")
    lines.append(f"**Scope:** {data.get('scope', 'full')}")
    lines.append("")

    summary = data.get("summary", {})
    overall = summary.get("overall", "unknown")
    concerns = _section_concerns(summary)
    by_level: dict = {}
    for c in concerns:
        lvl = c.get("level", "info")
        by_level[lvl] = by_level.get(lvl, 0) + 1

    lines.append("## Overall Status")
    lines.append("")
    lines.append(f"**Status:** `{overall.upper()}`")
    if by_level:
        breakdown = ", ".join(f"{n} {lvl}" for lvl, n in sorted(by_level.items()))
        lines.append(f"**Concerns:** {breakdown}")
    else:
        lines.append("**Concerns:** none")
    lines.append("")

    if concerns:
        lines.append("## Active Concerns")
        lines.append("")
        for c in concerns:
            lvl = c.get("level", "info").upper()
            icon = c.get("icon", "")
            title = c.get("title", "(no title)")
            detail = c.get("detail", "")
            tab = c.get("tab", "")
            lines.append(f"### [{lvl}] {icon} {title}".rstrip())
            if detail:
                lines.append("")
                lines.append(detail)
            if tab:
                lines.append("")
                lines.append(f"_Tab:_ `{tab}`")
            lines.append("")

    bios = data.get("bios", {})
    if bios and not bios.get("error"):
        lines.append("## System / BIOS")
        lines.append("")
        for k in ("manufacturer", "product", "bios_version", "bios_date", "secure_boot", "tpm_present"):
            v = bios.get(k)
            if v not in (None, "", "Unknown"):
                lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")
        lines.append("")

    bsod = data.get("bsod") or []
    if bsod:
        lines.append(f"## Recent BSODs ({len(bsod)})")
        lines.append("")
        for crash in bsod[:10]:
            ts = crash.get("Timestamp", crash.get("timestamp", "?"))
            code = crash.get("BugCheckCode", crash.get("bug_check_code", "?"))
            module = crash.get("FaultingModule", crash.get("faulting_module", ""))
            lines.append(f"- `{ts}` -- {code} {('(' + module + ')') if module else ''}".rstrip())
        if len(bsod) > 10:
            lines.append(f"- _… and {len(bsod) - 10} more_")
        lines.append("")

    lines.append("---")
    lines.append("_Generated by WinDesktopMgr (https://github.com/shigsdev/windesktopmgr)._")
    return "\n".join(lines)


def render_html(data: dict) -> str:
    """Render the report as a standalone HTML document with light styling."""
    md_body = render_markdown(data)
    # Cheap markdown -> HTML: only support headings / bold / lists / hr /
    # backticks. Good enough for this report shape; avoids pulling in
    # markdown / mistune as a runtime dep.
    body_html_lines: list[str] = []
    in_list = False
    for raw in md_body.splitlines():
        line = raw.rstrip()
        # Headings
        if line.startswith("### "):
            if in_list:
                body_html_lines.append("</ul>")
                in_list = False
            body_html_lines.append(f"<h3>{_html.escape(line[4:])}</h3>")
            continue
        if line.startswith("## "):
            if in_list:
                body_html_lines.append("</ul>")
                in_list = False
            body_html_lines.append(f"<h2>{_html.escape(line[3:])}</h2>")
            continue
        if line.startswith("# "):
            if in_list:
                body_html_lines.append("</ul>")
                in_list = False
            body_html_lines.append(f"<h1>{_html.escape(line[2:])}</h1>")
            continue
        # Horizontal rule
        if line == "---":
            if in_list:
                body_html_lines.append("</ul>")
                in_list = False
            body_html_lines.append("<hr/>")
            continue
        # Bullet
        if line.startswith("- "):
            if not in_list:
                body_html_lines.append("<ul>")
                in_list = True
            body_html_lines.append(f"<li>{_inline_md_to_html(line[2:])}</li>")
            continue
        # Blank line ends a list
        if not line:
            if in_list:
                body_html_lines.append("</ul>")
                in_list = False
            body_html_lines.append("")
            continue
        # Regular paragraph
        if in_list:
            body_html_lines.append("</ul>")
            in_list = False
        body_html_lines.append(f"<p>{_inline_md_to_html(line)}</p>")
    if in_list:
        body_html_lines.append("</ul>")
    body = "\n".join(body_html_lines)

    # Light styling so the document reads cleanly in a browser tab
    # without depending on the dashboard's CSS (which isn't loaded
    # when the user opens the export in a fresh tab).
    css = """
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
               max-width: 760px; margin: 2em auto; padding: 0 1em; line-height: 1.5; color: #1a202c; }
        h1 { border-bottom: 2px solid #00d4ff; padding-bottom: .3em; }
        h2 { color: #2c5282; border-bottom: 1px solid #e2e8f0; padding-bottom: .2em; margin-top: 1.5em; }
        h3 { color: #4a5568; margin-top: 1em; }
        code { background: #edf2f7; padding: 0 .25em; border-radius: 3px; font-size: .9em; }
        ul { padding-left: 1.5em; } li { margin: .25em 0; }
        hr { border: none; border-top: 1px solid #e2e8f0; margin: 2em 0; }
    """
    return (
        "<!DOCTYPE html>\n"
        "<html><head>\n"
        "<meta charset='utf-8'/>\n"
        "<title>WinDesktopMgr Health Report</title>\n"
        f"<style>{css}</style>\n"
        "</head>\n<body>\n"
        f"{body}\n"
        "</body></html>\n"
    )


def _inline_md_to_html(text: str) -> str:
    """Convert inline markdown (bold + backticks) to HTML, escaping the rest."""
    # Escape first, then re-introduce the formatting markers (which are
    # safe by construction since we control the patterns).
    escaped = _html.escape(text)
    # **bold**
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    # `code`
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    # _italic_ -- only when bordered by spaces or punctuation, to avoid
    # mangling things like snake_case identifiers.
    escaped = re.sub(r"(?:(?<=^)|(?<=[\s(]))_([^_\n]+)_(?=[\s.,;:)]|$)", r"<em>\1</em>", escaped)
    return escaped


def render_json(data: dict) -> str:
    """Render the full data dict as pretty-printed JSON."""
    return _json.dumps(data, indent=2, default=str, sort_keys=True)


# ── Public entry point ──────────────────────────────────────────────────────


def generate_report(scope: str = "full", fmt: str = "markdown", redact_pii: bool = True) -> tuple[str, str]:
    """Build a system health report.

    Args:
        scope: "full" | "dashboard" | "bsod" | "hardware" | "network"
            Sections to include. "full" is the default.
        fmt: "markdown" | "html" | "json".
        redact_pii: When True (default), replace MAC / IP / hostname /
            service-tag in the rendered text. When False, leave the raw
            values in -- only set False if the report stays on your own
            machine.

    Returns:
        ``(content, mime_type)`` -- the rendered report text and the
        MIME type the route should serve it with.
    """
    if fmt not in ("markdown", "html", "json"):
        raise ValueError(f"Unknown report format: {fmt!r}. Use 'markdown', 'html', or 'json'.")
    if scope not in ("full", "dashboard", "bsod", "hardware", "network"):
        raise ValueError(f"Unknown report scope: {scope!r}.")

    data = _collect_report_data(scope=scope)

    # Pull machine identifiers up so they can be passed to the redactor
    # for exact-match (not just regex-match) replacement.
    bios = data.get("bios") or {}
    summary = data.get("summary") or {}
    hostname = (bios.get("hostname") or summary.get("hostname") or "").strip()
    service_tag = (bios.get("serial_number") or "").strip()

    if fmt == "json":
        content = render_json(data)
    elif fmt == "html":
        content = render_html(data)
    else:
        content = render_markdown(data)

    if redact_pii:
        content = _redact_pii(content, hostname=hostname, service_tag=service_tag)

    mime = {
        "markdown": "text/markdown; charset=utf-8",
        "html": "text/html; charset=utf-8",
        "json": "application/json",
    }[fmt]
    return content, mime
