"""
nlq.py — Natural Language Query feature for WinDesktopMgr.

Claude-powered system diagnostics chat: 19 tool definitions, the agentic
tool-use loop, the ``_truncate_for_context`` helper, and the single
``/api/nlq/ask`` route.

The Python functions that back each tool live in ``windesktopmgr.py``
(and its sibling blueprints ``homenet.py`` / ``remediation.py``). Those
are captured into a dispatch dict by the main module and handed to this
blueprint via ``register_tool_dispatch`` at startup — that keeps the
lambdas' name resolution inside the ``windesktopmgr`` namespace so
existing tests that patch ``windesktopmgr.get_thermals`` etc. keep
working unchanged.

Extracted from windesktopmgr.py as the third and final blueprint
extraction planned for backlog #22 (disk → remediation → nlq), following
the disk.py / remediation.py playbook: zero behaviour changes, all tests
still pass, routes now served by ``nlq_bp``.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from flask import Blueprint, jsonify, request

try:
    import anthropic
except ImportError:
    anthropic = None  # NLQ feature unavailable without the SDK

nlq_bp = Blueprint("nlq", __name__)


# ── Tool registry (populated by windesktopmgr at import time) ─────────────────

_NLQ_DISPATCH: dict = {}


def register_tool_dispatch(dispatch: dict) -> None:
    """Wire the Python functions that back each Claude tool into this module.

    Called once from ``windesktopmgr.py`` after all the data-gathering
    functions have been defined. The dict is shared by reference so any
    later mutation inside ``windesktopmgr`` stays visible here.
    """
    _NLQ_DISPATCH.clear()
    _NLQ_DISPATCH.update(dispatch)


# ── Claude API tool definitions — each maps to an existing data function ─────

_NLQ_TOOLS = [
    {
        "name": "get_dashboard_summary",
        "description": (
            "Get a quick overview of the system's health status. Returns active concerns "
            "(critical/warning) across thermals, memory, BIOS, credentials, and NAS drives. "
            "Use this first for general health questions."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "query_event_log",
        "description": (
            "Search the Windows Event Log. Can filter by log name (System, Application, Security), "
            "severity level (Error, Warning, Information), and free-text search term. "
            "Returns up to 200 events with timestamp, ID, level, source, and message."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "log": {
                    "type": "string",
                    "enum": ["System", "Application", "Security"],
                    "description": "Which event log to query",
                },
                "level": {
                    "type": "string",
                    "enum": ["Error", "Warning", "Information"],
                    "description": "Minimum severity level",
                },
                "search": {"type": "string", "description": "Free-text filter for event messages"},
                "max": {"type": "integer", "description": "Max events to return (default 50, max 200)"},
            },
            "required": [],
        },
    },
    {
        "name": "get_bsod_analysis",
        "description": (
            "Get full BSOD (Blue Screen of Death) crash analysis. Returns crash history, "
            "timeline, error codes, faulty drivers, uptime periods, and recommendations. "
            "Use for any crash-related questions."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_disk_health",
        "description": (
            "Get disk drive health data: space usage per drive, physical disk status "
            "(SSD/HDD health, temperature, wear), and I/O performance counters."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_network_data",
        "description": (
            "Get network information: active TCP connections (established/listening), "
            "network adapter statistics, and top processes by connection count."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_update_history",
        "description": (
            "Get Windows Update installation history: title, date, result (success/fail), "
            "KB number. Use for questions about updates, patches, or what changed recently."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_startup_items",
        "description": (
            "Get all startup programs: name, command, location (registry/startup folder/scheduled task), "
            "whether enabled, and whether the item looks suspicious. Use for boot time questions."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_process_list",
        "description": (
            "Get running processes with CPU/memory usage, descriptions, and flagged concerns. "
            "Use for questions about what's running, high CPU/memory usage, or suspicious processes."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_thermals",
        "description": (
            "Get temperature readings, CPU utilization percentage, RAM utilization, and fan speeds. "
            "Use for questions about heat, cooling, performance, or system load."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_services_list",
        "description": (
            "Get all Windows services: name, display name, status (Running/Stopped), start mode "
            "(Auto/Manual/Disabled), and process ID. Use for service-related questions."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_health_report_history",
        "description": (
            "Get history of daily health reports: date, health score (0-100), BSOD count, "
            "WHEA errors, driver errors. Use for trend questions like 'is my system getting worse?'"
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_system_timeline",
        "description": (
            "Get a unified timeline of system events: BSODs, Windows Updates, service changes, "
            "reboots, and security events. Use for questions about what happened on a specific day "
            "or what caused a problem."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "days": {"type": "integer", "description": "How many days of history (default 30, max 90)"},
            },
            "required": [],
        },
    },
    {
        "name": "get_memory_analysis",
        "description": (
            "Get detailed memory/RAM analysis: total/used/free, per-process breakdown, "
            "categorized usage (browser, security, system, comms), McAfee vs Defender comparison."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_bios_status",
        "description": (
            "Get current BIOS version and whether an update is available from Dell. "
            "Includes current version, latest version, download URL, and release date."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_credentials_network_health",
        "description": (
            "Get credentials and network health: stored credentials, mapped NAS drives "
            "(and which are unreachable), OneDrive status, Microsoft auth token status, "
            "SMB signing, Fast Startup status, firewall rules, and credential failures."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "navigate_to_tab",
        "description": (
            "Navigate the user to a specific tab in the UI. Use this when the user asks to "
            "'show me' something that lives on a specific tab."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "tab": {
                    "type": "string",
                    "enum": [
                        "dashboard",
                        "drivers",
                        "bsod",
                        "startup",
                        "disk",
                        "network",
                        "updates",
                        "events",
                        "processes",
                        "thermals",
                        "services",
                        "health-history",
                        "timeline",
                        "memory",
                        "bios",
                        "credentials",
                        "sysinfo",
                        "remediation",
                    ],
                    "description": "Which tab to navigate to",
                },
            },
            "required": ["tab"],
        },
    },
    {
        "name": "get_remediation_history",
        "description": (
            "Get the log of all remediation actions that have been run: action name, "
            "risk level, timestamp, success/failure, and message. Use for questions like "
            "'what fixes have I run?' or 'did the DNS flush work?'"
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "run_remediation_action",
        "description": (
            "Execute a remediation action on the system. Only use when the user explicitly "
            "asks to run or apply a fix. Valid action_ids: flush_dns, reset_winsock, "
            "reset_tcpip, clear_temp, repair_image, clear_wu_cache, restart_spooler, "
            "reset_network_adapter, clear_icon_cache, reboot_system."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action_id": {
                    "type": "string",
                    "enum": [
                        "flush_dns",
                        "reset_winsock",
                        "reset_tcpip",
                        "clear_temp",
                        "repair_image",
                        "clear_wu_cache",
                        "restart_spooler",
                        "reset_network_adapter",
                        "clear_icon_cache",
                        "reboot_system",
                    ],
                    "description": "Which remediation action to run",
                }
            },
            "required": ["action_id"],
        },
    },
    {
        "name": "get_homenet_inventory",
        "description": (
            "Get the home network device inventory. Returns all discovered devices across "
            "both the wired (192.x) and wireless (10.x) networks, including device names, "
            "IPs, MACs, vendors, categories, and online status. Use for questions about "
            "network devices, what's connected, or home network status."
        ),
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _truncate_for_context(data, max_items=50):
    """Truncate large lists to keep Claude API context reasonable."""
    if isinstance(data, list) and len(data) > max_items:
        return data[:max_items] + [{"_truncated": f"... and {len(data) - max_items} more items"}]
    if isinstance(data, dict):
        return {k: _truncate_for_context(v, max_items) for k, v in data.items()}
    return data


# ── Route ─────────────────────────────────────────────────────────────────────


@nlq_bp.route("/api/nlq/ask", methods=["POST"])
def nlq_ask():
    """
    Natural Language Query endpoint.
    Accepts {"question": "..."} and returns Claude's analysis using tool use.
    """
    body = request.get_json() or {}
    question = body.get("question", "").strip()
    if not question:
        return jsonify({"error": "No question provided"}), 400

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return jsonify({"error": "ANTHROPIC_API_KEY not set. Add it to your environment variables."}), 500

    if anthropic is None:
        return jsonify({"error": "anthropic package not installed. Run: pip install anthropic"}), 500

    client = anthropic.Anthropic(api_key=api_key)

    system_prompt = (
        "You are a helpful Windows system diagnostics assistant embedded in WinDesktopMgr, "
        "a desktop health monitoring tool. The user is asking about THEIR specific Windows PC.\n\n"
        "You have tools to query real-time system data. Use them to answer the user's question "
        "with specific, actionable information from their actual system.\n\n"
        "Guidelines:\n"
        "- Call the most relevant tool(s) to gather data before answering\n"
        "- Be concise but thorough — the user sees this in a small chat panel\n"
        "- Use specific numbers, names, and dates from the data\n"
        "- If something looks concerning, say so clearly with a recommended action\n"
        "- Use the navigate_to_tab tool when the user would benefit from seeing a specific tab\n"
        "- Format with markdown: **bold** for emphasis, bullet lists for multiple items\n"
        "- Keep responses under 300 words unless the question requires detail\n"
        "- Today's date: " + datetime.now().strftime("%Y-%m-%d %H:%M")
    )

    messages = [{"role": "user", "content": question}]
    nav_tabs = []  # Track any tab navigations requested

    # Agentic tool-use loop — let Claude call tools until it produces a final answer
    max_rounds = 5
    for _round in range(max_rounds):
        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                system=system_prompt,
                tools=_NLQ_TOOLS,
                messages=messages,
            )
        except anthropic.APIError as e:
            return jsonify({"error": f"Claude API error: {e}"}), 502

        # Check if Claude wants to use tools
        if response.stop_reason == "tool_use":
            # Process all tool calls in this response
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    tool_name = block.name
                    tool_input = block.input or {}
                    dispatch_fn = _NLQ_DISPATCH.get(tool_name)

                    if dispatch_fn:
                        try:
                            result = dispatch_fn(tool_input)
                            # Track tab navigations
                            if tool_name == "navigate_to_tab":
                                nav_tabs.append(tool_input.get("tab", "dashboard"))
                            result_json = json.dumps(_truncate_for_context(result), default=str)
                        except Exception as e:
                            result_json = json.dumps({"error": str(e)})
                    else:
                        result_json = json.dumps({"error": f"Unknown tool: {tool_name}"})

                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result_json,
                        }
                    )

            # Add assistant response + tool results to conversation
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
        else:
            # Claude produced a final text response
            answer_parts = []
            for block in response.content:
                if hasattr(block, "text"):
                    answer_parts.append(block.text)

            return jsonify(
                {
                    "answer": "\n".join(answer_parts),
                    "navigate_to": nav_tabs[-1] if nav_tabs else None,
                }
            )

    # If we exhausted rounds, return whatever we have
    return jsonify(
        {
            "answer": "I gathered the data but couldn't finish the analysis. Please try a simpler question.",
            "navigate_to": nav_tabs[-1] if nav_tabs else None,
        }
    )
