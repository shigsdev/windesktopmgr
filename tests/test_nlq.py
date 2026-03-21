"""
Tests for the Natural Language Query (NLQ) feature.

Tests cover:
- Route validation (missing question, missing API key)
- Tool dispatch mapping
- Truncation helper
- Full agentic loop with mocked Claude API
- Tab navigation via tool use
- Error handling (API errors, tool failures)
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import windesktopmgr as wdm


class TestNlqRoute(unittest.TestCase):
    """Test the /api/nlq/ask endpoint."""

    def setUp(self):
        wdm.app.config["TESTING"] = True
        self.client = wdm.app.test_client()

    def test_missing_question_returns_400(self):
        resp = self.client.post("/api/nlq/ask", json={})
        assert resp.status_code == 400
        assert "No question" in resp.get_json()["error"]

    def test_empty_question_returns_400(self):
        resp = self.client.post("/api/nlq/ask", json={"question": "   "})
        assert resp.status_code == 400

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False)
    def test_missing_api_key_returns_500(self):
        resp = self.client.post("/api/nlq/ask", json={"question": "test"})
        assert resp.status_code == 500
        assert "ANTHROPIC_API_KEY" in resp.get_json()["error"]


class TestNlqToolDispatch(unittest.TestCase):
    """Verify all tool names map to callable dispatch functions."""

    def test_all_tools_have_dispatch(self):
        for tool in wdm._NLQ_TOOLS:
            name = tool["name"]
            assert name in wdm._NLQ_DISPATCH, f"Tool '{name}' missing from _NLQ_DISPATCH"

    def test_dispatch_functions_are_callable(self):
        for name, fn in wdm._NLQ_DISPATCH.items():
            assert callable(fn), f"Dispatch '{name}' is not callable"

    def test_navigate_to_tab_returns_dict(self):
        result = wdm._NLQ_DISPATCH["navigate_to_tab"]({"tab": "bsod"})
        assert result == {"navigated": True, "tab": "bsod"}

    def test_navigate_to_tab_default(self):
        result = wdm._NLQ_DISPATCH["navigate_to_tab"]({})
        assert result["tab"] == "dashboard"


class TestNlqTruncation(unittest.TestCase):
    """Test the _truncate_for_context helper."""

    def test_short_list_unchanged(self):
        data = [1, 2, 3]
        assert wdm._truncate_for_context(data) == [1, 2, 3]

    def test_long_list_truncated(self):
        data = list(range(100))
        result = wdm._truncate_for_context(data, max_items=10)
        assert len(result) == 11  # 10 items + 1 truncation notice
        assert result[-1]["_truncated"] == "... and 90 more items"

    def test_dict_recursion(self):
        data = {"events": list(range(60)), "name": "test"}
        result = wdm._truncate_for_context(data, max_items=20)
        assert len(result["events"]) == 21
        assert result["name"] == "test"

    def test_scalar_passthrough(self):
        assert wdm._truncate_for_context("hello") == "hello"
        assert wdm._truncate_for_context(42) == 42
        assert wdm._truncate_for_context(None) is None


class TestNlqToolDefinitions(unittest.TestCase):
    """Verify tool definitions are well-formed for the Claude API."""

    def test_all_tools_have_required_fields(self):
        for tool in wdm._NLQ_TOOLS:
            assert "name" in tool, f"Tool missing 'name': {tool}"
            assert "description" in tool, f"Tool '{tool['name']}' missing description"
            assert "input_schema" in tool, f"Tool '{tool['name']}' missing input_schema"

    def test_tool_schemas_are_valid(self):
        for tool in wdm._NLQ_TOOLS:
            schema = tool["input_schema"]
            assert schema["type"] == "object", f"Tool '{tool['name']}' schema type must be 'object'"
            assert "properties" in schema

    def test_query_event_log_has_params(self):
        tool = next(t for t in wdm._NLQ_TOOLS if t["name"] == "query_event_log")
        props = tool["input_schema"]["properties"]
        assert "log" in props
        assert "level" in props
        assert "search" in props

    def test_navigate_to_tab_has_enum(self):
        tool = next(t for t in wdm._NLQ_TOOLS if t["name"] == "navigate_to_tab")
        tab_enum = tool["input_schema"]["properties"]["tab"]["enum"]
        assert "dashboard" in tab_enum
        assert "bsod" in tab_enum
        assert "credentials" in tab_enum


class TestNlqFullLoop(unittest.TestCase):
    """Test the full NLQ agentic loop with mocked Claude API."""

    def setUp(self):
        wdm.app.config["TESTING"] = True
        self.client = wdm.app.test_client()

    def _mock_text_response(self, text):
        """Create a mock Claude response with just text (no tool use)."""
        block = MagicMock()
        block.type = "text"
        block.text = text
        resp = MagicMock()
        resp.stop_reason = "end_turn"
        resp.content = [block]
        return resp

    def _mock_tool_use_response(self, tool_name, tool_input, tool_id="call_123"):
        """Create a mock Claude response that calls a tool."""
        block = MagicMock()
        block.type = "tool_use"
        block.name = tool_name
        block.input = tool_input
        block.id = tool_id
        resp = MagicMock()
        resp.stop_reason = "tool_use"
        resp.content = [block]
        return resp

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("windesktopmgr.anthropic")
    def test_simple_text_response(self, mock_anthropic_mod):
        """Claude answers directly without calling tools."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_client.messages.create.return_value = self._mock_text_response("Your system looks healthy!")

        resp = self.client.post("/api/nlq/ask", json={"question": "How is my system?"})
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["answer"] == "Your system looks healthy!"
        assert data["navigate_to"] is None

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("windesktopmgr.anthropic")
    @patch("windesktopmgr.get_thermals")
    def test_tool_use_then_response(self, mock_thermals, mock_anthropic_mod):
        """Claude calls a tool, gets data, then responds."""
        mock_thermals.return_value = {
            "temps": [{"Name": "CPU", "TempC": 65, "status": "ok"}],
            "perf": {"CPUPct": 35, "RAMPct": 60},
        }

        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception

        # First call: Claude wants to use get_thermals tool
        # Second call: Claude responds with text
        mock_client.messages.create.side_effect = [
            self._mock_tool_use_response("get_thermals", {}),
            self._mock_text_response("CPU is at 65C, looking good."),
        ]

        resp = self.client.post("/api/nlq/ask", json={"question": "What are my temps?"})
        data = resp.get_json()
        assert resp.status_code == 200
        assert "65" in data["answer"]
        assert mock_thermals.called

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("windesktopmgr.anthropic")
    def test_navigate_to_tab(self, mock_anthropic_mod):
        """Claude navigates to a specific tab."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception

        mock_client.messages.create.side_effect = [
            self._mock_tool_use_response("navigate_to_tab", {"tab": "bsod"}),
            self._mock_text_response("Here's your BSOD data."),
        ]

        resp = self.client.post("/api/nlq/ask", json={"question": "Show me crashes"})
        data = resp.get_json()
        assert data["navigate_to"] == "bsod"

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("windesktopmgr.anthropic")
    def test_api_error_returns_502(self, mock_anthropic_mod):
        """Claude API error returns 502."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client

        api_error = Exception("rate limited")
        mock_anthropic_mod.APIError = type(api_error)
        mock_client.messages.create.side_effect = api_error

        resp = self.client.post("/api/nlq/ask", json={"question": "test"})
        assert resp.status_code == 502

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("windesktopmgr.anthropic")
    @patch("windesktopmgr.get_disk_health")
    def test_tool_failure_handled(self, mock_disk, mock_anthropic_mod):
        """Tool execution error is passed back to Claude gracefully."""
        mock_disk.side_effect = RuntimeError("PowerShell timeout")

        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception

        mock_client.messages.create.side_effect = [
            self._mock_tool_use_response("get_disk_health", {}),
            self._mock_text_response("I couldn't retrieve disk data."),
        ]

        resp = self.client.post("/api/nlq/ask", json={"question": "Check disk"})
        data = resp.get_json()
        assert resp.status_code == 200
        # Claude should have received the error and responded gracefully
        assert "couldn't" in data["answer"].lower()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("windesktopmgr.anthropic")
    @patch("windesktopmgr.query_event_log")
    def test_event_log_tool_passes_params(self, mock_events, mock_anthropic_mod):
        """query_event_log tool passes filter parameters correctly."""
        mock_events.return_value = [
            {"Time": "2026-03-15", "Id": 7036, "Level": "Error", "Source": "SCM", "Message": "stopped"}
        ]

        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception

        mock_client.messages.create.side_effect = [
            self._mock_tool_use_response("query_event_log", {"log": "System", "level": "Error", "max": 10}),
            self._mock_text_response("Found 1 error."),
        ]

        resp = self.client.post("/api/nlq/ask", json={"question": "errors"})
        assert resp.status_code == 200
        mock_events.assert_called_once_with({"log": "System", "level": "Error", "max": 10})

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("windesktopmgr.anthropic")
    def test_max_rounds_exhausted(self, mock_anthropic_mod):
        """If Claude keeps calling tools forever, we stop after max_rounds."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception

        # Every response is a tool_use — never a final text
        mock_client.messages.create.return_value = self._mock_tool_use_response("navigate_to_tab", {"tab": "dashboard"})

        resp = self.client.post("/api/nlq/ask", json={"question": "infinite loop test"})
        data = resp.get_json()
        assert resp.status_code == 200
        assert "couldn't finish" in data["answer"].lower()


class TestNlqDashboardSummary(unittest.TestCase):
    """Test the _nlq_dashboard_summary helper."""

    @patch("windesktopmgr.get_thermals")
    @patch("windesktopmgr.get_memory_analysis")
    @patch("windesktopmgr.get_bios_status")
    @patch("windesktopmgr.get_credentials_network_health")
    def test_returns_raw_and_summaries(self, mock_cred, mock_bios, mock_mem, mock_therm):
        mock_therm.return_value = {"temps": [], "perf": {"CPUPct": 20, "RAMPct": 40}}
        mock_mem.return_value = {"total_mb": 32000, "used_mb": 16000}
        mock_bios.return_value = {"current": {"version": "2.22.0"}, "update": {}}
        mock_cred.return_value = {"drives_down": [], "onedrive_suspended": False}

        result = wdm._nlq_dashboard_summary()
        assert "raw_data" in result
        assert "summaries" in result
        assert "thermals" in result["raw_data"]
        assert "memory" in result["summaries"]


if __name__ == "__main__":
    unittest.main()
