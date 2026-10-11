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

import nlq
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
        for tool in nlq._NLQ_TOOLS:
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
        assert nlq._truncate_for_context(data) == [1, 2, 3]

    def test_long_list_truncated(self):
        data = list(range(100))
        result = nlq._truncate_for_context(data, max_items=10)
        assert len(result) == 11  # 10 items + 1 truncation notice
        assert result[-1]["_truncated"] == "... and 90 more items"

    def test_dict_recursion(self):
        data = {"events": list(range(60)), "name": "test"}
        result = nlq._truncate_for_context(data, max_items=20)
        assert len(result["events"]) == 21
        assert result["name"] == "test"

    def test_scalar_passthrough(self):
        assert nlq._truncate_for_context("hello") == "hello"
        assert nlq._truncate_for_context(42) == 42
        assert nlq._truncate_for_context(None) is None


class TestNlqToolDefinitions(unittest.TestCase):
    """Verify tool definitions are well-formed for the Claude API."""

    def test_all_tools_have_required_fields(self):
        for tool in nlq._NLQ_TOOLS:
            assert "name" in tool, f"Tool missing 'name': {tool}"
            assert "description" in tool, f"Tool '{tool['name']}' missing description"
            assert "input_schema" in tool, f"Tool '{tool['name']}' missing input_schema"

    def test_tool_schemas_are_valid(self):
        for tool in nlq._NLQ_TOOLS:
            schema = tool["input_schema"]
            assert schema["type"] == "object", f"Tool '{tool['name']}' schema type must be 'object'"
            assert "properties" in schema

    def test_query_event_log_has_params(self):
        tool = next(t for t in nlq._NLQ_TOOLS if t["name"] == "query_event_log")
        props = tool["input_schema"]["properties"]
        assert "log" in props
        assert "level" in props
        assert "search" in props

    def test_navigate_to_tab_has_enum(self):
        tool = next(t for t in nlq._NLQ_TOOLS if t["name"] == "navigate_to_tab")
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
    @patch("nlq.anthropic")
    def test_simple_text_response(self, mock_anthropic_mod):
        """Claude answers directly without calling tools."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_client.beta.messages.create.return_value = self._mock_text_response("Your system looks healthy!")

        resp = self.client.post("/api/nlq/ask", json={"question": "How is my system?"})
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["answer"] == "Your system looks healthy!"
        assert data["navigate_to"] is None

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
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
        mock_client.beta.messages.create.side_effect = [
            self._mock_tool_use_response("get_thermals", {}),
            self._mock_text_response("CPU is at 65C, looking good."),
        ]

        resp = self.client.post("/api/nlq/ask", json={"question": "What are my temps?"})
        data = resp.get_json()
        assert resp.status_code == 200
        assert "65" in data["answer"]
        assert mock_thermals.called

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    def test_navigate_to_tab(self, mock_anthropic_mod):
        """Claude navigates to a specific tab."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception

        mock_client.beta.messages.create.side_effect = [
            self._mock_tool_use_response("navigate_to_tab", {"tab": "bsod"}),
            self._mock_text_response("Here's your BSOD data."),
        ]

        resp = self.client.post("/api/nlq/ask", json={"question": "Show me crashes"})
        data = resp.get_json()
        assert data["navigate_to"] == "bsod"

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    def test_navigate_to_unknown_tab_is_dropped(self, mock_anthropic_mod):
        """navigate_to ends up in an onclick handler; a non-enum tab must never reach it."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception
        mock_client.beta.messages.create.side_effect = [
            self._mock_tool_use_response("navigate_to_tab", {"tab": "x');alert(1);//"}),
            self._mock_text_response("Done."),
        ]

        data = self.client.post("/api/nlq/ask", json={"question": "q"}).get_json()
        assert data["navigate_to"] is None

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    def test_api_error_returns_502(self, mock_anthropic_mod):
        """Claude API error returns 502."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client

        api_error = Exception("rate limited")
        mock_anthropic_mod.APIError = type(api_error)
        mock_client.beta.messages.create.side_effect = api_error

        resp = self.client.post("/api/nlq/ask", json={"question": "test"})
        assert resp.status_code == 502

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    @patch("windesktopmgr.get_disk_health")
    def test_tool_failure_handled(self, mock_disk, mock_anthropic_mod):
        """Tool execution error is passed back to Claude gracefully."""
        mock_disk.side_effect = RuntimeError("PowerShell timeout")

        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception

        mock_client.beta.messages.create.side_effect = [
            self._mock_tool_use_response("get_disk_health", {}),
            self._mock_text_response("I couldn't retrieve disk data."),
        ]

        resp = self.client.post("/api/nlq/ask", json={"question": "Check disk"})
        data = resp.get_json()
        assert resp.status_code == 200
        # Claude should have received the error and responded gracefully
        assert "couldn't" in data["answer"].lower()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    @patch("windesktopmgr.query_event_log")
    def test_event_log_tool_passes_params(self, mock_events, mock_anthropic_mod):
        """query_event_log tool passes filter parameters correctly."""
        mock_events.return_value = [
            {"Time": "2026-03-15", "Id": 7036, "Level": "Error", "Source": "SCM", "Message": "stopped"}
        ]

        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception

        mock_client.beta.messages.create.side_effect = [
            self._mock_tool_use_response("query_event_log", {"log": "System", "level": "Error", "max": 10}),
            self._mock_text_response("Found 1 error."),
        ]

        resp = self.client.post("/api/nlq/ask", json={"question": "errors"})
        assert resp.status_code == 200
        mock_events.assert_called_once_with({"log": "System", "level": "Error", "max": 10})

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    def test_max_rounds_exhausted(self, mock_anthropic_mod):
        """If Claude keeps calling tools forever, we stop after max_rounds."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception

        # Every response is a tool_use — never a final text
        mock_client.beta.messages.create.return_value = self._mock_tool_use_response(
            "navigate_to_tab", {"tab": "dashboard"}
        )

        resp = self.client.post("/api/nlq/ask", json={"question": "infinite loop test"})
        data = resp.get_json()
        assert resp.status_code == 200
        assert "couldn't finish" in data["answer"].lower()

    def _stop_response(self, stop_reason, text=""):
        resp = self._mock_text_response(text)
        resp.stop_reason = stop_reason
        return resp

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    def test_refusal_returns_explanation_not_blank(self, mock_anthropic_mod):
        """stop_reason=refusal (after the fallback chain) must not render an empty answer."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception
        mock_client.beta.messages.create.return_value = self._stop_response("refusal")

        resp = self.client.post("/api/nlq/ask", json={"question": "q"})
        data = resp.get_json()
        assert resp.status_code == 200
        assert "declined" in data["answer"].lower()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    def test_max_tokens_without_text_returns_explanation(self, mock_anthropic_mod):
        """A cut-off reply with no text (thinking ate the budget) gets a readable message."""
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception
        mock_client.beta.messages.create.return_value = self._stop_response("max_tokens")

        data = self.client.post("/api/nlq/ask", json={"question": "q"}).get_json()
        assert "cut off" in data["answer"].lower()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    def test_max_tokens_with_partial_text_keeps_text(self, mock_anthropic_mod):
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception
        mock_client.beta.messages.create.return_value = self._stop_response("max_tokens", "Partial answer")

        data = self.client.post("/api/nlq/ask", json={"question": "q"}).get_json()
        assert data["answer"].startswith("Partial answer")
        assert "cut off" in data["answer"].lower()


# Model IDs the API has retired (404 not_found_error). claude-sonnet-4-20250514
# broke the NLQ endpoint in production on 2026-10-11.
RETIRED_MODELS = {
    "claude-sonnet-4-20250514",
    "claude-3-7-sonnet-20250219",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
    "claude-3-opus-20240229",
}


class TestNlqModel(unittest.TestCase):
    """Regression: the model ID must be a live one and the request must be one it accepts."""

    def setUp(self):
        wdm.app.config["TESTING"] = True
        self.client = wdm.app.test_client()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    def _create_kwargs(self, mock_anthropic_mod):
        mock_client = MagicMock()
        mock_anthropic_mod.Anthropic.return_value = mock_client
        mock_anthropic_mod.APIError = Exception
        block = MagicMock(type="text", text="ok")
        mock_client.beta.messages.create.return_value = MagicMock(stop_reason="end_turn", content=[block])
        assert self.client.post("/api/nlq/ask", json={"question": "q"}).status_code == 200
        return mock_client.beta.messages.create.call_args.kwargs

    def test_model_passed_is_nlq_model_and_not_retired(self):
        kw = self._create_kwargs()
        assert kw["model"] == nlq.NLQ_MODEL
        assert kw["model"] not in RETIRED_MODELS

    @staticmethod
    def _model_in_fresh_interpreter(nlq_model_env):
        """NLQ_MODEL as a fresh interpreter sees it (the constant is read at import)."""
        import subprocess

        env = {k: v for k, v in os.environ.items() if k != "NLQ_MODEL"}
        if nlq_model_env is not None:
            env["NLQ_MODEL"] = nlq_model_env
        out = subprocess.run(  # noqa: S603 -- fixed argv, our own interpreter
            [sys.executable, "-c", "import nlq; print(nlq.NLQ_MODEL)"],
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert out.returncode == 0, out.stderr
        return out.stdout.strip()

    def test_default_model_is_opus_5_5(self):
        assert self._model_in_fresh_interpreter(None) == "claude-opus-5-5"

    def test_env_override_sets_model(self):
        assert self._model_in_fresh_interpreter("claude-sonnet-5-5") == "claude-sonnet-5-5"

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}, clear=False)
    @patch("nlq.anthropic")
    def test_client_is_shared_and_has_timeout(self, mock_anthropic_mod):
        nlq._get_client("k")
        nlq._get_client("k")
        mock_anthropic_mod.Anthropic.assert_called_once()
        assert mock_anthropic_mod.Anthropic.call_args.kwargs["timeout"] == nlq.NLQ_TIMEOUT_S

    def test_no_params_opus_5_5_rejects(self):
        """Opus 5.5 400s on sampling params, thinking budgets/disabled, and forced tool_choice."""
        kw = self._create_kwargs()
        for banned in ("temperature", "top_p", "top_k"):
            assert banned not in kw
        thinking = kw.get("thinking")
        assert thinking is None or thinking.get("type") == "adaptive"
        tool_choice = kw.get("tool_choice")
        assert tool_choice is None or tool_choice.get("type") in ("auto", "none")
        # No assistant prefill: the first request ends on the user's question.
        assert kw["messages"][-1]["role"] == "user"

    def test_effort_and_fallbacks_set(self):
        kw = self._create_kwargs()
        assert kw["output_config"]["effort"] == nlq.NLQ_EFFORT
        assert "server-side-fallback-2026-07-01" in kw["betas"]
        assert kw["extra_body"] == {"fallbacks": "default"}

    def test_max_tokens_leaves_room_for_thinking(self):
        """Thinking is always on and counts against max_tokens; 1024 truncates answers."""
        assert self._create_kwargs()["max_tokens"] >= 8000


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
