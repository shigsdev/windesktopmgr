"""Tests for the centralized applogging module and /api/logs endpoint."""

import logging
import os
import tempfile

import pytest

import applogging


@pytest.fixture(autouse=True)
def _propagate_logs():
    """applogging configures windesktopmgr with propagate=False, which blocks
    pytest's caplog from seeing any messages. Temporarily re-enable propagation
    so log assertions work.
    """
    root = logging.getLogger("windesktopmgr")
    prev = root.propagate
    root.propagate = True
    yield
    root.propagate = prev


class TestConfigure:
    def test_configure_is_idempotent(self):
        """Calling configure() twice should not add duplicate handlers."""
        # Already configured on import — calling again must be a no-op.
        root1 = applogging.configure()
        root2 = applogging.configure()
        assert root1 is root2
        assert len(root1.handlers) == 1

    def test_get_logger_returns_child(self):
        log = applogging.get_logger("ps")
        assert log.name == "windesktopmgr.ps"

    def test_get_logger_empty_suffix_returns_root(self):
        log = applogging.get_logger("")
        assert log.name == "windesktopmgr"


class TestReadRecent:
    def test_empty_when_file_missing(self, monkeypatch):
        monkeypatch.setattr(applogging, "LOG_FILE", os.path.join(tempfile.gettempdir(), "nonexistent_wdm_test.log"))
        assert applogging.read_recent(lines=100) == []

    def test_parses_well_formed_lines(self, tmp_path, monkeypatch):
        log_path = tmp_path / "test.log"
        log_path.write_text(
            "2026-04-10 12:00:00 INFO    windesktopmgr.flask      GET /api/health -> 200 (1 ms)\n"
            "2026-04-10 12:00:01 WARNING windesktopmgr.ps         rc=1 (500 ms) powershell Get-Something\n"
            "2026-04-10 12:00:02 ERROR   windesktopmgr.ps         TIMEOUT (30000 ms) powershell Get-Slow\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(applogging, "LOG_FILE", str(log_path))
        entries = applogging.read_recent(lines=100)
        # Newest first
        assert len(entries) == 3
        assert entries[0]["level"] == "ERROR"
        assert entries[0]["logger"] == "windesktopmgr.ps"
        assert "TIMEOUT" in entries[0]["message"]
        assert entries[2]["level"] == "INFO"

    def test_level_filter(self, tmp_path, monkeypatch):
        log_path = tmp_path / "test.log"
        log_path.write_text(
            "2026-04-10 12:00:00 INFO    windesktopmgr.flask      msg1\n"
            "2026-04-10 12:00:01 WARNING windesktopmgr.ps         msg2\n"
            "2026-04-10 12:00:02 ERROR   windesktopmgr.ps         msg3\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(applogging, "LOG_FILE", str(log_path))
        entries = applogging.read_recent(lines=100, min_level="WARNING")
        assert len(entries) == 2
        assert all(e["level"] in ("WARNING", "ERROR") for e in entries)

    def test_skips_blank_and_unparseable_lines(self, tmp_path, monkeypatch):
        log_path = tmp_path / "test.log"
        log_path.write_text(
            "\ngarbage not a log line\n2026-04-10 12:00:00 INFO windesktopmgr.flask real\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(applogging, "LOG_FILE", str(log_path))
        entries = applogging.read_recent(lines=100)
        assert len(entries) == 1
        assert entries[0]["message"] == "real"


class TestLogsEndpoint:
    def test_api_logs_returns_ok(self, client, mocker):
        mocker.patch(
            "applogging.read_recent",
            return_value=[
                {
                    "timestamp": "2026-04-10 12:00:00",
                    "level": "INFO",
                    "logger": "windesktopmgr.flask",
                    "message": "hello",
                }
            ],
        )
        resp = client.get("/api/logs")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["count"] == 1
        assert data["entries"][0]["message"] == "hello"

    def test_api_logs_clamps_lines(self, client, mocker):
        mock = mocker.patch("applogging.read_recent", return_value=[])
        client.get("/api/logs?lines=999999")
        assert mock.call_args.kwargs["lines"] == 2000

    def test_api_logs_invalid_lines_defaults(self, client, mocker):
        mock = mocker.patch("applogging.read_recent", return_value=[])
        client.get("/api/logs?lines=notanumber")
        assert mock.call_args.kwargs["lines"] == 200

    def test_api_logs_passes_level(self, client, mocker):
        mock = mocker.patch("applogging.read_recent", return_value=[])
        client.get("/api/logs?level=WARNING")
        assert mock.call_args.kwargs["min_level"] == "WARNING"


class TestFlaskRequestMiddleware:
    def test_request_is_logged(self, client, caplog):
        with caplog.at_level(logging.INFO, logger="windesktopmgr.flask"):
            client.get("/api/logs?lines=1")
        messages = [r.getMessage() for r in caplog.records]
        assert any("GET" in m and "/api/logs" in m and "200" in m for m in messages)

    def test_health_is_not_logged(self, client, caplog):
        with caplog.at_level(logging.INFO, logger="windesktopmgr.flask"):
            client.get("/api/health")
        messages = [r.getMessage() for r in caplog.records]
        assert not any("/api/health" in m for m in messages)


class TestSubprocessLogging:
    def test_successful_call_logs_debug(self, mocker, caplog):
        import windesktopmgr as wdm

        mock_run = mocker.patch("windesktopmgr._original_subprocess_run")
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""
        mock_run.return_value.stdout = "[]"

        with caplog.at_level(logging.DEBUG, logger="windesktopmgr.ps"):
            wdm._headless_subprocess_run(["powershell", "-Command", "Get-Date"])

        # Should have at least one debug log with rc=0
        ps_records = [r for r in caplog.records if r.name == "windesktopmgr.ps"]
        assert any("rc=0" in r.getMessage() for r in ps_records)

    def test_failed_call_logs_warning(self, mocker, caplog):
        import windesktopmgr as wdm

        mock_run = mocker.patch("windesktopmgr._original_subprocess_run")
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "something broke"
        mock_run.return_value.stdout = ""

        with caplog.at_level(logging.WARNING, logger="windesktopmgr.ps"):
            wdm._headless_subprocess_run(["powershell", "-Command", "Get-Broken"])

        ps_records = [r for r in caplog.records if r.name == "windesktopmgr.ps"]
        assert any("rc=1" in r.getMessage() and "something broke" in r.getMessage() for r in ps_records)

    def test_timeout_logs_and_reraises(self, mocker, caplog):
        import subprocess

        import windesktopmgr as wdm

        mocker.patch(
            "windesktopmgr._original_subprocess_run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=30),
        )
        with caplog.at_level(logging.WARNING, logger="windesktopmgr.ps"):
            try:
                wdm._headless_subprocess_run(["powershell", "-Command", "Get-Slow"])
            except subprocess.TimeoutExpired:
                pass
        ps_records = [r for r in caplog.records if r.name == "windesktopmgr.ps"]
        assert any("TIMEOUT" in r.getMessage() for r in ps_records)

    def test_summarize_cmd_truncates_long_commands(self):
        import windesktopmgr as wdm

        long_cmd = ["powershell", "-Command", "X" * 500]
        summary = wdm._summarize_cmd(long_cmd)
        assert len(summary) <= 200
        assert summary.endswith("...")
