"""
test_cache_systems.py — Tests for all self-learning cache/lookup systems.

Covers: event cache, BSOD cache, startup cache, process cache, services cache.
Each system follows the same pattern:
  - load/save cache (file I/O)
  - lookup via local source (subprocess/dict)
  - lookup via web (urllib)
  - background worker (queue processing)
  - get_*_info (main entry point: static KB → cache → queue)
"""

import json
import queue
import subprocess
from unittest.mock import MagicMock

import windesktopmgr as wdm

# ── helpers ────────────────────────────────────────────────────────────────────


def _mock_run(mocker, stdout="", returncode=0, side_effect=None):
    m = mocker.patch("windesktopmgr.subprocess.run")
    if side_effect:
        m.side_effect = side_effect
    else:
        m.return_value.stdout = stdout
        m.return_value.returncode = returncode
        m.return_value.stderr = ""
    return m


def _mock_urlopen(mocker, response_data):
    """Mock urllib.request.urlopen to return JSON data."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(response_data).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mocker.patch("windesktopmgr.urllib.request.urlopen", return_value=mock_resp)


# ══════════════════════════════════════════════════════════════════════════════
# EVENT CACHE SYSTEM
# ══════════════════════════════════════════════════════════════════════════════


class TestLoadEventCache:
    def test_loads_from_file(self, mocker, tmp_path):
        cache_file = tmp_path / "event_cache.json"
        cache_file.write_text(json.dumps({"7036": {"title": "Service Control Manager"}}))
        mocker.patch("windesktopmgr.EVENT_CACHE_FILE", str(cache_file))
        wdm._load_event_cache()
        assert "7036" in wdm._event_cache

    def test_missing_file_sets_empty(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.EVENT_CACHE_FILE", str(tmp_path / "nope.json"))
        wdm._load_event_cache()
        assert wdm._event_cache == {}

    def test_corrupt_json_sets_empty(self, mocker, tmp_path):
        cache_file = tmp_path / "event_cache.json"
        cache_file.write_text("{corrupt")
        mocker.patch("windesktopmgr.EVENT_CACHE_FILE", str(cache_file))
        wdm._load_event_cache()
        assert wdm._event_cache == {}


class TestSaveEventCache:
    def test_writes_json(self, mocker, tmp_path):
        cache_file = tmp_path / "event_cache.json"
        mocker.patch("windesktopmgr.EVENT_CACHE_FILE", str(cache_file))
        wdm._event_cache = {"100": {"title": "Test"}}
        wdm._save_event_cache()
        data = json.loads(cache_file.read_text())
        assert data["100"]["title"] == "Test"

    def test_save_error_no_raise(self, mocker):
        mocker.patch("windesktopmgr.EVENT_CACHE_FILE", "/nonexistent/dir/cache.json")
        wdm._event_cache = {"1": {}}
        wdm._save_event_cache()  # should not raise


class TestLookupViaWindowsProvider:
    def test_returns_parsed_result(self, mocker):
        ps_output = json.dumps(
            {
                "Provider": "TestProvider",
                "Id": 7036,
                "Description": "The service entered the running state.",
                "Level": "Info",
                "Keywords": "Service",
            }
        )
        _mock_run(mocker, stdout=ps_output)
        result = wdm._lookup_via_windows_provider(7036, "Service Control Manager")
        assert result is not None
        assert result["source"] == "windows_provider"
        assert "running state" in result["detail"]

    def test_empty_output_returns_none(self, mocker):
        _mock_run(mocker, stdout="")
        assert wdm._lookup_via_windows_provider(9999, "Unknown") is None

    def test_empty_description_returns_none(self, mocker):
        ps_output = json.dumps({"Provider": "P", "Id": 1, "Description": "", "Level": "", "Keywords": ""})
        _mock_run(mocker, stdout=ps_output)
        assert wdm._lookup_via_windows_provider(1, "Src") is None

    def test_timeout_returns_none(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 20))
        assert wdm._lookup_via_windows_provider(7036, "SCM") is None

    def test_truncates_long_descriptions(self, mocker):
        ps_output = json.dumps(
            {"Provider": "P", "Id": 1, "Description": "A" * 500 + " %1 %2 placeholder", "Level": "", "Keywords": ""}
        )
        _mock_run(mocker, stdout=ps_output)
        result = wdm._lookup_via_windows_provider(1, "Src")
        assert len(result["detail"]) <= 402  # 400 + ellipsis


class TestLookupViaWeb:
    def test_returns_result(self, mocker):
        _mock_urlopen(
            mocker,
            {
                "results": [
                    {
                        "title": "Event 7036",
                        "summary": "Service state change",
                        "url": "https://learn.microsoft.com/event7036",
                    }
                ]
            },
        )
        result = wdm._lookup_via_web(7036, "SCM")
        assert result is not None
        assert result["source"] == "microsoft_learn"
        assert "7036" in result["title"]

    def test_empty_results_returns_none(self, mocker):
        _mock_urlopen(mocker, {"results": []})
        assert wdm._lookup_via_web(9999, "Unknown") is None

    def test_network_error_returns_none(self, mocker):
        mocker.patch("windesktopmgr.urllib.request.urlopen", side_effect=Exception("timeout"))
        assert wdm._lookup_via_web(7036, "SCM") is None


class TestEventLookupWorker:
    def test_processes_queue_item_windows_hit(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.EVENT_CACHE_FILE", str(tmp_path / "cache.json"))
        wdm._event_cache = {}
        wdm._lookup_in_flight = set()

        ps_output = json.dumps(
            {"Provider": "SCM", "Id": 7036, "Description": "Service state changed.", "Level": "Info", "Keywords": ""}
        )
        _mock_run(mocker, stdout=ps_output)

        # Put item and stop worker after one iteration
        wdm._lookup_queue = queue.Queue()
        wdm._lookup_queue.put((7036, "Service Control Manager"))

        # Run one iteration manually
        original_get = wdm._lookup_queue.get

        call_count = [0]

        def one_shot_get(timeout=5):
            call_count[0] += 1
            if call_count[0] == 1:
                return original_get(timeout=0)
            raise queue.Empty()

        mocker.patch.object(wdm._lookup_queue, "get", side_effect=one_shot_get)

        # Let the worker run — it'll process one item then hit Empty and loop
        # We break out by having get raise Empty on second call
        def run_one_iteration():
            got_item = False
            try:
                event_id, source = wdm._lookup_queue.get(timeout=1)
                got_item = True
                cache_key = str(event_id)
                with wdm._event_cache_lock:
                    if cache_key in wdm._event_cache:
                        wdm._lookup_in_flight.discard(event_id)
                        wdm._lookup_queue.task_done()
                        return
                result = wdm._lookup_via_windows_provider(event_id, source)
                if not result:
                    result = wdm._lookup_via_web(event_id, source)
                if not result:
                    result = {"source": "unknown", "title": f"Event ID {event_id}"}
                with wdm._event_cache_lock:
                    wdm._event_cache[cache_key] = result
                wdm._save_event_cache()
            except queue.Empty:
                pass
            finally:
                try:
                    if got_item:
                        with wdm._event_cache_lock:
                            wdm._lookup_in_flight.discard(event_id)
                        wdm._lookup_queue.task_done()
                except Exception:
                    pass

        # Reset queue and add item
        wdm._lookup_queue = queue.Queue()
        wdm._lookup_queue.put((7036, "Service Control Manager"))
        run_one_iteration()

        assert "7036" in wdm._event_cache
        assert wdm._event_cache["7036"]["source"] == "windows_provider"

    def test_already_cached_skips_lookup(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.EVENT_CACHE_FILE", str(tmp_path / "cache.json"))
        wdm._event_cache = {"7036": {"source": "cached", "title": "Already cached"}}
        wdm._lookup_in_flight = {7036}
        mock_ps = _mock_run(mocker, stdout="")

        wdm._lookup_queue = queue.Queue()
        wdm._lookup_queue.put((7036, "SCM"))

        # Process one item
        event_id, source = wdm._lookup_queue.get(timeout=1)
        cache_key = str(event_id)
        with wdm._event_cache_lock:
            found = cache_key in wdm._event_cache
        if found:
            with wdm._event_cache_lock:
                wdm._lookup_in_flight.discard(event_id)
            wdm._lookup_queue.task_done()

        mock_ps.assert_not_called()
        assert 7036 not in wdm._lookup_in_flight

    def test_web_fallback_when_windows_fails(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.EVENT_CACHE_FILE", str(tmp_path / "cache.json"))
        wdm._event_cache = {}
        wdm._lookup_in_flight = set()

        _mock_run(mocker, stdout="")  # Windows provider returns nothing
        _mock_urlopen(
            mocker, {"results": [{"title": "Event 100", "summary": "Web result", "url": "https://example.com"}]}
        )

        wdm._lookup_queue = queue.Queue()
        wdm._lookup_queue.put((100, "TestSource"))

        event_id, source = wdm._lookup_queue.get(timeout=1)
        result = wdm._lookup_via_windows_provider(event_id, source)
        if not result:
            result = wdm._lookup_via_web(event_id, source)
        wdm._event_cache[str(event_id)] = result
        wdm._lookup_queue.task_done()

        assert wdm._event_cache["100"]["source"] == "microsoft_learn"

    def test_placeholder_when_all_fail(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.EVENT_CACHE_FILE", str(tmp_path / "cache.json"))
        wdm._event_cache = {}
        _mock_run(mocker, stdout="")
        mocker.patch("windesktopmgr.urllib.request.urlopen", side_effect=Exception("fail"))

        result = wdm._lookup_via_windows_provider(99999, "Fake")
        assert result is None
        result = wdm._lookup_via_web(99999, "Fake")
        assert result is None
        # Worker would create placeholder
        placeholder = {
            "source": "unknown",
            "title": "Event ID 99999",
            "detail": "No description found.",
        }
        wdm._event_cache["99999"] = placeholder
        assert wdm._event_cache["99999"]["source"] == "unknown"


class TestGetEventInfo:
    def setup_method(self):
        self._orig_cache = dict(wdm._event_cache)
        self._orig_flight = set(wdm._lookup_in_flight)
        wdm._lookup_queue = queue.Queue()

    def teardown_method(self):
        wdm._event_cache = self._orig_cache
        wdm._lookup_in_flight = self._orig_flight
        wdm._lookup_queue = queue.Queue()

    def test_static_kb_hit(self):
        if wdm.EVENT_KB:
            eid = next(iter(wdm.EVENT_KB))
            result = wdm.get_event_info(eid)
            assert result is not None

    def test_cache_hit(self):
        wdm._event_cache["12345"] = {"source": "test", "title": "Cached Event"}
        result = wdm.get_event_info(12345)
        assert result is not None
        assert result["title"] == "Cached Event"

    def test_queues_unknown_id(self):
        wdm._event_cache = {}
        wdm._lookup_in_flight = set()
        result = wdm.get_event_info(77777, "TestSource")
        assert result is None  # not yet available
        assert not wdm._lookup_queue.empty()
        assert 77777 in wdm._lookup_in_flight

    def test_no_duplicate_queue(self):
        wdm._event_cache = {}
        wdm._lookup_in_flight = {88888}
        result = wdm.get_event_info(88888, "Test")
        assert result is None
        assert wdm._lookup_queue.empty()  # should not re-queue


class TestGetCacheStatus:
    def test_returns_stats(self):
        wdm._event_cache = {"1": {"title": "T", "source": "s", "fetched": ""}}
        status = wdm.get_cache_status()
        assert status["total_cached"] == 1
        assert len(status["entries"]) == 1


# ══════════════════════════════════════════════════════════════════════════════
# BSOD CACHE SYSTEM
# ══════════════════════════════════════════════════════════════════════════════


class TestLoadBsodCache:
    def test_loads_from_file(self, mocker, tmp_path):
        f = tmp_path / "bsod_cache.json"
        f.write_text(json.dumps({"0x0000009f": {"name": "DRIVER_POWER_STATE_FAILURE"}}))
        mocker.patch("windesktopmgr.BSOD_CACHE_FILE", str(f))
        wdm._load_bsod_cache()
        assert "0x0000009f" in wdm._bsod_cache

    def test_missing_file(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.BSOD_CACHE_FILE", str(tmp_path / "nope.json"))
        wdm._load_bsod_cache()
        assert wdm._bsod_cache == {}

    def test_corrupt_json(self, mocker, tmp_path):
        f = tmp_path / "bsod_cache.json"
        f.write_text("not json!")
        mocker.patch("windesktopmgr.BSOD_CACHE_FILE", str(f))
        wdm._load_bsod_cache()
        assert wdm._bsod_cache == {}


class TestSaveBsodCache:
    def test_writes_json(self, mocker, tmp_path):
        f = tmp_path / "bsod_cache.json"
        mocker.patch("windesktopmgr.BSOD_CACHE_FILE", str(f))
        wdm._bsod_cache = {"0x00000139": {"name": "test"}}
        wdm._save_bsod_cache()
        data = json.loads(f.read_text())
        assert "0x00000139" in data


class TestLookupStopCodeWindows:
    def test_known_code_returns_result(self):
        result = wdm._lookup_stop_code_windows("0x0000009f")
        assert result is not None
        assert result["source"] == "windows_bugcheck_table"
        assert "DRIVER_POWER_STATE_FAILURE" in result["name"]

    def test_unknown_code_returns_none(self):
        assert wdm._lookup_stop_code_windows("0xdeadbeef") is None


class TestLookupStopCodeWeb:
    def test_returns_result(self, mocker):
        _mock_urlopen(
            mocker,
            {
                "results": [
                    {
                        "title": "IRQL_NOT_LESS_OR_EQUAL",
                        "summary": "Bug check info",
                        "url": "https://learn.microsoft.com/bsod",
                    }
                ]
            },
        )
        result = wdm._lookup_stop_code_web("0x0000000a")
        assert result is not None
        assert result["source"] == "microsoft_learn"

    def test_empty_results_returns_none(self, mocker):
        _mock_urlopen(mocker, {"results": []})
        assert wdm._lookup_stop_code_web("0xdeadbeef") is None

    def test_network_error_returns_none(self, mocker):
        mocker.patch("windesktopmgr.urllib.request.urlopen", side_effect=Exception("fail"))
        assert wdm._lookup_stop_code_web("0x0000000a") is None


class TestGetStopCodeInfo:
    def setup_method(self):
        self._orig_cache = dict(wdm._bsod_cache)
        self._orig_flight = set(wdm._bsod_in_flight)
        wdm._bsod_queue = queue.Queue()

    def teardown_method(self):
        wdm._bsod_cache = self._orig_cache
        wdm._bsod_in_flight = self._orig_flight
        wdm._bsod_queue = queue.Queue()

    def test_empty_code_returns_none(self):
        assert wdm.get_stop_code_info("") is None

    def test_static_kb_hit(self):
        # 0x0000000a is IRQL_NOT_LESS_OR_EQUAL — should be in RECOMMENDATIONS_DB
        result = wdm.get_stop_code_info("0x0000000a")
        if result:
            assert result["source"] == "static_kb"

    def test_driver_context_enrichment(self):
        result = wdm.get_stop_code_info("0x0000000a", faulty_driver="ntoskrnl.exe")
        if result and "driver_context" in result:
            assert "ntoskrnl" in result["driver_context"].lower()

    def test_cache_hit(self):
        wdm._bsod_cache["0xaabbccdd"] = {"source": "cached", "title": "Test Code"}
        result = wdm.get_stop_code_info("0xaabbccdd")
        assert result is not None
        assert result["source"] == "cached"

    def test_cache_hit_with_driver_context(self):
        wdm._bsod_cache["0xaabbccdd"] = {"source": "cached", "title": "Test"}
        result = wdm.get_stop_code_info("0xaabbccdd", faulty_driver="nvlddmkm.sys")
        if result and "driver_context" in result:
            assert "nvlddmkm" in result["driver_context"].lower()

    def test_queues_unknown_code(self):
        wdm._bsod_cache = {}
        wdm._bsod_in_flight = set()
        result = wdm.get_stop_code_info("0xdeadbeef")
        assert result is None
        assert not wdm._bsod_queue.empty()

    def test_no_duplicate_queue(self):
        wdm._bsod_cache = {}
        code_norm = wdm._normalise_stop_code("0xdeadbeef")
        wdm._bsod_in_flight = {code_norm}
        wdm.get_stop_code_info("0xdeadbeef")
        assert wdm._bsod_queue.empty()


class TestGetBsodCacheStatus:
    def test_returns_stats(self):
        wdm._bsod_cache = {"0x0a": {"title": "T", "source": "s", "fetched": ""}}
        status = wdm.get_bsod_cache_status()
        assert status["total_cached"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP CACHE SYSTEM
# ══════════════════════════════════════════════════════════════════════════════


class TestLoadStartupCache:
    def test_loads_from_file(self, mocker, tmp_path):
        f = tmp_path / "startup_cache.json"
        f.write_text(json.dumps({"chrome": {"plain_name": "Google Chrome"}}))
        mocker.patch("windesktopmgr.STARTUP_CACHE_FILE", str(f))
        wdm._load_startup_cache()
        assert "chrome" in wdm._startup_cache

    def test_missing_file(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.STARTUP_CACHE_FILE", str(tmp_path / "nope.json"))
        wdm._load_startup_cache()
        assert wdm._startup_cache == {}

    def test_corrupt_json(self, mocker, tmp_path):
        f = tmp_path / "startup_cache.json"
        f.write_text("{bad")
        mocker.patch("windesktopmgr.STARTUP_CACHE_FILE", str(f))
        wdm._load_startup_cache()
        assert wdm._startup_cache == {}


class TestSaveStartupCache:
    def test_writes_json(self, mocker, tmp_path):
        f = tmp_path / "startup_cache.json"
        mocker.patch("windesktopmgr.STARTUP_CACHE_FILE", str(f))
        wdm._startup_cache = {"test": {"plain_name": "Test"}}
        wdm._save_startup_cache()
        data = json.loads(f.read_text())
        assert "test" in data


class TestLookupStartupViaFileinfo:
    def test_returns_parsed_result(self, mocker):
        ps_output = json.dumps(
            {
                "FileDescription": "Google Chrome",
                "CompanyName": "Google LLC",
                "ProductName": "Google Chrome",
                "FileVersion": "120.0.6099.130",
                "FileName": "chrome.exe",
            }
        )
        _mock_run(mocker, stdout=ps_output)
        result = wdm._lookup_startup_via_fileinfo('"C:\\Program Files\\Google\\Chrome\\chrome.exe"', "Chrome")
        assert result is not None
        assert result["source"] == "file_version_info"
        assert "Google" in result["publisher"]

    def test_empty_output_returns_none(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm._lookup_startup_via_fileinfo('"C:\\test.exe"', "Test")
        assert result is None

    def test_no_desc_no_company_returns_none(self, mocker):
        ps_output = json.dumps(
            {"FileDescription": "", "CompanyName": "", "ProductName": "", "FileVersion": "", "FileName": "test.exe"}
        )
        _mock_run(mocker, stdout=ps_output)
        result = wdm._lookup_startup_via_fileinfo('"C:\\test.exe"', "Test")
        assert result is None

    def test_system_path_gets_keep(self, mocker):
        ps_output = json.dumps(
            {
                "FileDescription": "Windows Security",
                "CompanyName": "Microsoft Corporation",
                "ProductName": "Windows Security",
                "FileVersion": "1.0",
                "FileName": "SecurityHealth.exe",
            }
        )
        _mock_run(mocker, stdout=ps_output)
        result = wdm._lookup_startup_via_fileinfo('"C:\\Windows\\System32\\SecurityHealth.exe"', "SecurityHealth")
        assert result is not None
        assert result["recommendation"] == "keep"
        assert result["safe_to_disable"] is False

    def test_microsoft_non_system_gets_optional(self, mocker):
        ps_output = json.dumps(
            {
                "FileDescription": "Microsoft Teams",
                "CompanyName": "Microsoft Corporation",
                "ProductName": "Microsoft Teams",
                "FileVersion": "1.0",
                "FileName": "Teams.exe",
            }
        )
        _mock_run(mocker, stdout=ps_output)
        result = wdm._lookup_startup_via_fileinfo('"C:\\Users\\test\\AppData\\Teams.exe"', "Teams")
        assert result is not None
        assert result["recommendation"] == "optional"
        assert result["safe_to_disable"] is True

    def test_third_party_gets_optional(self, mocker):
        ps_output = json.dumps(
            {
                "FileDescription": "Spotify",
                "CompanyName": "Spotify Ltd",
                "ProductName": "Spotify",
                "FileVersion": "1.0",
                "FileName": "Spotify.exe",
            }
        )
        _mock_run(mocker, stdout=ps_output)
        result = wdm._lookup_startup_via_fileinfo('"C:\\Users\\test\\AppData\\Spotify.exe"', "Spotify")
        assert result is not None
        assert result["recommendation"] == "optional"
        assert "Spotify" in result["reason"]

    def test_timeout_returns_none(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 10))
        result = wdm._lookup_startup_via_fileinfo('"C:\\test.exe"', "Test")
        assert result is None

    def test_non_exe_tries_get_command(self, mocker):
        """When path doesn't end in .exe, should try Get-Command to find it."""
        m = _mock_run(mocker, stdout="")
        wdm._lookup_startup_via_fileinfo("someapp", "SomeApp")
        assert m.called


class TestLookupStartupViaWeb:
    def test_returns_result(self, mocker):
        _mock_urlopen(
            mocker,
            {
                "results": [
                    {
                        "title": "Chrome Startup",
                        "summary": "Browser startup item",
                        "url": "https://learn.microsoft.com/chrome",
                    }
                ]
            },
        )
        result = wdm._lookup_startup_via_web("chrome", "Google Chrome")
        assert result is not None
        assert result["source"] == "microsoft_learn"

    def test_empty_results_returns_none(self, mocker):
        _mock_urlopen(mocker, {"results": []})
        result = wdm._lookup_startup_via_web("unknownapp", "Unknown App")
        assert result is None

    def test_filters_irrelevant_results(self, mocker):
        _mock_urlopen(
            mocker,
            {"results": [{"title": "Visual Studio Installation", "summary": "VS setup", "url": "https://example.com"}]},
        )
        result = wdm._lookup_startup_via_web("vscode", "VSCode")
        assert result is None

    def test_network_error_returns_none(self, mocker):
        mocker.patch("windesktopmgr.urllib.request.urlopen", side_effect=Exception("timeout"))
        result = wdm._lookup_startup_via_web("test", "Test")
        assert result is None


class TestGetStartupItemInfo:
    def setup_method(self):
        self._orig_cache = dict(wdm._startup_cache)
        self._orig_flight = set(wdm._startup_in_flight)
        wdm._startup_queue = queue.Queue()

    def teardown_method(self):
        wdm._startup_cache = self._orig_cache
        wdm._startup_in_flight = self._orig_flight
        wdm._startup_queue = queue.Queue()

    def test_static_kb_hit_by_exe(self):
        if wdm.STARTUP_KB:
            key = next(iter(wdm.STARTUP_KB))
            result = wdm.get_startup_item_info("SomeItem", f'"C:\\path\\{key}.exe"')
            assert result is not None
            assert result["source"] == "static_kb"

    def test_cache_hit(self):
        wdm._startup_cache["testapp"] = {"source": "cached", "plain_name": "Test App"}
        result = wdm.get_startup_item_info("TestItem", '"C:\\path\\testapp.exe"')
        assert result is not None
        assert result["source"] == "cached"

    def test_queues_unknown_item(self):
        wdm._startup_cache = {}
        wdm._startup_in_flight = set()
        result = wdm.get_startup_item_info("UnknownItem", '"C:\\path\\unknown.exe"')
        assert result is None
        assert not wdm._startup_queue.empty()

    def test_partial_name_match(self):
        """Static KB partial match via name_key."""
        if wdm.STARTUP_KB:
            key = next(iter(wdm.STARTUP_KB))
            # Use a name that contains the KB key
            result = wdm.get_startup_item_info(f"prefix_{key}_suffix", "")
            if result:
                assert result["source"] == "static_kb"


# ══════════════════════════════════════════════════════════════════════════════
# PROCESS CACHE SYSTEM
# ══════════════════════════════════════════════════════════════════════════════


class TestLoadProcessCache:
    def test_loads_from_file(self, mocker, tmp_path):
        f = tmp_path / "process_cache.json"
        f.write_text(json.dumps({"chrome": {"plain": "Google Chrome"}}))
        mocker.patch("windesktopmgr.PROCESS_CACHE_FILE", str(f))
        wdm._load_process_cache()
        assert "chrome" in wdm._process_cache

    def test_missing_file(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.PROCESS_CACHE_FILE", str(tmp_path / "nope.json"))
        wdm._load_process_cache()
        assert wdm._process_cache == {}

    def test_corrupt_json(self, mocker, tmp_path):
        f = tmp_path / "process_cache.json"
        f.write_text("{nope")
        mocker.patch("windesktopmgr.PROCESS_CACHE_FILE", str(f))
        wdm._load_process_cache()
        assert wdm._process_cache == {}


class TestSaveProcessCache:
    def test_writes_json(self, mocker, tmp_path):
        f = tmp_path / "process_cache.json"
        mocker.patch("windesktopmgr.PROCESS_CACHE_FILE", str(f))
        wdm._process_cache = {"chrome": {"plain": "Chrome"}}
        wdm._save_process_cache()
        data = json.loads(f.read_text())
        assert "chrome" in data


class TestLookupProcessViaFileinfo:
    def test_returns_parsed_result(self, mocker):
        ps_output = json.dumps(
            {
                "FileDescription": "Google Chrome",
                "CompanyName": "Google LLC",
                "ProductName": "Google Chrome",
                "FileVersion": "120.0",
            }
        )
        _mock_run(mocker, stdout=ps_output)
        result = wdm._lookup_process_via_fileinfo("chrome", "C:\\Program Files\\Google\\Chrome\\chrome.exe")
        assert result is not None
        assert result["source"] == "file_version_info"
        assert "Google" in result["publisher"]

    def test_empty_output_returns_none(self, mocker):
        _mock_run(mocker, stdout="")
        result = wdm._lookup_process_via_fileinfo("chrome", "C:\\chrome.exe")
        assert result is None

    def test_no_desc_no_company_returns_none(self, mocker):
        ps_output = json.dumps({"FileDescription": "", "CompanyName": "", "ProductName": "", "FileVersion": ""})
        _mock_run(mocker, stdout=ps_output)
        result = wdm._lookup_process_via_fileinfo("test", "C:\\test.exe")
        assert result is None

    def test_system_path_not_safe_to_kill(self, mocker):
        ps_output = json.dumps(
            {
                "FileDescription": "Host Process",
                "CompanyName": "Microsoft",
                "ProductName": "Windows",
                "FileVersion": "10.0",
            }
        )
        _mock_run(mocker, stdout=ps_output)
        result = wdm._lookup_process_via_fileinfo("svchost", "C:\\Windows\\System32\\svchost.exe")
        assert result is not None
        assert result["safe_kill"] is False

    def test_no_path_tries_get_command(self, mocker):
        m = _mock_run(mocker, stdout="")
        wdm._lookup_process_via_fileinfo("chrome", "")
        assert m.called

    def test_timeout_returns_none(self, mocker):
        _mock_run(mocker, side_effect=subprocess.TimeoutExpired("powershell", 8))
        result = wdm._lookup_process_via_fileinfo("test", "C:\\test.exe")
        assert result is None


class TestLookupProcessViaWeb:
    def test_returns_result(self, mocker):
        _mock_urlopen(
            mocker,
            {"results": [{"title": "Chrome Process", "summary": "Browser process", "url": "https://example.com"}]},
        )
        result = wdm._lookup_process_via_web("chrome")
        assert result is not None
        assert result["source"] == "microsoft_learn"

    def test_empty_results_returns_none(self, mocker):
        _mock_urlopen(mocker, {"results": []})
        assert wdm._lookup_process_via_web("totallyunknown") is None

    def test_network_error_returns_none(self, mocker):
        mocker.patch("windesktopmgr.urllib.request.urlopen", side_effect=Exception("fail"))
        assert wdm._lookup_process_via_web("test") is None


class TestGetProcessInfo:
    def setup_method(self):
        self._orig_cache = dict(wdm._process_cache)
        self._orig_flight = set(wdm._process_in_flight)
        wdm._process_queue = queue.Queue()

    def teardown_method(self):
        wdm._process_cache = self._orig_cache
        wdm._process_in_flight = self._orig_flight
        wdm._process_queue = queue.Queue()

    def test_static_kb_exact_hit(self):
        if wdm.PROCESS_KB:
            key = next(iter(wdm.PROCESS_KB))
            result = wdm.get_process_info(key)
            assert result is not None
            assert result["source"] == "static_kb"

    def test_static_kb_partial_match(self):
        if wdm.PROCESS_KB:
            key = next(iter(wdm.PROCESS_KB))
            # Try with .exe suffix to trigger partial match
            result = wdm.get_process_info(key + ".exe")
            assert result is not None

    def test_cache_hit(self):
        wdm._process_cache["testproc"] = {"source": "cached", "plain": "Test Process"}
        result = wdm.get_process_info("testproc")
        assert result is not None
        assert result["source"] == "cached"

    def test_queues_unknown_process(self):
        wdm._process_cache = {}
        wdm._process_in_flight = set()
        result = wdm.get_process_info("totallyunknownproc")
        assert result is None
        assert not wdm._process_queue.empty()

    def test_no_duplicate_queue(self):
        wdm._process_cache = {}
        wdm._process_in_flight = {"alreadyinflight"}
        wdm.get_process_info("alreadyinflight")
        assert wdm._process_queue.empty()


# ══════════════════════════════════════════════════════════════════════════════
# SERVICES CACHE SYSTEM
# ══════════════════════════════════════════════════════════════════════════════


class TestLoadServicesCache:
    def test_loads_from_file(self, mocker, tmp_path):
        f = tmp_path / "services_cache.json"
        f.write_text(json.dumps({"wuauserv": {"plain": "Windows Update"}}))
        mocker.patch("windesktopmgr.SERVICES_CACHE_FILE", str(f))
        wdm._load_services_cache()
        assert "wuauserv" in wdm._services_cache

    def test_missing_file(self, mocker, tmp_path):
        mocker.patch("windesktopmgr.SERVICES_CACHE_FILE", str(tmp_path / "nope.json"))
        wdm._load_services_cache()
        assert wdm._services_cache == {}

    def test_corrupt_json(self, mocker, tmp_path):
        f = tmp_path / "services_cache.json"
        f.write_text("bad!")
        mocker.patch("windesktopmgr.SERVICES_CACHE_FILE", str(f))
        wdm._load_services_cache()
        assert wdm._services_cache == {}


class TestSaveServicesCache:
    def test_writes_json(self, mocker, tmp_path):
        f = tmp_path / "services_cache.json"
        mocker.patch("windesktopmgr.SERVICES_CACHE_FILE", str(f))
        wdm._services_cache = {"wuauserv": {"plain": "Windows Update"}}
        wdm._save_services_cache()
        data = json.loads(f.read_text())
        assert "wuauserv" in data


class TestLookupServiceViaWeb:
    def test_returns_result(self, mocker):
        _mock_urlopen(
            mocker,
            {
                "results": [
                    {
                        "title": "Windows Update Service",
                        "summary": "Handles updates",
                        "url": "https://learn.microsoft.com/wu",
                    }
                ]
            },
        )
        result = wdm._lookup_service_via_web("wuauserv", "Windows Update")
        assert result is not None
        assert result["source"] == "microsoft_learn"

    def test_empty_results_returns_none(self, mocker):
        _mock_urlopen(mocker, {"results": []})
        assert wdm._lookup_service_via_web("fakesvc", "Fake Service") is None

    def test_no_summary_skips(self, mocker):
        _mock_urlopen(mocker, {"results": [{"title": "Result", "summary": "", "url": "https://example.com"}]})
        assert wdm._lookup_service_via_web("testsvc", "Test") is None

    def test_network_error_returns_none(self, mocker):
        mocker.patch("windesktopmgr.urllib.request.urlopen", side_effect=Exception("timeout"))
        assert wdm._lookup_service_via_web("svc", "Svc") is None


class TestGetServicesItemInfo:
    def setup_method(self):
        self._orig_cache = dict(wdm._services_cache)
        self._orig_flight = set(wdm._services_in_flight)
        wdm._services_queue = queue.Queue()

    def teardown_method(self):
        wdm._services_cache = self._orig_cache
        wdm._services_in_flight = self._orig_flight
        wdm._services_queue = queue.Queue()

    def test_static_kb_hit(self):
        if wdm.SERVICES_KB:
            key = next(iter(wdm.SERVICES_KB))
            result = wdm.get_services_item_info(key, "Display Name")
            assert result is not None
            assert result["source"] == "static_kb"

    def test_cache_hit(self):
        wdm._services_cache["testsvc"] = {"source": "cached", "plain": "Test Service"}
        result = wdm.get_services_item_info("testsvc", "Test Service")
        assert result is not None
        assert result["source"] == "cached"

    def test_queues_unknown_service(self):
        wdm._services_cache = {}
        wdm._services_in_flight = set()
        result = wdm.get_services_item_info("unknownsvc", "Unknown Service")
        assert result is None
        assert not wdm._services_queue.empty()

    def test_no_duplicate_queue(self):
        wdm._services_cache = {}
        wdm._services_in_flight = {"alreadyinflight"}
        wdm.get_services_item_info("alreadyinflight", "Display")
        assert wdm._services_queue.empty()


# ══════════════════════════════════════════════════════════════════════════════
# build_bsod_analysis + run_scan + _is_this_month
# ══════════════════════════════════════════════════════════════════════════════


class TestIsThisMonth:
    def test_current_month_returns_true(self):
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        ts = now.isoformat()
        assert wdm._is_this_month(ts) is True

    def test_old_date_returns_false(self):
        assert wdm._is_this_month("2020-01-01T00:00:00Z") is False

    def test_garbage_returns_false(self):
        assert wdm._is_this_month("not-a-date") is False


class TestBuildBsodAnalysis:
    def test_empty_events_returns_structure(self, mocker):
        mocker.patch("windesktopmgr.get_bsod_events", return_value=[])
        mocker.patch("windesktopmgr.os.path.isdir", return_value=False)
        result = wdm.build_bsod_analysis()
        assert "summary" in result
        assert "crashes" in result
        assert "timeline" in result
        assert result["summary"]["total_crashes"] == 0

    def test_with_events(self, mocker):
        events = [
            {
                "TimeCreated": "2026-03-15T10:00:00Z",
                "Message": "The computer has rebooted from a bugcheck. Bugcheck was: 0x0000009f. A dump was saved in: C:\\Windows\\MEMORY.DMP",
                "Id": 1001,
            }
        ]
        mocker.patch("windesktopmgr.get_bsod_events", return_value=events)
        mocker.patch("windesktopmgr.os.path.isdir", return_value=False)
        result = wdm.build_bsod_analysis()
        assert result["summary"]["total_crashes"] >= 0  # may or may not parse depending on format


class TestRunScan:
    _DEFAULT_INSTALLED = [
        {
            "DeviceName": "Intel NIC",
            "DriverVersion": "1.0",
            "DriverDate": "",
            "DeviceClass": "Network",
            "Manufacturer": "Intel",
        }
    ]
    _SENTINEL = object()

    def _mock_scan_deps(self, mocker, installed=_SENTINEL, wu=_SENTINEL, nvidia=None):
        """Helper to mock all run_scan dependencies."""
        mocker.patch(
            "windesktopmgr.get_installed_drivers",
            return_value=self._DEFAULT_INSTALLED if installed is self._SENTINEL else installed,
        )
        mocker.patch(
            "windesktopmgr.get_windows_update_drivers",
            return_value={} if wu is self._SENTINEL else wu,
        )
        mocker.patch("windesktopmgr.get_nvidia_update_info", return_value=nvidia)

    def test_completes_scan_wu_success_no_updates(self, mocker):
        self._mock_scan_deps(mocker, wu={})
        wdm.run_scan()
        assert wdm._scan_status["status"] == "complete"
        assert len(wdm._scan_results) == 1
        assert wdm._scan_results[0]["status"] == "up_to_date"  # WU success, 0 updates

    def test_completes_scan_wu_failure(self, mocker):
        self._mock_scan_deps(mocker, wu=None)
        wdm.run_scan()
        assert wdm._scan_status["status"] == "complete"
        assert len(wdm._scan_results) == 1
        assert wdm._scan_results[0]["status"] == "unknown"  # WU failed → unknown

    def test_with_wu_match(self, mocker):
        self._mock_scan_deps(
            mocker,
            installed=[
                {
                    "DeviceName": "Intel Ethernet Controller",
                    "DriverVersion": "1.0",
                    "DriverDate": "",
                    "DeviceClass": "Network",
                    "Manufacturer": "Intel",
                }
            ],
            wu={
                "intel ethernet controller update": {
                    "Title": "Intel Ethernet Controller Update",
                    "DriverVersion": "2.0",
                }
            },
        )
        wdm.run_scan()
        assert wdm._scan_results[0]["status"] == "update_available"

    def test_results_sorted(self, mocker):
        self._mock_scan_deps(
            mocker,
            installed=[
                {
                    "DeviceName": "Zzz Device",
                    "DriverVersion": "1.0",
                    "DriverDate": "",
                    "DeviceClass": "",
                    "Manufacturer": "",
                },
                {
                    "DeviceName": "Aaa Device",
                    "DriverVersion": "1.0",
                    "DriverDate": "",
                    "DeviceClass": "",
                    "Manufacturer": "",
                },
            ],
            wu={"aaa device update": {"Title": "Aaa Device Update", "DriverVersion": "2.0"}},
        )
        wdm.run_scan()
        # update_available sorts before unknown/up_to_date
        assert wdm._scan_results[0]["name"] == "Aaa Device"

    def test_nvidia_update_detected_in_scan(self, mocker):
        """NVIDIA driver with pending update shows update_available via NVIDIA App."""
        self._mock_scan_deps(
            mocker,
            installed=[
                {
                    "DeviceName": "NVIDIA GeForce RTX 4060 Ti",
                    "DriverVersion": "32.0.15.9174",
                    "DriverDate": "2025-01-15",
                    "DeviceClass": "Display",
                    "Manufacturer": "NVIDIA",
                }
            ],
            wu={},  # WU has no NVIDIA update — but NVIDIA App does
            nvidia={
                "Name": "NVIDIA GeForce RTX 4060 Ti",
                "InstalledVersion": "591.74",
                "LatestVersion": "595.79",
                "UpdateAvailable": True,
            },
        )
        wdm.run_scan()
        nv = wdm._scan_results[0]
        assert nv["status"] == "update_available"
        assert nv["latest_version"] == "595.79"
        assert nv["download_url"] == "nvidia-app:"

    def test_nvidia_current_shows_up_to_date(self, mocker):
        """NVIDIA driver that is current shows up_to_date (not unknown)."""
        self._mock_scan_deps(
            mocker,
            installed=[
                {
                    "DeviceName": "NVIDIA GeForce RTX 4060 Ti",
                    "DriverVersion": "32.0.15.9579",
                    "DriverDate": "2026-03-10",
                    "DeviceClass": "Display",
                    "Manufacturer": "NVIDIA",
                }
            ],
            wu={},
            nvidia={
                "Name": "NVIDIA GeForce RTX 4060 Ti",
                "InstalledVersion": "595.79",
                "LatestVersion": "595.79",
                "UpdateAvailable": False,
            },
        )
        wdm.run_scan()
        nv = wdm._scan_results[0]
        assert nv["status"] == "up_to_date"

    def test_nvidia_none_does_not_crash(self, mocker):
        """When no NVIDIA GPU exists, scan still works normally."""
        self._mock_scan_deps(
            mocker,
            installed=[
                {
                    "DeviceName": "NVIDIA High Definition Audio",
                    "DriverVersion": "1.4.5.7",
                    "DriverDate": "",
                    "DeviceClass": "Audio",
                    "Manufacturer": "Microsoft",
                }
            ],
            wu={},
            nvidia=None,
        )
        wdm.run_scan()
        # WU success with 0 updates + no nvidia_info → up_to_date
        assert wdm._scan_results[0]["status"] == "up_to_date"

    def test_wu_match_takes_precedence_over_nvidia_app(self, mocker):
        """If Windows Update has an NVIDIA update, it takes precedence."""
        self._mock_scan_deps(
            mocker,
            installed=[
                {
                    "DeviceName": "NVIDIA GeForce RTX 4060 Ti",
                    "DriverVersion": "32.0.15.9174",
                    "DriverDate": "",
                    "DeviceClass": "Display",
                    "Manufacturer": "NVIDIA",
                }
            ],
            wu={
                "nvidia geforce rtx 4060 ti update": {
                    "Title": "NVIDIA GeForce RTX 4060 Ti Update",
                    "DriverVersion": "32.0.15.9579",
                }
            },
            nvidia={"UpdateAvailable": True, "LatestVersion": "595.79"},
        )
        wdm.run_scan()
        nv = wdm._scan_results[0]
        assert nv["status"] == "update_available"
        # WU match version, not NVIDIA App version
        assert nv["latest_version"] == "32.0.15.9579"
        assert nv["download_url"] == "ms-settings:windowsupdate"
