"""tests/test_identify.py — global AI "identify an unknown thing" service.

Covers the AI engine (identify_via_ai), the non-blocking subsystem (identify /
_resolve_one / cache), the tolerant JSON extractor, and every graceful-fallback
path. The Anthropic SDK + network are fully mocked — no real API calls.
"""

from __future__ import annotations

import json

import pytest

import ai_identify as identify


@pytest.fixture(autouse=True)
def _reset_identify_state(tmp_path, monkeypatch):
    """Isolate module globals + cache file per test."""
    monkeypatch.setattr(identify, "IDENTIFY_CACHE_FILE", str(tmp_path / "identify_cache.json"))
    monkeypatch.setattr(identify, "_cache", {})
    monkeypatch.setattr(identify, "_in_flight", set())
    monkeypatch.setattr(identify, "_ai_calls", 0)
    # Fresh queue so enqueue assertions are clean.
    import queue

    monkeypatch.setattr(identify, "_queue", queue.Queue())
    yield


def _fake_anthropic(text: str, *, raise_exc: Exception | None = None):
    """Build a fake `anthropic` module whose client returns `text`."""

    class _Block:
        def __init__(self, t):
            self.text = t

    class _Resp:
        content = [_Block(text)]

    class _Messages:
        def create(self, **_kw):
            if raise_exc:
                raise raise_exc
            return _Resp()

    class _Client:
        def __init__(self, **_kw):
            self.messages = _Messages()

    class _Mod:
        Anthropic = _Client

    return _Mod()


# ── _extract_json ───────────────────────────────────────────────────────────


class TestExtractJson:
    def test_plain_json(self):
        assert identify._extract_json('{"a": 1}') == {"a": 1}

    def test_json_with_surrounding_prose(self):
        assert identify._extract_json('Sure! {"a": 1, "b": "x"} hope that helps') == {"a": 1, "b": "x"}

    def test_no_braces_returns_none(self):
        assert identify._extract_json("no json here") is None

    def test_malformed_returns_none(self):
        assert identify._extract_json("{not valid json}") is None

    def test_empty_returns_none(self):
        assert identify._extract_json("") is None

    def test_non_object_json_returns_none(self):
        # A bare array isn't a dict.
        assert identify._extract_json("[1, 2, 3]") is None

    def test_prose_prefix_with_brace_still_parses(self):
        # A preamble that itself contains braces must not drop the real object.
        text = 'Here you go {see below}: {"plain": "X", "what": "y"}'
        assert identify._extract_json(text) == {"plain": "X", "what": "y"}


# ── identify_via_ai ─────────────────────────────────────────────────────────


class TestIdentifyViaAi:
    def test_no_sdk_returns_none(self, monkeypatch):
        monkeypatch.setattr(identify, "anthropic", None)
        assert identify.identify_via_ai("process", "vmmem") is None

    def test_no_api_key_returns_none(self, monkeypatch):
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic("{}"))
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert identify.identify_via_ai("process", "vmmem") is None

    def test_happy_path_parses_result(self, monkeypatch):
        payload = json.dumps({"plain": "Virtual Machine Memory", "what": "WSL2/Hyper-V VM memory.", "safe_kill": True})
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic(payload))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        r = identify.identify_via_ai("process", "vmmem")
        assert r["source"] == "claude_ai"
        assert r["plain"] == "Virtual Machine Memory"
        assert "VM memory" in r["what"]
        assert r["safe_kill"] is True
        assert r["fetched"]

    def test_api_error_returns_none(self, monkeypatch):
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic("", raise_exc=RuntimeError("503")))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        assert identify.identify_via_ai("process", "vmmem") is None

    def test_unparseable_reply_returns_none(self, monkeypatch):
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic("I cannot help with that."))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        assert identify.identify_via_ai("process", "vmmem") is None

    def test_reply_without_what_returns_none(self, monkeypatch):
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic('{"plain": "X"}'))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        assert identify.identify_via_ai("process", "vmmem") is None

    def test_call_cap_enforced(self, monkeypatch):
        payload = json.dumps({"plain": "X", "what": "y"})
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic(payload))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setattr(identify, "MAX_AI_LOOKUPS", 2)
        assert identify.identify_via_ai("process", "a") is not None
        assert identify.identify_via_ai("process", "b") is not None
        # Third call exceeds the cap -> None without calling the API.
        assert identify.identify_via_ai("process", "c") is None

    def test_failed_calls_do_not_burn_the_cap(self, monkeypatch):
        """A network blip must not permanently exhaust the budget: failed calls
        return their cap slot so successful calls can still happen afterwards."""
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic("", raise_exc=RuntimeError("503")))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        monkeypatch.setattr(identify, "MAX_AI_LOOKUPS", 2)
        # Many failures...
        for _ in range(5):
            assert identify.identify_via_ai("process", "boom") is None
        assert identify._ai_calls == 0, "failed calls must not consume cap quota"
        # ...the budget is intact, so a recovered API still resolves.
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic(json.dumps({"plain": "X", "what": "y"})))
        assert identify.identify_via_ai("process", "ok") is not None

    def test_unparseable_reply_returns_cap_slot(self, monkeypatch):
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic("no json at all"))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        identify.identify_via_ai("process", "x")
        assert identify._ai_calls == 0

    def test_safe_kill_null_preserved(self, monkeypatch):
        payload = json.dumps({"plain": "X", "what": "y", "safe_kill": None})
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic(payload))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        r = identify.identify_via_ai("driver", "X")
        assert r["safe_kill"] is None


# ── identify (non-blocking) + cache ─────────────────────────────────────────


class TestIdentifyNonBlocking:
    def test_cache_hit_returns_entry(self, monkeypatch):
        entry = {"source": "claude_ai", "plain": "Foo", "what": "bar", "safe_kill": True}
        identify._cache[identify._cache_key("driver", "foo")] = entry
        assert identify.identify("driver", "foo") == entry

    def test_miss_returns_pending_and_enqueues(self):
        r = identify.identify("driver", "mystery", display="Mystery Device")
        assert r["pending"] is True
        assert r["plain"] == "Mystery Device"
        assert identify._queue.qsize() == 1
        assert identify._cache_key("driver", "mystery") in identify._in_flight

    def test_single_flight_no_double_enqueue(self):
        identify.identify("driver", "dup")
        identify.identify("driver", "dup")
        assert identify._queue.qsize() == 1

    def test_get_cached(self):
        assert identify.get_cached("bios", "x") is None
        identify._cache[identify._cache_key("bios", "x")] = {"what": "y"}
        assert identify.get_cached("bios", "x") == {"what": "y"}


# ── _resolve_one (worker core) ──────────────────────────────────────────────


class TestResolveOne:
    def test_resolves_via_ai_and_caches(self, monkeypatch):
        payload = json.dumps({"plain": "NIC", "what": "network card", "safe_kill": False})
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic(payload))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        out = identify._resolve_one("driver", "realtek-xyz")
        assert out["source"] == "claude_ai"
        assert out["plain"] == "NIC"
        # Cached for next time.
        assert identify.get_cached("driver", "realtek-xyz")["what"] == "network card"

    def test_unresolved_placeholder_when_ai_fails(self, monkeypatch):
        monkeypatch.setattr(identify, "anthropic", None)  # no AI available
        out = identify._resolve_one("driver", "nope")
        assert out["source"] == "unresolved"
        assert out["safe_kill"] is None
        assert identify.get_cached("driver", "nope")["source"] == "unresolved"

    def test_cache_hit_skips_ai(self, monkeypatch):
        identify._cache[identify._cache_key("driver", "known")] = {"source": "claude_ai", "what": "cached"}
        # If AI were called it would raise; cache hit must short-circuit.
        monkeypatch.setattr(
            identify,
            "identify_via_ai",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not call AI on cache hit")),
        )
        out = identify._resolve_one("driver", "known")
        assert out["what"] == "cached"

    def test_resolved_entry_persisted_to_disk(self, monkeypatch):
        payload = json.dumps({"plain": "X", "what": "desc"})
        monkeypatch.setattr(identify, "anthropic", _fake_anthropic(payload))
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        identify._resolve_one("service", "svc1")
        with open(identify.IDENTIFY_CACHE_FILE, encoding="utf-8") as fh:
            on_disk = json.load(fh)
        assert identify._cache_key("service", "svc1") in on_disk

    def test_unresolved_entry_not_persisted_to_disk(self, monkeypatch):
        """A transient miss (no key) must NOT be written to disk -- otherwise it
        survives restart and the entity is never retried after the key is set."""
        monkeypatch.setattr(identify, "anthropic", None)  # AI unavailable
        out = identify._resolve_one("driver", "nope")
        assert out["source"] == "unresolved"
        # In-memory cache dedupes this session...
        assert identify.get_cached("driver", "nope")["source"] == "unresolved"
        # ...but nothing was persisted, so a restart gets a clean slate.
        import os

        assert not os.path.exists(identify.IDENTIFY_CACHE_FILE)
