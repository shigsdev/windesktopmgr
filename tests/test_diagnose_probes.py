"""Tests for diagnose_probes.py -- the closed probe registry and bounded runner."""

from __future__ import annotations

import inspect
import ipaddress
import json
import os
import re
import socket
import struct
import sys
import time
import types
import winreg

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

import diagnose
import diagnose_crash_probes as dcp
import diagnose_probes as dp
import remediation

# Snapshot before the autouse fixture empties PROBES: the real registrations.
# diagnose_crash_probes is imported first so the snapshot never depends on
# which test module an xdist worker happened to load before this one.
_REGISTERED = dict(dp.PROBES)


@pytest.fixture(autouse=True)
def _isolated_registry(mocker):
    """Every test starts with an empty PROBES dict and registers throwaway probes."""
    mocker.patch.dict(dp.PROBES, {}, clear=True)


class TestResolverConfigMethod:
    """dnspython must not read the resolver config through WMI (it hung inside the tray)."""

    @pytest.mark.skipif(sys.platform != "win32", reason="dnspython's config method is Windows-only")
    def test_import_switches_dnspython_off_wmi(self):
        import dns.win32util

        assert dns.win32util._config_method == dns.win32util.ConfigMethod.Win32

    def test_no_dnspython_is_a_no_op(self, mocker):
        mocker.patch.object(dp, "HAVE_DNSPYTHON", False)
        assert dp._use_win32_resolver_config() is False

    @pytest.mark.skipif(sys.platform != "win32", reason="dnspython's config method is Windows-only")
    def test_a_failing_switch_never_raises(self, mocker):
        import dns.win32util

        mocker.patch.object(dns.win32util, "set_config_method", side_effect=RuntimeError("old dnspython"))
        assert dp._use_win32_resolver_config() is False


def _probe(key="t.probe", fn=None, **kw):
    return dp.register(dp.Probe(key=key, label=f"label {key}", category="test", fn=fn or (lambda s: {}), **kw))


class TestRunProbes:
    def test_happy_path_wraps_data(self):
        _probe("t.ok", fn=lambda s: {"x": 1})
        out = dp.run_probes(["t.ok"], {})
        assert len(out) == 1
        r = out[0]
        assert r["key"] == "t.ok"
        assert r["label"] == "label t.ok"
        assert r["ok"] is True
        assert r["data"] == {"x": 1}
        assert r["elapsed_ms"] >= 0

    def test_slots_passed_to_probe(self):
        seen = {}
        _probe("t.slots", fn=lambda s: seen.update(s) or {})
        dp.run_probes(["t.slots"], {"target_host": "example.com"})
        assert seen == {"target_host": "example.com"}

    def test_raising_probe_becomes_error_not_exception(self):
        def boom(slots):
            raise RuntimeError("boom")

        _probe("t.boom", fn=boom)
        r = dp.run_probes(["t.boom"], {})[0]
        assert r["ok"] is False
        assert "boom" in r["error"]
        assert "data" not in r

    def test_missing_slot_refuses_without_calling(self, mocker):
        fn = mocker.Mock(return_value={})
        _probe("t.need", fn=fn, needs=("target_host",))
        r = dp.run_probes(["t.need"], {})[0]
        assert r["ok"] is False
        assert r["error"] == "missing required slot: target_host"
        fn.assert_not_called()

    def test_empty_slot_value_counts_as_missing(self, mocker):
        fn = mocker.Mock(return_value={})
        _probe("t.need", fn=fn, needs=("target_host",))
        r = dp.run_probes(["t.need"], {"target_host": ""})[0]
        assert r["ok"] is False
        fn.assert_not_called()

    def test_unknown_key_reported(self):
        r = dp.run_probes(["nope.nothing"], {})[0]
        assert r["key"] == "nope.nothing"
        assert r["ok"] is False
        assert r["error"] == "unknown probe"

    def test_timeout_is_bounded(self):
        _probe("t.slow", fn=lambda s: time.sleep(2) or {}, timeout_s=0.2)
        t0 = time.perf_counter()
        r = dp.run_probes(["t.slow"], {})[0]
        assert time.perf_counter() - t0 < 1.0
        assert r["ok"] is False
        assert r["error"] == "timed out after 0.2s"

    def test_results_preserve_input_order(self):
        _probe("a", fn=lambda s: {"n": "a"})
        _probe("b", fn=lambda s: {"n": "b"})
        out = dp.run_probes(["b", "a"], {})
        assert [r["key"] for r in out] == ["b", "a"]

    def test_mixed_outcomes_keep_order(self):
        _probe("ok", fn=lambda s: {})
        out = dp.run_probes(["missing", "ok"], {})
        assert [r["key"] for r in out] == ["missing", "ok"]
        assert [r["ok"] for r in out] == [False, True]

    def test_runs_in_parallel(self):
        for k in ("p1", "p2", "p3"):
            _probe(k, fn=lambda s: time.sleep(0.3) or {})
        t0 = time.perf_counter()
        out = dp.run_probes(["p1", "p2", "p3"], {})
        assert time.perf_counter() - t0 < 0.8
        assert all(r["ok"] for r in out)

    def test_register_rejects_duplicate(self):
        _probe("dup")
        with pytest.raises(ValueError, match="dup"):
            _probe("dup")

    def test_non_dict_return_is_error(self):
        _probe("t.str", fn=lambda s: "str")
        r = dp.run_probes(["t.str"], {})[0]
        assert r["ok"] is False
        assert r["error"] == "probe returned str, expected dict"

    def test_empty_key_list_returns_empty(self, mocker):
        ex = mocker.patch("diagnose_probes.concurrent.futures.ThreadPoolExecutor")
        assert dp.run_probes([], {}) == []
        ex.assert_not_called()

    def test_all_refused_keys_skip_executor(self, mocker):
        ex = mocker.patch("diagnose_probes.concurrent.futures.ThreadPoolExecutor")
        out = dp.run_probes(["x", "y"], {})
        assert [r["error"] for r in out] == ["unknown probe", "unknown probe"]
        ex.assert_not_called()

    def test_duplicate_keys_in_request_each_get_a_result(self):
        _probe("t.ok", fn=lambda s: {"x": 1})
        out = dp.run_probes(["t.ok", "t.ok"], {})
        assert [r["ok"] for r in out] == [True, True]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("hynote.ai", "hynote.ai"),
        ("https://WWW.Hynote.ai:443/login?x=1#y", "www.hynote.ai"),
        ("hynote.ai.", "hynote.ai"),
        ("hynote.ai’s", "hynote.ai"),
        ("hynote.ai's", "hynote.ai"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("8.8.8.8", "8.8.8.8"),
        ("foo", None),
        ("..", None),
        ("a b.com", None),
        ("", None),
        ("a" * 250 + ".com", None),
        ("hynote.ai;rm -rf", None),
        ("2001:db8::1", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("hynote.ai:8443", "hynote.ai"),
    ],
)
def test_normalize_host(raw, expected):
    assert dp.normalize_host(raw) == expected


def test_normalize_host_non_string_is_none():
    assert dp.normalize_host(None) is None


# A newline exposed by one of the cuts must not survive ("$" matches before a final "\n").
_NEWLINE_SHAPES = [
    "hynote.ai\n's",
    "hynote.ai\n.",
    "hynote.ai\n:80",
    "hynote.ai\n/x",
    "hynote.ai\n?q=1",
    "hynote.ai\n#frag",
]

# IPv6 scope ids are link-local interface names, never a diagnosable target.
_SCOPE_ID_SHAPES = ["fe80::1%eth0", "[fe80::1%25eth0]:80", "fe80::1%-v", "fe80::1%1"]

_HOSTILE = [
    *_NEWLINE_SHAPES,
    *_SCOPE_ID_SHAPES,
    "hynote.ai ; calc",
    "hynote.ai;rm -rf",
    "a&b.com",
    "a|b.com",
    "`id`.com",
    "$(id).com",
    "-hynote.ai",
    "-v",
    "--help.com",
    "hynote.ai\x00",
    "hyn\x00ote.ai",
    "hynote.ai\u00a0",
    "hynote\u00a0.ai",
    "hynote.ai\u2028",
    "hynote.ai\u3000",
    "hynote.ai\t",
    "hynote.ai\r\n",
    "a " * 200,
    "a" * 5000,
    ("a" * 60 + ".") * 10 + "com",
    "[" * 50,
    ":" * 50,
]


@pytest.mark.parametrize("raw,expected", [("hynote.ai\n", "hynote.ai"), ("1.2.3.4\n", "1.2.3.4"), ("::1\n", "::1")])
def test_normalize_host_strips_outer_whitespace(raw, expected):
    assert dp.normalize_host(raw) == expected


@pytest.mark.parametrize("raw", _NEWLINE_SHAPES)
def test_normalize_host_rejects_newline_shapes(raw):
    assert dp.normalize_host(raw) is None


@pytest.mark.parametrize("raw", _SCOPE_ID_SHAPES)
def test_normalize_host_rejects_ipv6_scope_id(raw):
    assert dp.normalize_host(raw) is None


@pytest.mark.parametrize("raw", _HOSTILE)
def test_normalize_host_output_is_always_argv_safe(raw):
    """It guards a tracert argument and the egress payload: no result may carry odd characters."""
    out = dp.normalize_host(raw)
    if out is not None:
        assert re.fullmatch(r"[a-z0-9.:-]+", out)
        assert not out.startswith("-")


def _reply(rcode="NOERROR", answers=(), flags=0, rdtype="A", name="example.com"):
    """Build a real dnspython response so the wrapper parses genuine objects."""
    resp = dns.message.make_response(dns.message.make_query(name, rdtype))
    resp.set_rcode(dns.rcode.from_text(rcode))
    resp.flags |= flags
    if answers:
        resp.answer.append(dns.rrset.from_text_list(name, 300, "IN", rdtype, list(answers)))
    return resp


class TestDnsQuery:
    def test_noerror_with_answer(self, mocker):
        mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply(answers=["93.184.216.34"]))
        r = dp._dns_query("1.1.1.1", "example.com", "A")
        assert r == {
            "server": "1.1.1.1",
            "rcode": "NOERROR",
            "nodata": False,
            "answers": ["93.184.216.34"],
            "aa": False,
            "ad": False,
            "error": None,
        }

    def test_noerror_empty_is_nodata(self, mocker):
        mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply())
        r = dp._dns_query("1.1.1.1", "example.com", "A")
        assert r["rcode"] == "NOERROR"
        assert r["nodata"] is True
        assert r["answers"] == []

    def test_nxdomain(self, mocker):
        mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply(rcode="NXDOMAIN"))
        r = dp._dns_query("1.1.1.1", "nope.example.com", "A")
        assert r["rcode"] == "NXDOMAIN"
        assert r["answers"] == []
        assert r["nodata"] is False

    @pytest.mark.parametrize("rc", ["SERVFAIL", "REFUSED"])
    def test_other_rcodes_pass_through(self, mocker, rc):
        mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply(rcode=rc))
        assert dp._dns_query("8.8.8.8", "example.com", "A")["rcode"] == rc

    def test_aa_and_ad_flags(self, mocker):
        mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply(flags=dns.flags.AA | dns.flags.AD))
        r = dp._dns_query("1.1.1.1", "example.com", "A")
        assert r["aa"] is True
        assert r["ad"] is True

    def test_only_matching_rdtype_answers_returned(self, mocker):
        resp = _reply(rdtype="A", answers=["93.184.216.34"])
        resp.answer.append(dns.rrset.from_text("example.com", 300, "IN", "CNAME", "alias.example.net."))
        mocker.patch("diagnose_probes.dns.query.udp", return_value=resp)
        assert dp._dns_query("1.1.1.1", "example.com", "A")["answers"] == ["93.184.216.34"]

    def test_timeout(self, mocker):
        mocker.patch("diagnose_probes.dns.query.udp", side_effect=dns.exception.Timeout())
        r = dp._dns_query("1.1.1.1", "example.com", "A")
        assert r["rcode"] == "TIMEOUT"
        assert r["answers"] == []
        assert r["nodata"] is False

    def test_oserror_becomes_error(self, mocker):
        mocker.patch("diagnose_probes.dns.query.udp", side_effect=OSError("unreachable"))
        r = dp._dns_query("1.1.1.1", "example.com", "A")
        assert r["rcode"] == "ERROR"
        assert "unreachable" in r["error"]

    def test_unexpected_exception_never_raises(self, mocker):
        mocker.patch("diagnose_probes.dns.query.udp", side_effect=ValueError("boom"))
        r = dp._dns_query("1.1.1.1", "example.com", "A")
        assert r["rcode"] == "ERROR"
        assert r["error"] == "boom"

    def test_tc_falls_back_to_tcp(self, mocker):
        mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply(flags=dns.flags.TC))
        tcp = mocker.patch("diagnose_probes.dns.query.tcp", return_value=_reply(answers=["93.184.216.34"]))
        r = dp._dns_query("1.1.1.1", "example.com", "A")
        tcp.assert_called_once()
        assert r["answers"] == ["93.184.216.34"]

    def test_no_tcp_when_not_truncated(self, mocker):
        mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply())
        tcp = mocker.patch("diagnose_probes.dns.query.tcp")
        dp._dns_query("1.1.1.1", "example.com", "A")
        tcp.assert_not_called()

    def test_cd_flag_set_on_query(self, mocker):
        udp = mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply())
        dp._dns_query("1.1.1.1", "example.com", "A", cd=True)
        assert udp.call_args.args[0].flags & dns.flags.CD

    def test_cd_flag_clear_by_default(self, mocker):
        udp = mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply())
        dp._dns_query("1.1.1.1", "example.com", "A")
        assert not udp.call_args.args[0].flags & dns.flags.CD

    def test_want_dnssec_sets_do_bit(self, mocker):
        udp = mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply())
        dp._dns_query("1.1.1.1", "example.com", "A", want_dnssec=True)
        assert udp.call_args.args[0].ednsflags & dns.flags.DO

    def test_timeout_passed_through(self, mocker):
        udp = mocker.patch("diagnose_probes.dns.query.udp", return_value=_reply())
        dp._dns_query("1.1.1.1", "example.com", "A", timeout=1.5)
        assert udp.call_args.kwargs["timeout"] == 1.5

    def test_without_dnspython(self, mocker):
        mocker.patch("diagnose_probes.HAVE_DNSPYTHON", False)
        r = dp._dns_query("1.1.1.1", "example.com", "A")
        assert r["rcode"] == "ERROR"
        assert r["error"] == "dnspython not installed"
        assert r["answers"] == []

    def test_tls_hostname_uses_dns_over_tls_not_udp(self, mocker):
        udp = mocker.patch("diagnose_probes.dns.query.udp")
        tls = mocker.patch("diagnose_probes.dns.query.tls", return_value=_reply(answers=["34.110.213.225"]))
        r = dp._dns_query("1.1.1.1", "hynote.ai", "A", timeout=2.5, tls_hostname="cloudflare-dns.com")
        udp.assert_not_called()
        assert tls.call_args.args[1] == "1.1.1.1"
        assert tls.call_args.kwargs == {"timeout": 2.5, "server_hostname": "cloudflare-dns.com"}
        assert r["rcode"] == "NOERROR"
        assert r["answers"] == ["34.110.213.225"]

    def test_tls_timeout_is_timeout(self, mocker):
        mocker.patch("diagnose_probes.dns.query.tls", side_effect=dns.exception.Timeout())
        assert dp._dns_query("1.1.1.1", "hynote.ai", "A", tls_hostname="cloudflare-dns.com")["rcode"] == "TIMEOUT"

    def test_tls_failure_never_raises(self, mocker):
        # e.g. a certificate that does not match the resolver's name (an interceptor on :853)
        mocker.patch("diagnose_probes.dns.query.tls", side_effect=dp.ssl.SSLCertVerificationError("bad cert"))
        r = dp._dns_query("1.1.1.1", "hynote.ai", "A", tls_hostname="cloudflare-dns.com")
        assert r["rcode"] == "ERROR"
        assert "bad cert" in r["error"]


class TestSystemNameservers:
    def test_returns_resolver_nameservers(self, mocker):
        mocker.patch("diagnose_probes.dns.resolver.Resolver").return_value.nameservers = ["192.168.1.1"]
        assert dp._system_nameservers() == ["192.168.1.1"]

    def test_error_returns_empty(self, mocker):
        mocker.patch("diagnose_probes.dns.resolver.Resolver", side_effect=OSError("no config"))
        assert dp._system_nameservers() == []

    def test_without_dnspython_returns_empty(self, mocker):
        mocker.patch("diagnose_probes.HAVE_DNSPYTHON", False)
        assert dp._system_nameservers() == []


def test_public_resolvers_constant():
    assert dp.PUBLIC_RESOLVERS == (("cloudflare", "1.1.1.1"), ("google", "8.8.8.8"))


def test_public_resolver_tls_names_cover_every_public_resolver():
    assert dp.PUBLIC_RESOLVER_TLS_NAMES == {"cloudflare": "cloudflare-dns.com", "google": "dns.google"}
    assert set(dp.PUBLIC_RESOLVER_TLS_NAMES) == {name for name, _ in dp.PUBLIC_RESOLVERS}


class TestWaveOneRegistration:
    @pytest.mark.parametrize(
        ("key", "label", "timeout"),
        [
            ("dns.resolve_cached", "Resolve through Windows (uses the DNS cache)", 8),
            ("dns.resolve_direct", "Ask public DNS servers directly over encrypted DNS (bypasses the cache)", 8),
            ("dns.authoritative", "Ask the domain's own nameservers", 12),
            ("dns.record_sweep", "List every DNS record type for the name", 10),
        ],
    )
    def test_registered_with_contract_metadata(self, key, label, timeout):
        p = _REGISTERED[key]
        assert p.label == label
        assert p.category == "network"
        assert p.needs == ("target_host",)
        assert p.redact == ("username",)
        assert p.timeout_s == timeout

    def test_registry_functions_are_the_p_functions(self):
        assert _REGISTERED["dns.resolve_cached"].fn is dp._p_resolve_cached
        assert _REGISTERED["dns.resolve_direct"].fn is dp._p_resolve_direct
        assert _REGISTERED["dns.authoritative"].fn is dp._p_authoritative
        assert _REGISTERED["dns.record_sweep"].fn is dp._p_record_sweep


class TestOptionalNeeds:
    def test_missing_optional_slot_does_not_refuse_the_probe(self):
        seen = []
        dp.register(dp.Probe("t.opt", "T", "crash", lambda s: seen.append(dict(s)) or {}, needs_optional=("app_name",)))
        [res] = dp.run_probes(["t.opt"], {})
        assert res["ok"] is True
        assert seen == [{}]

    def test_present_optional_slot_is_passed_through(self):
        seen = []
        dp.register(dp.Probe("t.opt", "T", "crash", lambda s: seen.append(dict(s)) or {}, needs_optional=("app_name",)))
        dp.run_probes(["t.opt"], {"app_name": "Chrome"})
        assert seen == [{"app_name": "Chrome"}]


SLOTS = {"target_host": "hynote.ai"}


class TestResolveCached:
    def test_happy_path_dedupes_and_sorts(self, mocker):
        mocker.patch.object(
            dp.socket,
            "getaddrinfo",
            return_value=[
                (2, 1, 6, "", ("104.21.5.9", 0)),
                (2, 2, 17, "", ("104.21.5.9", 0)),
                (2, 1, 6, "", ("104.21.1.1", 0)),
            ],
        )
        assert dp._p_resolve_cached(SLOTS) == {
            "resolved": True,
            "addresses": ["104.21.1.1", "104.21.5.9"],
            "error": None,
        }

    def test_gaierror_reports_failure(self, mocker):
        mocker.patch.object(dp.socket, "getaddrinfo", side_effect=socket.gaierror(11001, "getaddrinfo failed"))
        d = dp._p_resolve_cached(SLOTS)
        assert d["resolved"] is False
        assert d["addresses"] == []
        assert "11001" in d["error"]

    def test_empty_result_is_unresolved(self, mocker):
        mocker.patch.object(dp.socket, "getaddrinfo", return_value=[])
        d = dp._p_resolve_cached(SLOTS)
        assert d["resolved"] is False
        assert d["addresses"] == []
        assert d["error"]

    def test_queries_the_target_host(self, mocker):
        m = mocker.patch.object(dp.socket, "getaddrinfo", return_value=[])
        dp._p_resolve_cached(SLOTS)
        assert m.call_args.args[0] == "hynote.ai"


def _fake_reply(server, rcode="NOERROR", answers=(), aa=False):
    answers = list(answers)
    return {
        "server": server,
        "rcode": rcode,
        "nodata": rcode == "NOERROR" and not answers,
        "answers": answers,
        "aa": aa,
        "ad": False,
        "error": None,
    }


class TestResolveDirect:
    def test_three_resolvers_in_order(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=["192.168.1.1"])
        q = mocker.patch.object(
            dp,
            "_dns_query",
            side_effect=lambda server, name, rdtype, **kw: _fake_reply(
                server, answers=["1.2.3.4"] if server != "8.8.8.8" else []
            ),
        )
        d = dp._p_resolve_direct(SLOTS)
        assert d["dnspython"] is True
        assert [r["name"] for r in d["resolvers"]] == ["system", "cloudflare", "google"]
        assert [r["server"] for r in d["resolvers"]] == ["192.168.1.1", "1.1.1.1", "8.8.8.8"]
        assert d["resolvers"][0] == {
            "name": "system",
            "server": "192.168.1.1",
            "transport": "udp",
            "rcode": "NOERROR",
            "nodata": False,
            "answers": ["1.2.3.4"],
        }
        assert [r["transport"] for r in d["resolvers"]] == ["udp", "tls", "tls"]
        assert d["resolvers"][2]["nodata"] is True
        assert all(c.args[1] == "hynote.ai" and c.args[2] == "A" for c in q.call_args_list)

    def test_public_resolvers_are_asked_over_tls_with_their_names(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=["192.168.1.1"])
        q = mocker.patch.object(dp, "_dns_query", side_effect=lambda server, *a, **k: _fake_reply(server))
        dp._p_resolve_direct(SLOTS)
        tls_names = {c.args[0]: c.kwargs.get("tls_hostname") for c in q.call_args_list}
        assert tls_names == {"192.168.1.1": None, "1.1.1.1": "cloudflare-dns.com", "8.8.8.8": "dns.google"}

    @pytest.mark.parametrize("rcode", ["TIMEOUT", "ERROR"])
    def test_tls_failure_falls_back_to_udp(self, mocker, rcode):
        mocker.patch.object(dp, "_system_nameservers", return_value=[])

        def fake(server, name, rdtype, **kw):
            if kw.get("tls_hostname"):
                return _fake_reply(server, rcode=rcode)
            return _fake_reply(server, rcode="NXDOMAIN")

        q = mocker.patch.object(dp, "_dns_query", side_effect=fake)
        d = dp._p_resolve_direct(SLOTS)
        assert [(r["name"], r["transport"], r["rcode"]) for r in d["resolvers"]] == [
            ("cloudflare", "udp", "NXDOMAIN"),
            ("google", "udp", "NXDOMAIN"),
        ]
        assert q.call_count == 4

    @pytest.mark.parametrize("rcode", ["NXDOMAIN", "SERVFAIL", "REFUSED"])
    def test_a_tls_answer_of_any_rcode_is_kept_without_fallback(self, mocker, rcode):
        mocker.patch.object(dp, "_system_nameservers", return_value=[])
        q = mocker.patch.object(dp, "_dns_query", side_effect=lambda server, *a, **k: _fake_reply(server, rcode=rcode))
        d = dp._p_resolve_direct(SLOTS)
        assert [(r["transport"], r["rcode"]) for r in d["resolvers"]] == [("tls", rcode), ("tls", rcode)]
        assert q.call_count == 2

    def test_worst_case_fits_the_probe_timeout(self):
        # The resolvers are asked side by side; the slowest chain is one TLS try plus one UDP fallback.
        budget = _REGISTERED["dns.resolve_direct"].timeout_s
        assert budget > dp._DOT_TIMEOUT_S + dp._DIRECT_UDP_TIMEOUT_S

    def test_no_system_nameserver_omits_system(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=[])
        mocker.patch.object(dp, "_dns_query", side_effect=lambda server, *a, **k: _fake_reply(server))
        d = dp._p_resolve_direct(SLOTS)
        assert [r["name"] for r in d["resolvers"]] == ["cloudflare", "google"]

    def test_queries_a_records_on_public_servers(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=[])
        q = mocker.patch.object(dp, "_dns_query", side_effect=lambda server, *a, **k: _fake_reply(server))
        dp._p_resolve_direct(SLOTS)
        assert {c.args[0] for c in q.call_args_list} == {"1.1.1.1", "8.8.8.8"}
        assert {c.args[2] for c in q.call_args_list} == {"A"}

    def test_failure_rcodes_copied_through(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=[])
        mocker.patch.object(dp, "_dns_query", side_effect=lambda server, *a, **k: _fake_reply(server, rcode="NXDOMAIN"))
        d = dp._p_resolve_direct(SLOTS)
        assert [r["rcode"] for r in d["resolvers"]] == ["NXDOMAIN", "NXDOMAIN"]

    def test_without_dnspython(self, mocker):
        mocker.patch.object(dp, "HAVE_DNSPYTHON", False)
        assert dp._p_resolve_direct(SLOTS) == {"dnspython": False, "resolvers": []}


class TestInterception:
    @pytest.fixture(autouse=True)
    def _hops(self, mocker):
        """The hop test sends real packets; every test here gets a canned result instead."""
        self.hops = mocker.patch.object(dp, "_intercept_hops", return_value=[{"source": "s", "answering_hop": 1}])

    def test_any_reply_from_test_net_means_intercepted(self, mocker):
        q = mocker.patch.object(dp, "_dns_query", return_value=_fake_reply("192.0.2.1", answers=["23.1.2.3"]))
        assert dp._p_interception({}) == {
            "intercepted": True,
            "probe_server": "192.0.2.1",
            "answered_rcode": "NOERROR",
            "paths": [{"source": "s", "answering_hop": 1}],
        }
        q.assert_called_once_with("192.0.2.1", "www.microsoft.com", "A", timeout=2)
        self.hops.assert_called_once_with()

    @pytest.mark.parametrize("rcode", ["NXDOMAIN", "SERVFAIL", "REFUSED"])
    def test_an_error_reply_is_still_a_reply(self, mocker, rcode):
        mocker.patch.object(dp, "_dns_query", return_value=_fake_reply("192.0.2.1", rcode=rcode))
        d = dp._p_interception({})
        assert d["intercepted"] is True
        assert d["answered_rcode"] == rcode

    @pytest.mark.parametrize("rcode", ["TIMEOUT", "ERROR"])
    def test_no_reply_means_not_intercepted(self, mocker, rcode):
        mocker.patch.object(dp, "_dns_query", return_value=_fake_reply("192.0.2.1", rcode=rcode))
        assert dp._p_interception({}) == {"intercepted": False, "probe_server": "192.0.2.1", "answered_rcode": None}
        self.hops.assert_not_called()  # no interception: no hop test, no extra seconds

    def test_probe_server_is_rfc5737_test_net_1(self):
        assert ipaddress.ip_address(dp.INTERCEPTION_PROBE_SERVER) in ipaddress.ip_network("192.0.2.0/24")

    def test_without_dnspython(self, mocker):
        mocker.patch.object(dp, "HAVE_DNSPYTHON", False)
        q = mocker.patch.object(dp, "_dns_query")
        assert dp._p_interception({}) == {"intercepted": None, "error": "dnspython not installed"}
        q.assert_not_called()

    def test_registered_with_contract_metadata(self):
        p = _REGISTERED["dns.interception"]
        assert p.label == "Check whether something on the network answers DNS itself"
        assert p.category == "network"
        assert p.needs == ()
        assert p.redact == ("username",)
        # The first query (2 s) plus the hop test's worst case (3 s) must fit.
        assert p.timeout_s == 7
        assert p.timeout_s > 2 + len(dp._HOP_TTLS) * dp._HOP_TIMEOUT_S
        assert p.fn is dp._p_interception


def _fake_udp_socket(mocker, *, recv=None, bind_error=None):
    """Patch socket.socket for the hop test; returns the socket mock."""
    sock = mocker.MagicMock()
    sock.__enter__.return_value = sock
    if bind_error is not None:
        sock.bind.side_effect = bind_error
    sock.recvfrom.side_effect = recv if recv is not None else [(b"reply", ("192.0.2.1", 53))]
    mocker.patch.object(dp.socket, "socket", return_value=sock)
    return sock


class TestInterceptHops:
    """The hop test: which hop answers a never-routed DNS query, per network connection."""

    def test_ipv4_list_keeps_usable_v4_only(self):
        raw = ["10.0.0.34", " 10.0.0.34", "0.0.0.0", "169.254.1.2", "fe80::1", "junk & calc", 7, "192.168.1.159"]
        assert dp._ipv4_list(raw) == ["10.0.0.34", "192.168.1.159"]
        assert dp._ipv4_list("192.168.1.1") == ["192.168.1.1"]
        assert dp._ipv4_list(None) == []

    def test_gateway_paths_pair_each_adapter_source_with_its_gateway(self, mocker):
        hklm = winreg.HKEY_LOCAL_MACHINE
        _patch_registry(
            mocker,
            subkeys=["{eth}", "{wifi}", "{nogw}", "{noip}"],
            values={
                (hklm, _IFACES + r"\{eth}"): {"DhcpIPAddress": "192.168.1.159", "DhcpDefaultGateway": ["192.168.1.1"]},
                (hklm, _IFACES + r"\{wifi}"): {
                    "IPAddress": ["10.0.0.34"],
                    "DefaultGateway": ["10.0.0.1"],
                    "DhcpIPAddress": "10.9.9.9",
                    "DhcpDefaultGateway": ["10.9.9.1"],
                },
                (hklm, _IFACES + r"\{nogw}"): {"DhcpIPAddress": "172.16.0.5"},
                (hklm, _IFACES + r"\{noip}"): {"DhcpDefaultGateway": ["172.16.0.1"], "DhcpIPAddress": "0.0.0.0"},
            },
        )
        assert dp._gateway_paths() == [
            {"source": "192.168.1.159", "gateway": "192.168.1.1"},
            {"source": "10.0.0.34", "gateway": "10.0.0.1"},  # static settings win over DHCP leftovers
        ]

    def test_hop_answered_sends_the_query_from_source_with_the_hop_limit(self, mocker):
        sock = _fake_udp_socket(mocker)
        assert dp._hop_answered("10.0.0.34", 2) is True
        sock.bind.assert_called_once_with(("10.0.0.34", 0))
        sock.setsockopt.assert_called_once_with(socket.IPPROTO_IP, socket.IP_TTL, 2)
        sock.settimeout.assert_called_once_with(dp._HOP_TIMEOUT_S)
        wire, target = sock.sendto.call_args.args
        assert target == ("192.0.2.1", 53)
        assert dns.message.from_wire(wire).question[0].name.to_text() == "www.microsoft.com."

    def test_hop_answered_timeout_is_no_answer(self, mocker):
        _fake_udp_socket(mocker, recv=TimeoutError("timed out"))
        assert dp._hop_answered("10.0.0.34", 1) is False

    @pytest.mark.parametrize("err", [ConnectionResetError(10054, "reset"), OSError(10052, "net reset")])
    def test_hop_answered_icmp_error_on_receive_is_no_answer_at_this_hop(self, mocker, err):
        # Windows reports a router's ICMP "time exceeded" as a receive error; the next hop must still be tried.
        _fake_udp_socket(mocker, recv=err)
        assert dp._hop_answered("10.0.0.34", 1) is False

    def test_hop_answered_send_failure_is_none(self, mocker):
        sock = _fake_udp_socket(mocker)
        sock.sendto.side_effect = OSError(10051, "network unreachable")
        assert dp._hop_answered("10.0.0.34", 1) is None

    def test_hop_answered_socket_creation_failure_is_none(self, mocker):
        mocker.patch.object(dp.socket, "socket", side_effect=OSError("no sockets"))
        assert dp._hop_answered("10.0.0.34", 1) is None

    def test_hop_answered_unassigned_source_is_none(self, mocker):
        _fake_udp_socket(mocker, bind_error=OSError(10049, "address not valid"))
        assert dp._hop_answered("10.9.9.9", 1) is None

    def test_path_hops_stops_at_the_first_answering_hop(self, mocker):
        tried = []
        mocker.patch.object(dp, "_hop_answered", side_effect=lambda src, ttl: tried.append(ttl) or ttl == 2)
        out = dp._path_hops({"source": "10.0.0.34", "gateway": "10.0.0.1"})
        assert out == {"source": "10.0.0.34", "gateway": "10.0.0.1", "answering_hop": 2, "error": None}
        assert tried == [1, 2]

    def test_path_hops_no_answer_within_three_hops(self, mocker):
        mocker.patch.object(dp, "_hop_answered", return_value=False)
        assert dp._path_hops({"source": "a", "gateway": "g"})["answering_hop"] is None

    def test_path_hops_unsendable_source_is_an_error(self, mocker):
        mocker.patch.object(dp, "_hop_answered", return_value=None)
        out = dp._path_hops({"source": "a", "gateway": "g"})
        assert out["answering_hop"] is None
        assert out["error"] == "could not send from this address"

    def test_intercept_hops_drops_unusable_paths_and_caps_the_count(self, mocker):
        paths = [{"source": f"10.0.{i}.2", "gateway": f"10.0.{i}.1"} for i in range(5)]
        mocker.patch.object(dp, "_gateway_paths", return_value=paths)
        mocker.patch.object(
            dp,
            "_hop_answered",
            side_effect=lambda src, ttl: None if src == "10.0.1.2" else ttl == 1,
        )
        out = dp._intercept_hops()
        assert [p["source"] for p in out] == ["10.0.0.2", "10.0.2.2"]  # 3-path cap, unsendable one dropped
        assert all(p["answering_hop"] == 1 for p in out)

    def test_intercept_hops_without_paths_or_registry(self, mocker):
        mocker.patch.object(dp, "_gateway_paths", return_value=[])
        assert dp._intercept_hops() == []
        mocker.patch.object(dp, "_gateway_paths", side_effect=OSError("no registry"))
        assert dp._intercept_hops() == []


class TestAuthoritative:
    @staticmethod
    def _query_fn(ns_names, ns_ips, target_answers=("104.21.1.1",)):
        def fake(server, name, rdtype, **kw):
            if rdtype == "NS":
                return _fake_reply(server, answers=[n + "." for n in ns_names])
            if name in ns_ips:
                return _fake_reply(server, answers=[ns_ips[name]])
            return _fake_reply(server, answers=list(target_answers), aa=True)

        return fake

    def test_happy_path(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=["192.168.1.1"])
        mocker.patch.object(dp.dns.resolver, "zone_for_name", return_value=dns.name.from_text("hynote.ai."))
        ips = {"ns1.cf.com": "10.0.0.1", "ns2.cf.com": "10.0.0.2"}
        q = mocker.patch.object(dp, "_dns_query", side_effect=self._query_fn(list(ips), ips))
        d = dp._p_authoritative(SLOTS)
        assert d["zone"] == "hynote.ai"
        assert [n["name"] for n in d["nameservers"]] == ["ns1.cf.com", "ns2.cf.com"]
        assert [n["ip"] for n in d["nameservers"]] == ["10.0.0.1", "10.0.0.2"]
        assert all(n["aa"] is True and n["rcode"] == "NOERROR" and n["answers"] for n in d["nameservers"])
        assert set(d["nameservers"][0]) == {"name", "ip", "rcode", "nodata", "aa", "answers"}
        # NS and NS-address lookups go via the system resolver; target A goes to the NS IP.
        assert q.call_args_list[0].args[:3] == ("192.168.1.1", "hynote.ai", "NS")
        assert ("10.0.0.1", "hynote.ai", "A") in [c.args[:3] for c in q.call_args_list]

    def test_only_first_two_ns_queried(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=[])
        mocker.patch.object(dp.dns.resolver, "zone_for_name", return_value=dns.name.from_text("hynote.ai."))
        ips = {f"ns{i}.cf.com": f"10.0.0.{i}" for i in range(1, 5)}
        q = mocker.patch.object(dp, "_dns_query", side_effect=self._query_fn(list(ips), ips))
        d = dp._p_authoritative(SLOTS)
        assert len(d["nameservers"]) == 2
        assert "ns3.cf.com" not in [c.args[1] for c in q.call_args_list]
        assert q.call_args_list[0].args[0] == "1.1.1.1"

    def test_ns_without_ip_is_skipped(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=[])
        mocker.patch.object(dp.dns.resolver, "zone_for_name", return_value=dns.name.from_text("hynote.ai."))

        def fake(server, name, rdtype, **kw):
            if rdtype == "NS":
                return _fake_reply(server, answers=["ns1.cf.com.", "ns2.cf.com."])
            if name == "ns1.cf.com":
                return _fake_reply(server, rcode="NXDOMAIN")
            if name == "ns2.cf.com":
                return _fake_reply(server, answers=["10.0.0.2"])
            return _fake_reply(server, answers=["104.21.1.1"], aa=True)

        mocker.patch.object(dp, "_dns_query", side_effect=fake)
        d = dp._p_authoritative(SLOTS)
        assert [n["name"] for n in d["nameservers"]] == ["ns2.cf.com"]

    def test_zone_lookup_failure(self, mocker):
        mocker.patch.object(dp.dns.resolver, "zone_for_name", side_effect=RuntimeError("boom"))
        assert dp._p_authoritative(SLOTS) == {"zone": None, "nameservers": []}

    def test_without_dnspython(self, mocker):
        mocker.patch.object(dp, "HAVE_DNSPYTHON", False)
        assert dp._p_authoritative(SLOTS) == {"zone": None, "nameservers": []}


class TestRecordSweep:
    TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "SOA", "NS")

    def test_one_query_per_type_against_system_resolver(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=["192.168.1.1"])
        q = mocker.patch.object(
            dp,
            "_dns_query",
            side_effect=lambda server, name, rdtype, **kw: _fake_reply(server, answers=[f"{rdtype}-rec"]),
        )
        d = dp._p_record_sweep(SLOTS)
        assert [c.args[2] for c in q.call_args_list] == list(self.TYPES)
        assert {c.args[0] for c in q.call_args_list} == {"192.168.1.1"}
        assert set(d["records"]) == set(self.TYPES)
        assert d["records"]["MX"] == ["MX-rec"]
        assert d["rcode"] == "NOERROR"

    def test_falls_back_to_cloudflare(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=[])
        q = mocker.patch.object(dp, "_dns_query", side_effect=lambda server, *a, **k: _fake_reply(server))
        dp._p_record_sweep(SLOTS)
        assert {c.args[0] for c in q.call_args_list} == {"1.1.1.1"}

    def test_rcode_comes_from_a_query(self, mocker):
        mocker.patch.object(dp, "_system_nameservers", return_value=[])
        mocker.patch.object(
            dp,
            "_dns_query",
            side_effect=lambda server, name, rdtype, **kw: _fake_reply(
                server, rcode="NXDOMAIN" if rdtype == "A" else "NOERROR"
            ),
        )
        d = dp._p_record_sweep(SLOTS)
        assert d["rcode"] == "NXDOMAIN"
        assert d["records"]["A"] == []

    def test_without_dnspython(self, mocker):
        mocker.patch.object(dp, "HAVE_DNSPYTHON", False)
        d = dp._p_record_sweep(SLOTS)
        assert d["rcode"] == "ERROR"
        assert d["records"] == {t: [] for t in self.TYPES}


# ── Local configuration probes (hosts, DNS client, proxy) ────────────────────


def _hosts_file(mocker, tmp_path, text: str | bytes):
    f = tmp_path / "hosts"
    if isinstance(text, bytes):
        f.write_bytes(text)
    else:
        f.write_text(text, encoding="utf-8")
    mocker.patch.object(dp, "HOSTS_PATH", str(f))
    return f


class TestHostsFile:
    def test_comments_and_blank_lines_ignored(self, mocker, tmp_path):
        _hosts_file(mocker, tmp_path, "# a comment about hynote.ai\n\n   \n127.0.0.1 localhost\n")
        d = dp._p_hosts_file(SLOTS)
        assert d["readable"] is True
        assert d["matches"] == []

    def test_blocking_line_matches_with_line_no_and_lowercased_names(self, mocker, tmp_path):
        f = _hosts_file(mocker, tmp_path, "# header\n127.0.0.1 localhost\n0.0.0.0 Hynote.AI www.hynote.ai  # block\n")
        d = dp._p_hosts_file(SLOTS)
        assert d["path"] == str(f)
        assert d["matches"] == [{"line_no": 3, "ip": "0.0.0.0", "names": ["hynote.ai", "www.hynote.ai"]}]

    def test_match_is_case_insensitive_and_ignores_trailing_dot(self, mocker, tmp_path):
        _hosts_file(mocker, tmp_path, "10.0.0.5 HYNOTE.AI.\n")
        d = dp._p_hosts_file({"target_host": "HyNote.ai."})
        assert [m["line_no"] for m in d["matches"]] == [1]

    def test_substring_name_does_not_match(self, mocker, tmp_path):
        _hosts_file(mocker, tmp_path, "0.0.0.0 myhynote.ai\n0.0.0.0 hynote.ai.evil.com\n")
        assert dp._p_hosts_file(SLOTS)["matches"] == []

    def test_every_matching_line_is_reported(self, mocker, tmp_path):
        _hosts_file(mocker, tmp_path, "1.1.1.1 hynote.ai\n2.2.2.2 other\n::1 hynote.ai\n")
        d = dp._p_hosts_file(SLOTS)
        assert [(m["line_no"], m["ip"]) for m in d["matches"]] == [(1, "1.1.1.1"), (3, "::1")]

    def test_line_with_only_an_ip_is_skipped(self, mocker, tmp_path):
        _hosts_file(mocker, tmp_path, "1.2.3.4\n1.2.3.4 # nothing\n")
        assert dp._p_hosts_file(SLOTS)["matches"] == []

    def test_missing_file_is_unreadable(self, mocker, tmp_path):
        missing = tmp_path / "nope"
        mocker.patch.object(dp, "HOSTS_PATH", str(missing))
        d = dp._p_hosts_file(SLOTS)
        assert d == {"path": str(missing), "readable": False, "matches": []}

    def test_non_utf8_byte_does_not_raise(self, mocker, tmp_path):
        _hosts_file(mocker, tmp_path, b"127.0.0.1 caf\xe9\n0.0.0.0 hynote.ai\n")
        d = dp._p_hosts_file(SLOTS)
        assert d["readable"] is True
        assert [m["line_no"] for m in d["matches"]] == [2]

    def test_default_path_is_the_system32_hosts_file(self):
        assert dp.HOSTS_PATH.lower().endswith(os.path.join("system32", "drivers", "etc", "hosts"))


_IFACES = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
_TCPIP = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
_DNSCACHE = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"


def _patch_registry(mocker, subkeys=(), values=None):
    """Patch the two registry helpers; ``values`` maps (hive, path) -> dict."""
    values = values or {}
    mocker.patch.object(dp, "_reg_subkeys", return_value=list(subkeys))
    return mocker.patch.object(dp, "_reg_values", side_effect=lambda hive, path: dict(values.get((hive, path), {})))


class TestClientConfig:
    HKLM = winreg.HKEY_LOCAL_MACHINE

    def test_splits_commas_and_whitespace_and_omits_empty_adapters(self, mocker):
        _patch_registry(
            mocker,
            subkeys=["{G1}", "{G2}", "{G3}"],
            values={
                (self.HKLM, _IFACES + "\\{G1}"): {"NameServer": "1.1.1.1,8.8.8.8"},
                (self.HKLM, _IFACES + "\\{G2}"): {"DhcpNameServer": "192.168.1.1 192.168.1.2"},
                (self.HKLM, _IFACES + "\\{G3}"): {"NameServer": "", "DhcpNameServer": ""},
                (self.HKLM, _TCPIP): {"SearchList": "corp.local,example.com"},
                (self.HKLM, _DNSCACHE): {"EnableAutoDoh": 2},
            },
        )
        d = dp._p_client_config({})
        assert d["adapters"] == [
            {"guid": "{G1}", "dns_servers": ["1.1.1.1", "8.8.8.8"]},
            {"guid": "{G2}", "dns_servers": ["192.168.1.1", "192.168.1.2"]},
        ]
        assert d["search_list"] == ["corp.local", "example.com"]
        assert d["enable_auto_doh"] == 2

    def test_static_servers_win_over_dhcp(self, mocker):
        _patch_registry(
            mocker,
            subkeys=["{G1}"],
            values={(self.HKLM, _IFACES + "\\{G1}"): {"NameServer": "9.9.9.9", "DhcpNameServer": "192.168.1.1"}},
        )
        assert dp._p_client_config({})["adapters"][0]["dns_servers"] == ["9.9.9.9"]

    def test_multi_sz_list_values_accepted(self, mocker):
        _patch_registry(
            mocker,
            subkeys=["{G1}"],
            values={
                (self.HKLM, _IFACES + "\\{G1}"): {"NameServer": ["1.1.1.1", "8.8.8.8,9.9.9.9"]},
                (self.HKLM, _TCPIP): {"SearchList": ["a.local", "b.local"]},
            },
        )
        d = dp._p_client_config({})
        assert d["adapters"][0]["dns_servers"] == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        assert d["search_list"] == ["a.local", "b.local"]

    def test_missing_keys_give_empty_results(self, mocker):
        _patch_registry(mocker)
        assert dp._p_client_config({}) == {"adapters": [], "search_list": [], "enable_auto_doh": None}

    def test_non_text_value_is_ignored(self, mocker):
        _patch_registry(
            mocker,
            subkeys=["{G1}"],
            values={(self.HKLM, _IFACES + "\\{G1}"): {"NameServer": 5}, (self.HKLM, _TCPIP): {"SearchList": None}},
        )
        d = dp._p_client_config({})
        assert d["adapters"] == []
        assert d["search_list"] == []

    def test_enumerates_the_interfaces_key(self, mocker):
        _patch_registry(mocker)
        dp._p_client_config({})
        dp._reg_subkeys.assert_called_once_with(self.HKLM, _IFACES)


def _winhttp_blob(flags: int, proxy: str = "", bypass: str = "") -> bytes:
    p, b = proxy.encode("ascii"), bypass.encode("ascii")
    return struct.pack("<IIII", 0x28, 0, flags, len(p)) + p + struct.pack("<I", len(b)) + b


_INET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_CONNS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"


class TestParseWinhttpBlob:
    def test_direct_access(self):
        assert dp._parse_winhttp_blob(_winhttp_blob(1)) == {"direct": True, "proxy_server": "", "bypass": ""}

    def test_proxy_and_bypass(self):
        d = dp._parse_winhttp_blob(_winhttp_blob(3, "proxy:8080", "<local>;*.corp"))
        assert d == {"direct": False, "proxy_server": "proxy:8080", "bypass": "<local>;*.corp"}

    def test_trailing_bytes_after_bypass_are_ignored(self):
        assert dp._parse_winhttp_blob(_winhttp_blob(1) + b"\x00" * 4)["direct"] is True

    @pytest.mark.parametrize("cut", [0, 8, 15, 20, 28, 30])
    def test_truncated_blob_is_a_parse_error(self, cut):
        blob = _winhttp_blob(3, "proxy:8080", "<local>")[:cut]
        d = dp._parse_winhttp_blob(blob)
        assert set(d) == {"parse_error"}
        assert d["parse_error"]

    def test_non_ascii_proxy_is_a_parse_error(self):
        blob = struct.pack("<IIII", 0x28, 0, 3, 2) + b"\xff\xfe" + struct.pack("<I", 0)
        assert "parse_error" in dp._parse_winhttp_blob(blob)


class TestProxyConfig:
    HKCU = winreg.HKEY_CURRENT_USER
    HKLM = winreg.HKEY_LOCAL_MACHINE

    @pytest.fixture(autouse=True)
    def _clean_env(self, mocker):
        mocker.patch.dict(os.environ)
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy"):
            os.environ.pop(k, None)

    def test_reads_wininet_winhttp_and_env(self, mocker):
        _patch_registry(
            mocker,
            values={
                (self.HKCU, _INET): {
                    "ProxyEnable": 1,
                    "ProxyServer": "proxy.corp:3128",
                    "ProxyOverride": "<local>",
                    "AutoConfigURL": "http://wpad/wpad.dat",
                    "AutoDetect": 0,
                },
                (self.HKLM, _CONNS): {"WinHttpSettings": _winhttp_blob(3, "proxy:8080", "*.corp")},
            },
        )
        mocker.patch.dict(os.environ, {"HTTP_PROXY": "http://envproxy:1", "NO_PROXY": "localhost"})
        d = dp._p_proxy_config({})
        assert d["wininet"] == {
            "proxy_enable": 1,
            "proxy_server": "proxy.corp:3128",
            "proxy_override": "<local>",
            "auto_config_url": "http://wpad/wpad.dat",
            "auto_detect": 0,
        }
        assert d["winhttp"] == {"direct": False, "proxy_server": "proxy:8080", "bypass": "*.corp"}
        assert d["env"] == {"HTTP_PROXY": "http://envproxy:1", "HTTPS_PROXY": None, "NO_PROXY": "localhost"}

    def test_missing_registry_keys_give_none_and_empty(self, mocker):
        _patch_registry(mocker)
        d = dp._p_proxy_config({})
        assert d["wininet"] == {
            "proxy_enable": None,
            "proxy_server": None,
            "proxy_override": None,
            "auto_config_url": None,
            "auto_detect": None,
        }
        assert d["winhttp"] == {}
        assert d["env"] == {"HTTP_PROXY": None, "HTTPS_PROXY": None, "NO_PROXY": None}

    def test_non_bytes_winhttp_value_is_ignored(self, mocker):
        _patch_registry(mocker, values={(self.HKLM, _CONNS): {"WinHttpSettings": "oops"}})
        assert dp._p_proxy_config({})["winhttp"] == {}

    def test_corrupt_winhttp_blob_reports_parse_error(self, mocker):
        _patch_registry(mocker, values={(self.HKLM, _CONNS): {"WinHttpSettings": b"\x01\x02"}})
        assert "parse_error" in dp._p_proxy_config({})["winhttp"]

    def test_lowercase_env_var_is_used_when_upper_is_unset(self, mocker):
        _patch_registry(mocker)
        mocker.patch.object(dp.os, "environ", {"https_proxy": "http://lower:9"})
        assert dp._p_proxy_config({})["env"]["HTTPS_PROXY"] == "http://lower:9"

    def test_uppercase_env_var_is_preferred(self, mocker):
        _patch_registry(mocker)
        mocker.patch.object(dp.os, "environ", {"HTTP_PROXY": "http://upper:1", "http_proxy": "http://lower:2"})
        assert dp._p_proxy_config({})["env"]["HTTP_PROXY"] == "http://upper:1"


class TestScrubUserinfo:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("http://alice:s3cret@proxy:8080", "http://<credentials>@proxy:8080"),
            ("alice:s3cret@proxy:8080", "<credentials>@proxy:8080"),
            ("http=bob:pw@a:1;https=b:2", "http=<credentials>@a:1;https=b:2"),
            ("http://alice@proxy:8080", "http://<credentials>@proxy:8080"),
            ("proxy:8080", "proxy:8080"),
            ("http://wpad/wpad.dat", "http://wpad/wpad.dat"),
            (None, None),
        ],
    )
    def test_scrub(self, raw, expected):
        assert dp._scrub_userinfo(raw) == expected

    def test_password_containing_at_sign_does_not_leak(self):
        assert "s3cret" not in dp._scrub_userinfo("http://alice:p@s3cret@proxy:8080")

    @pytest.mark.parametrize(
        ("raw", "secret", "expected"),
        [
            ("http://svc:dGVzdA==@proxy:3128", "dGVzdA", "http://<credentials>@proxy:3128"),
            ("svc:abc=@proxy", "abc", "<credentials>@proxy"),
            ("http://user:ab=cd@proxy", "ab=cd", "http://<credentials>@proxy"),
            ("http://user:pa/ss@proxy", "pa/ss", "http://<credentials>@proxy"),
            ("http://user:p;w@proxy", "p;w", "http://<credentials>@proxy"),
            ("http=u:p=@h:1;https=b:2", "u:p", "http=<credentials>@h:1;https=b:2"),
            ("http=u:pw@a:1;https=v:qq@b:2", "pw", "http=<credentials>@a:1;https=<credentials>@b:2"),
            ("http=http://u:pw@a:1 https=b:2", "pw", "http=http://<credentials>@a:1 https=b:2"),
        ],
    )
    def test_awkward_passwords_are_fully_scrubbed(self, raw, secret, expected):
        out = dp._scrub_userinfo(raw)
        assert secret not in out
        assert out == expected

    @pytest.mark.parametrize("raw", ["proxy:8080", "http=a:1;https=b:2", "http://proxy:3128/", "a:1;b:2"])
    def test_values_without_userinfo_are_unchanged(self, raw):
        assert dp._scrub_userinfo(raw) == raw


class TestScrubPacUrl:
    def test_query_and_fragment_stripped_path_kept(self):
        out = dp._scrub_pac_url("http://pac.example/dir/x.pac?token=abc123#frag")
        assert out == "http://pac.example/dir/x.pac"

    def test_fragment_only_stripped(self):
        assert dp._scrub_pac_url("http://pac.example/x.pac#frag") == "http://pac.example/x.pac"

    def test_userinfo_scrubbed_too(self):
        out = dp._scrub_pac_url("http://carol:s3cret@pac.example/x.pac?token=abc123")
        assert out == "http://<credentials>@pac.example/x.pac"

    def test_at_sign_only_in_query_is_over_redacted_not_leaked(self):
        out = dp._scrub_pac_url("http://pac.example/x.pac?mail=a@b.example")
        assert "mail" not in out
        assert "a@" not in out

    def test_password_with_question_mark_does_not_leak(self):
        assert "s3cret" not in dp._scrub_pac_url("http://carol:s3?cret@pac.example/x.pac")

    def test_plain_url_and_non_string_pass_through(self):
        assert dp._scrub_pac_url("http://wpad/wpad.dat") == "http://wpad/wpad.dat"
        assert dp._scrub_pac_url(None) is None

    def test_non_string_passes_through(self):
        assert dp._scrub_userinfo(1) == 1


class TestProxyConfigCredentials:
    def test_no_secret_anywhere_in_the_payload(self, mocker):
        _patch_registry(
            mocker,
            values={
                (winreg.HKEY_CURRENT_USER, _INET): {
                    "ProxyServer": "http=bob:s3cret@a:1;https=b:2",
                    "AutoConfigURL": "http://carol:s3cret@wpad/wpad.dat?token=abc123#frag",
                },
                (winreg.HKEY_LOCAL_MACHINE, _CONNS): {"WinHttpSettings": _winhttp_blob(3, "dave:s3cret@proxy:8080")},
            },
        )
        mocker.patch.object(
            dp.os, "environ", {"HTTP_PROXY": "http://erin:s3cret@e:1", "https_proxy": "http://frank:s3cret@f:2"}
        )
        d = dp._p_proxy_config({})
        assert "s3cret" not in json.dumps(d)
        assert "abc123" not in json.dumps(d)
        assert d["wininet"]["proxy_server"] == "http=<credentials>@a:1;https=b:2"
        assert d["wininet"]["auto_config_url"] == "http://<credentials>@wpad/wpad.dat"
        assert d["winhttp"]["proxy_server"] == "<credentials>@proxy:8080"
        assert d["env"]["HTTP_PROXY"] == "http://<credentials>@e:1"
        assert d["env"]["HTTPS_PROXY"] == "http://<credentials>@f:2"


class TestRegHelpers:
    def test_reg_values_enumerates_until_oserror(self, mocker):
        mocker.patch.object(dp.winreg, "OpenKey")
        mocker.patch.object(
            dp.winreg,
            "EnumValue",
            side_effect=[("A", 1, winreg.REG_DWORD), ("B", "x", winreg.REG_SZ), OSError(259, "no more")],
        )
        assert dp._reg_values(winreg.HKEY_LOCAL_MACHINE, "Some\\Path") == {"A": 1, "B": "x"}

    def test_reg_values_missing_key_is_empty(self, mocker):
        mocker.patch.object(dp.winreg, "OpenKey", side_effect=FileNotFoundError(2, "nope"))
        assert dp._reg_values(winreg.HKEY_LOCAL_MACHINE, "Missing") == {}

    def test_reg_subkeys_enumerates_until_oserror(self, mocker):
        mocker.patch.object(dp.winreg, "OpenKey")
        mocker.patch.object(dp.winreg, "EnumKey", side_effect=["{G1}", "{G2}", OSError(259, "no more")])
        assert dp._reg_subkeys(winreg.HKEY_LOCAL_MACHINE, "Some\\Path") == ["{G1}", "{G2}"]

    def test_reg_subkeys_missing_key_is_empty(self, mocker):
        mocker.patch.object(dp.winreg, "OpenKey", side_effect=FileNotFoundError(2, "nope"))
        assert dp._reg_subkeys(winreg.HKEY_LOCAL_MACHINE, "Missing") == []


class TestLocalConfigRegistration:
    @pytest.mark.parametrize(
        ("key", "label", "needs", "redact", "fn"),
        [
            ("dns.hosts_file", "Check the hosts file", ("target_host",), ("username",), "_p_hosts_file"),
            ("dns.client_config", "This PC's DNS settings", (), ("username", "mac"), "_p_client_config"),
            ("net.proxy_config", "Proxy settings", (), ("username",), "_p_proxy_config"),
        ],
    )
    def test_registered_with_contract_metadata(self, key, label, needs, redact, fn):
        p = _REGISTERED[key]
        assert p.label == label
        assert p.category == "network"
        assert p.needs == needs
        assert p.redact == redact
        assert p.fn is getattr(dp, fn)


# ── Connectivity probes (control domain, gateway, TCP, TLS, traceroute) ──────


_INFO = (2, 1, 6, "", ("23.1.2.3", 443))


def _fake_net(mocker, *, infos=None, resolve_error=None, connect_error=None):
    """Patch ``getaddrinfo`` and ``socket.socket``; return ``(getaddrinfo mock, socket factory mock)``."""
    gai = mocker.patch.object(
        dp.socket, "getaddrinfo", return_value=[_INFO] if infos is None else infos, side_effect=resolve_error
    )
    factory = mocker.patch.object(dp.socket, "socket")
    if connect_error is not None:
        factory.return_value.connect.side_effect = connect_error
    return gai, factory


_V4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("23.1.2.3", 443))
_V4B = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("23.9.9.9", 443))
_V6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2600:1406::1", 443, 0, 0))


def _refuse(*addresses):
    """connect() side effect that refuses the given addresses and accepts every other."""

    def connect(sockaddr):
        if sockaddr[0] in addresses:
            raise ConnectionRefusedError(10061, f"refused {sockaddr[0]}")

    return connect


class TestControlDomain:
    def test_constant(self):
        assert dp.CONTROL_DOMAIN == "www.microsoft.com"

    def test_resolved_and_connected(self, mocker):
        gai, factory = _fake_net(mocker)
        d = dp._p_control_domain({})
        assert d["host"] == "www.microsoft.com"
        assert d["resolved"] is True
        assert d["address"] == "23.1.2.3"
        assert d["connected"] is True
        assert isinstance(d["connect_ms"], float)
        assert d["error"] is None
        assert [(a["address"], a["family"], a["connected"], a["error"]) for a in d["attempts"]] == [
            ("23.1.2.3", "ipv4", True, None)
        ]
        assert isinstance(d["attempts"][0]["ms"], float)
        gai.assert_called_once_with("www.microsoft.com", 443, type=socket.SOCK_STREAM)
        factory.assert_called_once_with(2, 1, 6)
        sock = factory.return_value
        sock.settimeout.assert_called_once_with(dp._CONTROL_CONNECT_TIMEOUT_S)
        sock.connect.assert_called_once_with(("23.1.2.3", 443))
        sock.close.assert_called_once()

    def test_resolve_failure_skips_connect(self, mocker):
        gai, factory = _fake_net(mocker, resolve_error=socket.gaierror(11001, "getaddrinfo failed"))
        d = dp._p_control_domain({})
        assert d["resolved"] is False
        assert d["address"] is None
        assert d["connected"] is False
        assert d["connect_ms"] is None
        assert d["attempts"] == []
        assert "getaddrinfo failed" in d["error"]
        gai.assert_called_once()
        factory.assert_not_called()

    def test_empty_resolution_is_a_resolve_failure(self, mocker):
        _, factory = _fake_net(mocker, infos=[])
        d = dp._p_control_domain({})
        assert d["resolved"] is False
        assert d["error"] == "no addresses returned"
        factory.assert_not_called()

    def test_ipv4_connect_skips_ipv6(self, mocker):
        _, factory = _fake_net(mocker, infos=[_V6, _V4])
        d = dp._p_control_domain({})
        assert d["address"] == "23.1.2.3"
        factory.return_value.connect.assert_called_once_with(("23.1.2.3", 443))

    def test_ipv4_failure_falls_back_to_ipv6(self, mocker):
        gai, factory = _fake_net(mocker, infos=[_V6, _V4])
        factory.return_value.connect.side_effect = _refuse("23.1.2.3")
        d = dp._p_control_domain({})
        assert d["connected"] is True
        assert d["address"] == "2600:1406::1"
        assert d["error"] is None
        assert [(a["address"], a["family"], a["connected"]) for a in d["attempts"]] == [
            ("23.1.2.3", "ipv4", False),
            ("2600:1406::1", "ipv6", True),
        ]
        assert "refused" in d["attempts"][0]["error"]
        assert d["connect_ms"] == d["attempts"][1]["ms"]
        gai.assert_called_once()

    def test_both_families_fail_reports_the_first_tried(self, mocker):
        _, factory = _fake_net(mocker, infos=[_V4, _V6])
        factory.return_value.connect.side_effect = _refuse("23.1.2.3", "2600:1406::1")
        d = dp._p_control_domain({})
        assert d["connected"] is False
        assert d["address"] == "23.1.2.3"
        assert d["connect_ms"] is None
        assert "refused 23.1.2.3" in d["error"]
        assert [a["connected"] for a in d["attempts"]] == [False, False]
        assert factory.return_value.close.call_count == 2

    def test_tries_only_the_first_address_of_each_family(self, mocker):
        _, factory = _fake_net(mocker, infos=[_V4, _V4B], connect_error=TimeoutError())
        d = dp._p_control_domain({})
        assert d["address"] == "23.1.2.3"
        assert d["connected"] is False
        factory.return_value.connect.assert_called_once_with(("23.1.2.3", 443))

    def test_connect_timeout_sets_error_and_closes_socket(self, mocker):
        _, factory = _fake_net(mocker, connect_error=TimeoutError())
        d = dp._p_control_domain({})
        assert d["resolved"] is True
        assert d["connected"] is False
        assert d["connect_ms"] is None
        assert d["error"]  # a bare TimeoutError has an empty str(); the probe must still say something
        factory.return_value.close.assert_called_once()

    def test_two_attempts_leave_room_for_the_lookup(self):
        assert _REGISTERED["net.control_domain"].timeout_s - 2 * dp._CONTROL_CONNECT_TIMEOUT_S >= 2


def _gateway_registry(mocker, ifaces: dict):
    """Patch the registry helpers; ``ifaces`` maps guid -> its Interfaces-key values."""
    hklm = winreg.HKEY_LOCAL_MACHINE
    values = {(hklm, _IFACES + "\\" + guid): vals for guid, vals in ifaces.items()}
    return _patch_registry(mocker, subkeys=list(ifaces), values=values)


def _ping(mocker, stdout="", returncode=0, side_effect=None):
    run = mocker.patch.object(dp.subprocess, "run", side_effect=side_effect)
    if side_effect is None:
        run.return_value.stdout = stdout
        run.return_value.returncode = returncode
        run.return_value.stderr = ""
    return run


_PING_OK = "Reply from 192.168.1.1: bytes=32 time=3ms TTL=64"


class TestGateway:
    def test_dedupes_across_static_and_dhcp_values(self, mocker):
        _gateway_registry(
            mocker,
            {
                "{G1}": {"DefaultGateway": ["192.168.1.1"]},
                "{G2}": {"DhcpDefaultGateway": ["192.168.1.1"]},
            },
        )
        _ping(mocker, _PING_OK)
        assert dp._p_gateway({})["gateways"] == ["192.168.1.1"]

    def test_str_value_empty_strings_and_order(self, mocker):
        _gateway_registry(
            mocker,
            {
                "{G1}": {"DefaultGateway": [""], "DhcpDefaultGateway": "10.0.0.1"},
                "{G2}": {"DefaultGateway": ["10.0.0.2", "10.0.0.1"]},
            },
        )
        run = _ping(mocker, _PING_OK)
        d = dp._p_gateway({})
        assert d["gateways"] == ["10.0.0.1", "10.0.0.2"]
        assert [c.args[0][-1] for c in run.call_args_list] == ["10.0.0.1", "10.0.0.2"]

    def test_happy_path_parses_rtt(self, mocker):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["192.168.1.1"]}})
        _ping(mocker, _PING_OK)
        d = dp._p_gateway({})
        assert d == {
            "gateways": ["192.168.1.1"],
            "reachable": True,
            "rtt_ms": 3.0,
            "results": [{"gateway": "192.168.1.1", "reachable": True, "rtt_ms": 3.0}],
        }

    def test_sub_millisecond_rtt(self, mocker):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["192.168.1.1"]}})
        _ping(mocker, "Reply from 192.168.1.1: bytes=32 time<1ms TTL=64")
        d = dp._p_gateway({})
        assert d["reachable"] is True
        assert d["rtt_ms"] == 0.5

    def test_unparseable_rtt_is_none_but_still_reachable(self, mocker):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["192.168.1.1"]}})
        _ping(mocker, "Antwort von 192.168.1.1: Bytes=32 Zeit=3ms TTL=64")
        d = dp._p_gateway({})
        assert d["reachable"] is True
        assert d["rtt_ms"] is None

    def test_nonzero_returncode_is_unreachable(self, mocker):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["192.168.1.1"]}})
        _ping(mocker, "Request timed out.", returncode=1)
        d = dp._p_gateway({})
        assert d["reachable"] is False
        assert d["rtt_ms"] is None

    def test_unreachable_reply_without_ttl_is_unreachable(self, mocker):
        # "Destination host unreachable" replies can still exit 0 on Windows.
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["192.168.1.1"]}})
        _ping(mocker, "Reply from 192.168.1.50: Destination host unreachable.", returncode=0)
        assert dp._p_gateway({})["reachable"] is False

    def test_timeout_is_unreachable(self, mocker):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["192.168.1.1"]}})
        _ping(mocker, side_effect=dp.subprocess.TimeoutExpired(cmd="ping", timeout=5))
        d = dp._p_gateway({})
        assert d["reachable"] is False
        assert d["rtt_ms"] is None
        assert d["gateways"] == ["192.168.1.1"]

    def test_missing_executable_is_untested_not_unreachable(self, mocker):
        # Not being able to launch ping means "could not test"; reporting False would feed a false dead-gateway verdict.
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["192.168.1.1"]}})
        _ping(mocker, side_effect=FileNotFoundError("ping"))
        d = dp._p_gateway({})
        assert d["gateways"] == ["192.168.1.1"]
        assert d["reachable"] is None
        assert d["rtt_ms"] is None
        assert "ping" in d["error"]
        assert d["results"] == [{"gateway": "192.168.1.1", "reachable": None, "rtt_ms": None}]

    def test_no_gateway_means_unknown_and_no_subprocess(self, mocker):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": [], "DhcpDefaultGateway": ""}})
        run = _ping(mocker)
        d = dp._p_gateway({})
        assert d == {"gateways": [], "reachable": None, "rtt_ms": None, "results": []}
        run.assert_not_called()

    def test_command_content(self, mocker):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["192.168.1.1"]}})
        run = _ping(mocker, _PING_OK)
        dp._p_gateway({})
        assert run.call_args.args[0] == ["ping", "-n", "1", "-w", "1000", "192.168.1.1"]
        assert "shell" not in run.call_args.kwargs
        assert run.call_args.kwargs["timeout"] == 5
        assert run.call_args.kwargs["capture_output"] is True
        assert run.call_args.kwargs["text"] is True
        assert run.call_args.kwargs["creationflags"] == dp._NO_WINDOW

    @pytest.mark.parametrize(
        "bad", ["192.168.1.1 & calc", "192.168.1.1;calc", "not-an-ip", "fe80::1%eth0", "0.0.0.0", "::", 5, None]
    )
    def test_invalid_gateway_is_dropped_and_never_reaches_ping(self, mocker, bad):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": [bad]}, "{G2}": {"DhcpDefaultGateway": "192.168.1.1"}})
        run = _ping(mocker, _PING_OK)
        d = dp._p_gateway({})
        assert d["gateways"] == ["192.168.1.1"]
        assert all(str(bad) not in arg for arg in run.call_args.args[0])

    def test_only_invalid_gateway_means_no_ping(self, mocker):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["192.168.1.1 & calc"]}})
        run = _ping(mocker)
        assert dp._p_gateway({})["reachable"] is None
        run.assert_not_called()

    @staticmethod
    def _four_gateways(mocker):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]}})

    @staticmethod
    def _replies(by_gateway: dict):
        """subprocess.run stand-in: ``by_gateway`` maps gateway -> stdout, or an exception to raise."""

        def run(argv, **kw):
            outcome = by_gateway.get(argv[-1], "Request timed out.")
            if isinstance(outcome, BaseException):
                raise outcome
            reply = types.SimpleNamespace(stdout=outcome, stderr="", returncode=0 if "TTL=" in outcome else 1)
            return reply

        return run

    def test_pings_at_most_three_gateways(self, mocker):
        self._four_gateways(mocker)
        run = _ping(mocker, side_effect=self._replies({}))
        d = dp._p_gateway({})
        assert d["gateways"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        assert [c.args[0][-1] for c in run.call_args_list] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        assert d["reachable"] is False
        assert [r["gateway"] for r in d["results"]] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        assert all(c.args[0][:5] == ["ping", "-n", "1", "-w", "1000"] for c in run.call_args_list)
        assert all(c.kwargs["timeout"] == 5 for c in run.call_args_list)

    def test_any_answering_gateway_is_reachable_with_its_rtt(self, mocker):
        self._four_gateways(mocker)
        _ping(mocker, side_effect=self._replies({"10.0.0.2": "Reply from 10.0.0.2: bytes=32 time=7ms TTL=64"}))
        d = dp._p_gateway({})
        assert d["reachable"] is True
        assert d["rtt_ms"] == 7.0
        assert d["results"] == [
            {"gateway": "10.0.0.1", "reachable": False, "rtt_ms": None},
            {"gateway": "10.0.0.2", "reachable": True, "rtt_ms": 7.0},
            {"gateway": "10.0.0.3", "reachable": False, "rtt_ms": None},
        ]

    def test_rtt_is_the_first_reachable_gateways(self, mocker):
        self._four_gateways(mocker)
        _ping(
            mocker,
            side_effect=self._replies(
                {
                    "10.0.0.2": "Reply from 10.0.0.2: bytes=32 time=7ms TTL=64",
                    "10.0.0.3": "Reply from 10.0.0.3: bytes=32 time=2ms TTL=64",
                }
            ),
        )
        assert dp._p_gateway({})["rtt_ms"] == 7.0

    def test_a_hung_ping_counts_as_unreachable_and_the_next_is_tried(self, mocker):
        self._four_gateways(mocker)
        _ping(
            mocker,
            side_effect=self._replies(
                {
                    "10.0.0.1": dp.subprocess.TimeoutExpired(cmd="ping", timeout=5),
                    "10.0.0.2": "Reply from 10.0.0.2: bytes=32 time<1ms TTL=64",
                }
            ),
        )
        d = dp._p_gateway({})
        assert d["results"][0] == {"gateway": "10.0.0.1", "reachable": False, "rtt_ms": None}
        assert d["reachable"] is True
        assert d["rtt_ms"] == 0.5

    def test_ping_that_cannot_launch_stops_and_is_untested(self, mocker):
        self._four_gateways(mocker)
        run = _ping(mocker, side_effect=FileNotFoundError("ping"))
        d = dp._p_gateway({})
        assert run.call_count == 1
        assert d["reachable"] is None
        assert d["results"] == [{"gateway": "10.0.0.1", "reachable": None, "rtt_ms": None}]

    def test_out_of_budget_gateways_are_untested_not_unreachable(self, mocker):
        self._four_gateways(mocker)
        run = _ping(mocker, side_effect=self._replies({}))
        # Clock: start, before ping 1, before ping 2 (budget nearly spent).
        mocker.patch.object(
            dp, "time", mocker.Mock(monotonic=mocker.Mock(side_effect=[0.0, 0.0, dp._GATEWAY_BUDGET_S - 0.5]))
        )
        d = dp._p_gateway({})
        assert run.call_count == 1
        assert d["results"] == [{"gateway": "10.0.0.1", "reachable": False, "rtt_ms": None}]
        assert d["reachable"] is None  # not every gateway was tested, so this is not "dead"

    def test_ping_timeout_is_clamped_to_the_remaining_budget(self, mocker):
        self._four_gateways(mocker)
        run = _ping(mocker, side_effect=self._replies({}))
        mocker.patch.object(
            dp, "time", mocker.Mock(monotonic=mocker.Mock(side_effect=[0.0, 0.0, 0.0, dp._GATEWAY_BUDGET_S - 2.0]))
        )
        dp._p_gateway({})
        assert [c.kwargs["timeout"] for c in run.call_args_list] == [5, 5, 2.0]

    def test_budget_fits_the_probe_timeout(self):
        assert _REGISTERED["net.gateway"].timeout_s > dp._GATEWAY_BUDGET_S

    def test_ipv6_gateway_is_kept(self, mocker):
        _gateway_registry(mocker, {"{G1}": {"DefaultGateway": ["fe80::1"]}})
        _ping(mocker, "Reply from fe80::1: time<1ms")
        assert dp._p_gateway({})["gateways"] == ["fe80::1"]


class TestTcpConnect:
    def test_both_ports_connect_with_one_resolution(self, mocker):
        gai, factory = _fake_net(mocker)
        d = dp._p_tcp_connect(SLOTS)
        assert [r["port"] for r in d["results"]] == [443, 80]
        assert all(
            r["connected"] is True and isinstance(r["ms"], float) and r["error"] is None and r["address"] == "23.1.2.3"
            for r in d["results"]
        )
        assert all(len(r["attempts"]) == 1 for r in d["results"])
        gai.assert_called_once_with("hynote.ai", 443, type=socket.SOCK_STREAM)
        assert [c.args for c in factory.call_args_list] == [(2, 1, 6), (2, 1, 6)]
        sock = factory.return_value
        t = dp._TCP_CONNECT_TIMEOUT_S
        assert [c.args for c in sock.settimeout.call_args_list] == [(t,), (t,)]
        assert [c.args for c in sock.connect.call_args_list] == [(("23.1.2.3", 443),), (("23.1.2.3", 80),)]
        assert sock.close.call_count == 2

    def test_ipv6_sockaddr_keeps_flow_and_scope(self, mocker):
        v6 = (socket.AF_INET6, 1, 6, "", ("2606:4700::1", 443, 0, 0))
        _, factory = _fake_net(mocker, infos=[v6])
        d = dp._p_tcp_connect(SLOTS)
        assert d["results"][0]["address"] == "2606:4700::1"
        assert d["results"][0]["attempts"][0]["family"] == "ipv6"
        assert [c.args for c in factory.return_value.connect.call_args_list] == [
            (("2606:4700::1", 443, 0, 0),),
            (("2606:4700::1", 80, 0, 0),),
        ]

    def test_ipv4_failure_falls_back_to_ipv6_per_port(self, mocker):
        _, factory = _fake_net(mocker, infos=[_V4, _V6])
        factory.return_value.connect.side_effect = _refuse("23.1.2.3")
        d = dp._p_tcp_connect(SLOTS)
        for r in d["results"]:
            assert r["connected"] is True
            assert r["address"] == "2600:1406::1"
            assert r["error"] is None
            assert [(a["family"], a["connected"]) for a in r["attempts"]] == [("ipv4", False), ("ipv6", True)]
            assert r["ms"] == r["attempts"][1]["ms"]
        assert [c.args[0][:2] for c in factory.return_value.connect.call_args_list] == [
            ("23.1.2.3", 443),
            ("2600:1406::1", 443),
            ("23.1.2.3", 80),
            ("2600:1406::1", 80),
        ]

    def test_ipv4_success_does_not_try_ipv6(self, mocker):
        _, factory = _fake_net(mocker, infos=[_V6, _V4])
        d = dp._p_tcp_connect(SLOTS)
        assert [r["address"] for r in d["results"]] == ["23.1.2.3", "23.1.2.3"]
        assert factory.return_value.connect.call_count == 2

    def test_port_failing_on_both_families_reports_the_last_tried(self, mocker):
        def refuse_443(sockaddr):
            if sockaddr[1] == 443:
                raise ConnectionRefusedError(10061, f"refused {sockaddr[0]}")

        _, factory = _fake_net(mocker, infos=[_V4, _V6])
        factory.return_value.connect.side_effect = refuse_443
        by_port = {r["port"]: r for r in dp._p_tcp_connect(SLOTS)["results"]}
        assert by_port[443]["connected"] is False
        assert by_port[443]["address"] == "2600:1406::1"
        assert "refused 2600:1406::1" in by_port[443]["error"]
        assert by_port[443]["ms"] is None
        assert len(by_port[443]["attempts"]) == 2
        assert by_port[80]["connected"] is True
        assert by_port[80]["address"] == "23.1.2.3"

    def test_per_port_results_when_one_fails(self, mocker):
        def refuse_443(sockaddr):
            if sockaddr[1] == 443:
                raise ConnectionRefusedError(10061, "refused")

        _, factory = _fake_net(mocker)
        factory.return_value.connect.side_effect = refuse_443
        by_port = {r["port"]: r for r in dp._p_tcp_connect(SLOTS)["results"]}
        assert by_port[443]["connected"] is False
        assert by_port[443]["ms"] is None
        assert "refused" in by_port[443]["error"]
        assert by_port[443]["address"] == "23.1.2.3"
        assert by_port[80]["connected"] is True
        assert factory.return_value.close.call_count == 2  # the failed socket is closed too

    def test_timeout_has_nonempty_error(self, mocker):
        _fake_net(mocker, connect_error=TimeoutError())
        r = dp._p_tcp_connect(SLOTS)["results"][0]
        assert r["connected"] is False
        assert r["error"]

    def test_resolution_failure_fails_both_ports_without_connecting(self, mocker):
        gai, factory = _fake_net(mocker, resolve_error=socket.gaierror(11001, "getaddrinfo failed"))
        d = dp._p_tcp_connect(SLOTS)
        assert [(r["port"], r["connected"], r["address"], r["ms"], r["attempts"]) for r in d["results"]] == [
            (443, False, None, None, []),
            (80, False, None, None, []),
        ]
        assert all("getaddrinfo failed" in r["error"] for r in d["results"])
        gai.assert_called_once()
        factory.assert_not_called()

    def test_four_attempts_leave_room_for_the_lookup(self):
        assert _REGISTERED["net.tcp_connect"].timeout_s - 4 * dp._TCP_CONNECT_TIMEOUT_S >= 2


def _fake_tls(mocker, *, version="TLSv1.3", cert=None, wrap_error=None):
    """Patch ssl.create_default_context, getaddrinfo and socket.socket; return (ctx, raw_sock, tls_sock)."""
    if cert is None:
        cert = {"subject": ((("commonName", "hynote.ai"),),), "notAfter": "Jan  1 00:00:00 2027 GMT"}
    tls_sock = mocker.MagicMock()
    tls_sock.version.return_value = version
    tls_sock.getpeercert.return_value = cert
    ctx = mocker.MagicMock()
    if wrap_error is not None:
        ctx.wrap_socket.side_effect = wrap_error
    else:
        ctx.wrap_socket.return_value = tls_sock
    mocker.patch.object(dp.ssl, "create_default_context", return_value=ctx)
    _, factory = _fake_net(mocker)
    return ctx, factory.return_value, tls_sock


class TestTlsHandshake:
    def test_happy_path(self, mocker):
        ctx, raw, tls_sock = _fake_tls(mocker)
        d = dp._p_tls_handshake(SLOTS)
        attempts = d.pop("attempts")
        assert d == {
            "handshake": True,
            "address": "23.1.2.3",
            "protocol": "TLSv1.3",
            "cert_cn": "hynote.ai",
            "not_after": "Jan  1 00:00:00 2027 GMT",
            "error": None,
        }
        assert [(a["address"], a["family"], a["connected"]) for a in attempts] == [("23.1.2.3", "ipv4", True)]
        dp.socket.getaddrinfo.assert_called_once_with("hynote.ai", 443, type=socket.SOCK_STREAM)
        dp.socket.socket.assert_called_once_with(2, 1, 6)
        assert [c.args for c in raw.settimeout.call_args_list] == [
            (dp._TLS_CONNECT_TIMEOUT_S,),
            (dp._TLS_HANDSHAKE_TIMEOUT_S,),
        ]
        raw.connect.assert_called_once_with(("23.1.2.3", 443))
        ctx.wrap_socket.assert_called_once_with(raw, server_hostname="hynote.ai")
        tls_sock.close.assert_called_once()

    def test_certificate_verification_failure(self, mocker):
        err = dp.ssl.SSLCertVerificationError(1, "certificate verify failed: unable to get local issuer certificate")
        _, raw, _ = _fake_tls(mocker, wrap_error=err)
        d = dp._p_tls_handshake(SLOTS)
        assert d["handshake"] is False
        assert d["address"] == "23.1.2.3"
        assert "unable to get local issuer certificate" in d["error"]
        assert d["protocol"] is None
        assert d["cert_cn"] is None
        assert d["not_after"] is None
        raw.close.assert_called_once()

    def test_resolution_failure_does_not_connect(self, mocker):
        mocker.patch.object(dp.ssl, "create_default_context")
        gai, factory = _fake_net(mocker, resolve_error=socket.gaierror(11001, "getaddrinfo failed"))
        d = dp._p_tls_handshake(SLOTS)
        assert d["handshake"] is False
        assert d["address"] is None
        assert d["attempts"] == []
        assert "getaddrinfo failed" in d["error"]
        gai.assert_called_once()
        factory.assert_not_called()

    def test_connect_failure(self, mocker):
        mocker.patch.object(dp.ssl, "create_default_context")
        _, factory = _fake_net(mocker, connect_error=ConnectionRefusedError(10061, "refused"))
        d = dp._p_tls_handshake(SLOTS)
        assert d["handshake"] is False
        assert d["address"] == "23.1.2.3"
        assert "refused" in d["error"]
        factory.return_value.close.assert_called_once()

    def test_timeout_has_nonempty_error(self, mocker):
        mocker.patch.object(dp.ssl, "create_default_context")
        _fake_net(mocker, connect_error=TimeoutError())
        d = dp._p_tls_handshake(SLOTS)
        assert d["handshake"] is False
        assert d["error"]

    def test_ipv4_connect_failure_falls_back_to_ipv6_then_handshakes(self, mocker):
        ctx, raw, _ = _fake_tls(mocker)
        dp.socket.getaddrinfo.return_value = [_V4, _V6]
        raw.connect.side_effect = _refuse("23.1.2.3")
        d = dp._p_tls_handshake(SLOTS)
        assert d["handshake"] is True
        assert d["address"] == "2600:1406::1"
        assert [(a["family"], a["connected"]) for a in d["attempts"]] == [("ipv4", False), ("ipv6", True)]
        ctx.wrap_socket.assert_called_once()

    def test_no_family_connects_reports_the_last_tried_and_no_handshake(self, mocker):
        ctx, raw, _ = _fake_tls(mocker)
        dp.socket.getaddrinfo.return_value = [_V4, _V6]
        raw.connect.side_effect = _refuse("23.1.2.3", "2600:1406::1")
        d = dp._p_tls_handshake(SLOTS)
        assert d["handshake"] is False
        assert d["address"] == "2600:1406::1"
        assert "refused 2600:1406::1" in d["error"]
        assert len(d["attempts"]) == 2
        ctx.wrap_socket.assert_not_called()

    def test_connects_plus_handshake_fit_the_probe_timeout(self):
        worst = 2 * dp._TLS_CONNECT_TIMEOUT_S + dp._TLS_HANDSHAKE_TIMEOUT_S
        assert _REGISTERED["net.tls_handshake"].timeout_s - worst >= 2

    def test_cert_without_common_name(self, mocker):
        _fake_tls(mocker, cert={"subject": ((("organizationName", "Acme"),),), "notAfter": "Jan  1 00:00:00 2027 GMT"})
        d = dp._p_tls_handshake(SLOTS)
        assert d["handshake"] is True
        assert d["cert_cn"] is None

    def test_missing_peer_cert(self, mocker):
        _fake_tls(mocker, cert={})
        d = dp._p_tls_handshake(SLOTS)
        assert d["handshake"] is True
        assert d["cert_cn"] is None
        assert d["not_after"] is None


_TRACERT_OK = """
Tracing route to hynote.ai [104.16.0.1]
over a maximum of 15 hops:

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    12 ms    11 ms    13 ms  104.16.0.1

Trace complete.
"""


def _tracert(mocker, stdout="", returncode=0, side_effect=None, stderr=""):
    run = mocker.patch.object(dp.subprocess, "run", side_effect=side_effect)
    if side_effect is None:
        run.return_value.stdout = stdout
        run.return_value.returncode = returncode
        run.return_value.stderr = stderr
    return run


class TestTraceroute:
    def test_parses_hops_and_reached(self, mocker):
        _tracert(mocker, _TRACERT_OK)
        d = dp._p_traceroute(SLOTS)
        assert d["hops"] == [
            {"hop": 1, "ip": "192.168.1.1", "timeout": False},
            {"hop": 2, "ip": None, "timeout": True},
            {"hop": 3, "ip": "104.16.0.1", "timeout": False},
        ]
        assert d["reached"] is True
        assert "error" not in d

    def test_not_reached_without_trace_complete(self, mocker):
        _tracert(
            mocker,
            "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n  2     *        *        *     Request timed out.\n",
        )
        d = dp._p_traceroute(SLOTS)
        assert d["reached"] is False
        assert len(d["hops"]) == 2

    def test_not_reached_when_last_hop_timed_out(self, mocker):
        _tracert(mocker, "  1     *        *        *     Request timed out.\n\nTrace complete.\n")
        assert dp._p_traceroute(SLOTS)["reached"] is False

    def test_hop_limit_with_trace_complete_is_not_reached(self, mocker):
        # tracert prints "Trace complete." even when it only ran out of hops.
        _tracert(
            mocker,
            "Tracing route to hynote.ai [104.16.0.1]\nover a maximum of 15 hops:\n\n"
            "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n"
            " 15    30 ms    31 ms    29 ms  10.9.9.9\n\nTrace complete.\n",
        )
        d = dp._p_traceroute(SLOTS)
        assert len(d["hops"]) == 2
        assert d["reached"] is False

    def test_ip_literal_target_without_brackets_compares_to_target(self, mocker):
        out = "Tracing route to 8.8.8.8 over a maximum of 15 hops\n\n  1    <1 ms  <1 ms  <1 ms  192.168.1.1\n"
        _tracert(mocker, out + "  2    9 ms     9 ms     9 ms  8.8.8.8\n\nTrace complete.\n")
        assert dp._p_traceroute({"target_host": "8.8.8.8"})["reached"] is True
        _tracert(mocker, out + "  2    9 ms     9 ms     9 ms  8.8.4.4\n\nTrace complete.\n")
        assert dp._p_traceroute({"target_host": "8.8.8.8"})["reached"] is False

    def test_unknown_destination_is_not_reached(self, mocker):
        # A hostname target and no parseable "[ip]" in the header: nothing to compare against.
        _tracert(mocker, "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n\nTrace complete.\n")
        assert dp._p_traceroute(SLOTS)["reached"] is False

    def test_partial_stars_with_ip_is_not_a_timeout(self, mocker):
        _tracert(mocker, "  4    12 ms     *       13 ms  10.1.1.1\n")
        assert dp._p_traceroute(SLOTS)["hops"] == [{"hop": 4, "ip": "10.1.1.1", "timeout": False}]

    def test_command_content(self, mocker):
        run = _tracert(mocker, _TRACERT_OK)
        dp._p_traceroute(SLOTS)
        assert run.call_args.args[0] == ["tracert", "-d", "-h", "15", "-w", "500", "hynote.ai"]
        assert "shell" not in run.call_args.kwargs
        assert run.call_args.kwargs["timeout"] == 45
        assert run.call_args.kwargs["capture_output"] is True
        assert run.call_args.kwargs["text"] is True
        assert run.call_args.kwargs["creationflags"] == dp._NO_WINDOW

    def test_timeout_returns_fallback_with_error(self, mocker):
        _tracert(mocker, side_effect=dp.subprocess.TimeoutExpired(cmd="tracert", timeout=45))
        d = dp._p_traceroute(SLOTS)
        assert d["hops"] == []
        assert d["reached"] is False
        assert d["error"]

    def test_missing_executable_returns_fallback_with_error(self, mocker):
        _tracert(mocker, side_effect=FileNotFoundError("tracert"))
        d = dp._p_traceroute(SLOTS)
        assert d["hops"] == []
        assert d["reached"] is False
        assert d["error"]

    def test_empty_output(self, mocker):
        _tracert(mocker, "  \n")
        d = dp._p_traceroute(SLOTS)
        assert d["hops"] == []
        assert d["reached"] is False

    def test_nonzero_returncode_reports_error(self, mocker):
        _tracert(mocker, "", returncode=1, stderr="Unable to resolve target system name nope.invalid.")
        d = dp._p_traceroute(SLOTS)
        assert d["hops"] == []
        assert d["reached"] is False
        assert "Unable to resolve" in d["error"]

    def test_garbage_output_yields_no_hops(self, mocker):
        _tracert(mocker, "\x00\x01 not a trace\n--- 12 ---\n")
        assert dp._p_traceroute(SLOTS)["hops"] == []

    @pytest.mark.parametrize("bad", ["x;calc", "a b", "-h 1", "host&calc", "", "ex ample.com\n"])
    def test_invalid_target_is_rejected_without_running(self, mocker, bad):
        run = _tracert(mocker, _TRACERT_OK)
        assert dp._p_traceroute({"target_host": bad}) == {"hops": [], "reached": False, "error": "invalid target"}
        run.assert_not_called()

    def test_target_is_normalised_before_use(self, mocker):
        run = _tracert(mocker, _TRACERT_OK)
        dp._p_traceroute({"target_host": "https://HyNote.AI/path"})
        assert run.call_args.args[0][-1] == "hynote.ai"


class TestConnectivityRegistration:
    @pytest.mark.parametrize(
        ("key", "label", "needs", "redact", "timeout", "fn"),
        [
            ("net.control_domain", "Reach a known-good site", (), (), 8, "_p_control_domain"),
            ("net.gateway", "Ping the default gateway", (), ("mac",), 8, "_p_gateway"),
            ("net.tcp_connect", "Connect to the site's ports", ("target_host",), (), 10, "_p_tcp_connect"),
            ("net.tls_handshake", "Check the site's TLS certificate", ("target_host",), (), 12, "_p_tls_handshake"),
            ("net.traceroute", "Trace the route to the site", ("target_host",), (), 50, "_p_traceroute"),
        ],
    )
    def test_registered_with_contract_metadata(self, key, label, needs, redact, timeout, fn):
        p = _REGISTERED[key]
        assert p.label == label
        assert p.category == "network"
        assert p.needs == needs
        assert p.redact == redact
        assert p.timeout_s == timeout
        assert p.fn is getattr(dp, fn)


# ── DNS escalation probes (delegation trace, DNSSEC) ─────────────────────────


class TestTraceDelegation:
    @staticmethod
    def _fake(replies):
        """_dns_query stand-in: ``replies`` maps zone -> (rcode, answers)."""

        def fake(server, name, rdtype, **kw):
            rcode, answers = replies.get(name, ("NOERROR", []))
            return _fake_reply(server, rcode=rcode, answers=answers)

        return fake

    def test_queries_zones_from_tld_down_in_order(self, mocker):
        q = mocker.patch.object(dp, "_dns_query", side_effect=self._fake({}))
        dp._p_trace_delegation({"target_host": "www.hynote.ai"})
        assert [(c.args[0], c.args[1], c.args[2]) for c in q.call_args_list] == [
            ("1.1.1.1", "ai.", "NS"),
            ("1.1.1.1", "hynote.ai.", "NS"),
            ("1.1.1.1", "www.hynote.ai.", "NS"),
        ]

    def test_chain_carries_rcode_and_ns_without_trailing_dots(self, mocker):
        mocker.patch.object(
            dp,
            "_dns_query",
            side_effect=self._fake(
                {
                    "ai.": ("NOERROR", ["a.nic.ai.", "b.nic.ai."]),
                    "hynote.ai.": ("NOERROR", ["ns1.cloudflare.com."]),
                }
            ),
        )
        d = dp._p_trace_delegation(SLOTS)
        assert d == {
            "chain": [
                {"zone": "ai", "rcode": "NOERROR", "ns": ["a.nic.ai", "b.nic.ai"]},
                {"zone": "hynote.ai", "rcode": "NOERROR", "ns": ["ns1.cloudflare.com"]},
            ]
        }

    def test_stops_after_first_nxdomain_and_includes_it(self, mocker):
        q = mocker.patch.object(
            dp,
            "_dns_query",
            side_effect=self._fake({"ai.": ("NOERROR", ["a.nic.ai."]), "hynote.ai.": ("NXDOMAIN", [])}),
        )
        d = dp._p_trace_delegation({"target_host": "www.hynote.ai"})
        assert [c.args[1] for c in q.call_args_list] == ["ai.", "hynote.ai."]  # no www.hynote.ai. query
        assert [e["zone"] for e in d["chain"]] == ["ai", "hynote.ai"]
        assert d["chain"][-1] == {"zone": "hynote.ai", "rcode": "NXDOMAIN", "ns": []}

    def test_non_nxdomain_failures_do_not_stop_the_walk(self, mocker):
        q = mocker.patch.object(dp, "_dns_query", side_effect=self._fake({"ai.": ("SERVFAIL", [])}))
        d = dp._p_trace_delegation({"target_host": "www.hynote.ai"})
        assert len(q.call_args_list) == 3
        assert d["chain"][0]["rcode"] == "SERVFAIL"

    def test_deadline_stops_the_walk_and_keeps_the_partial_chain(self, mocker):
        clock = {"now": 100.0}
        mocker.patch.object(dp, "time", mocker.Mock(monotonic=lambda: clock["now"]))
        seen_timeouts = []

        def slow(server, name, rdtype, **kw):
            seen_timeouts.append(kw["timeout"])
            clock["now"] += 5.0  # each query "takes" 5s
            return _fake_reply(server, answers=["ns.example."])

        q = mocker.patch.object(dp, "_dns_query", side_effect=slow)
        d = dp._p_trace_delegation({"target_host": "a.b.hynote.ai"})  # would be 4 zones
        assert [c.args[1] for c in q.call_args_list] == ["ai.", "hynote.ai."]  # third not attempted: 10s > 9s budget
        assert [e["zone"] for e in d["chain"]] == ["ai", "hynote.ai"]
        assert d["error"] == "deadline reached"
        assert seen_timeouts == [3.0, 3.0]

    def test_query_timeout_is_clamped_to_the_remaining_budget(self, mocker):
        clock = {"now": 0.0}
        mocker.patch.object(dp, "time", mocker.Mock(monotonic=lambda: clock["now"]))
        seen = []

        def slow(server, name, rdtype, **kw):
            seen.append(kw["timeout"])
            clock["now"] += 7.0
            return _fake_reply(server)

        mocker.patch.object(dp, "_dns_query", side_effect=slow)
        dp._p_trace_delegation({"target_host": "www.hynote.ai"})
        assert seen == [3.0, 2.0]  # second query only has 9 - 7 = 2s left

    def test_completed_walk_has_no_error_key(self, mocker):
        mocker.patch.object(dp, "_dns_query", side_effect=self._fake({}))
        assert "error" not in dp._p_trace_delegation({"target_host": "www.hynote.ai"})

    @pytest.mark.parametrize("literal", ["192.0.2.7", "2001:db8::1"])
    def test_ip_literal_has_no_chain_and_no_queries(self, mocker, literal):
        q = mocker.patch.object(dp, "_dns_query")
        assert dp._p_trace_delegation({"target_host": literal}) == {"chain": []}
        q.assert_not_called()

    def test_without_dnspython(self, mocker):
        mocker.patch.object(dp, "HAVE_DNSPYTHON", False)
        q = mocker.patch.object(dp, "_dns_query")
        assert dp._p_trace_delegation(SLOTS) == {"chain": [], "error": "dnspython not installed"}
        q.assert_not_called()


class TestDnssecCheck:
    @staticmethod
    def _fake(validating, cd):
        """``validating`` / ``cd`` are (rcode, ad) pairs for the two queries."""

        def fake(server, name, rdtype, **kw):
            rcode, ad = cd if kw.get("cd") else validating
            r = _fake_reply(server, rcode=rcode)
            r["ad"] = ad
            return r

        return fake

    def test_two_queries_second_with_checking_disabled(self, mocker):
        q = mocker.patch.object(dp, "_dns_query", side_effect=self._fake(("NOERROR", True), ("NOERROR", False)))
        dp._p_dnssec_check(SLOTS)
        assert len(q.call_args_list) == 2
        first, second = q.call_args_list
        assert first.args == ("1.1.1.1", "hynote.ai", "A")
        assert first.kwargs == {"want_dnssec": True}
        assert second.args == ("1.1.1.1", "hynote.ai", "A")
        assert second.kwargs == {"want_dnssec": True, "cd": True}

    def test_servfail_that_clears_with_cd_is_a_validation_failure(self, mocker):
        mocker.patch.object(dp, "_dns_query", side_effect=self._fake(("SERVFAIL", False), ("NOERROR", False)))
        assert dp._p_dnssec_check(SLOTS) == {
            "rcode_validating": "SERVFAIL",
            "rcode_cd": "NOERROR",
            "ad": False,
            "validation_failure": True,
        }

    def test_servfail_with_cd_nxdomain_is_a_validation_failure(self, mocker):
        mocker.patch.object(dp, "_dns_query", side_effect=self._fake(("SERVFAIL", False), ("NXDOMAIN", False)))
        assert dp._p_dnssec_check(SLOTS)["validation_failure"] is True

    def test_both_noerror_with_ad_is_not_a_failure(self, mocker):
        mocker.patch.object(dp, "_dns_query", side_effect=self._fake(("NOERROR", True), ("NOERROR", False)))
        assert dp._p_dnssec_check(SLOTS) == {
            "rcode_validating": "NOERROR",
            "rcode_cd": "NOERROR",
            "ad": True,
            "validation_failure": False,
        }

    def test_servfail_with_cd_also_servfail_is_a_broken_zone_not_dnssec(self, mocker):
        mocker.patch.object(dp, "_dns_query", side_effect=self._fake(("SERVFAIL", False), ("SERVFAIL", False)))
        assert dp._p_dnssec_check(SLOTS)["validation_failure"] is False

    def test_ad_comes_from_the_validating_query(self, mocker):
        mocker.patch.object(dp, "_dns_query", side_effect=self._fake(("NOERROR", False), ("NOERROR", True)))
        assert dp._p_dnssec_check(SLOTS)["ad"] is False


class TestEscalationRegistration:
    @pytest.mark.parametrize(
        ("key", "label", "timeout", "fn"),
        [
            ("dns.trace_delegation", "Follow the delegation chain from the TLD", 12, "_p_trace_delegation"),
            ("dns.dnssec_check", "Check DNSSEC validation", 8, "_p_dnssec_check"),
        ],
    )
    def test_registered_with_contract_metadata(self, key, label, timeout, fn):
        p = _REGISTERED[key]
        assert p.label == label
        assert p.category == "network"
        assert p.needs == ("target_host",)
        assert p.redact == ("username",)
        assert p.timeout_s == timeout
        assert p.fn is getattr(dp, fn)


# Probes allowed to shell out (ping.exe / tracert.exe, list args, validated host).
_SUBPROCESS_ALLOWED = {"_p_gateway", "_p_traceroute"}


def _referenced_probes():
    """(class name, probe key) for every probe any symptom class lists."""
    return [(name, key) for name, cls in diagnose.SYMPTOM_CLASSES.items() for key in (*cls["wave1"], *cls["escalate"])]


class TestRegistryInvariants:
    """Checked against the import-time snapshot: the autouse fixture empties dp.PROBES."""

    def test_snapshot_is_the_full_registry(self):
        network = [k for k, p in _REGISTERED.items() if p.category == "network"]
        assert len(network) == 15
        assert {k for k, p in _REGISTERED.items() if p.category == "crash"} == set(dcp.REGISTERED)

    def test_wave_one_runs_in_a_single_batch_of_workers(self):
        # Fewer workers than wave-1 probes would queue some behind the slow ones and eat their timeouts.
        assert dp._MAX_WORKERS == 10
        assert all(len(cls["wave1"]) <= dp._MAX_WORKERS for cls in diagnose.SYMPTOM_CLASSES.values())

    def test_every_referenced_probe_is_registered(self):
        referenced = _referenced_probes()
        assert referenced
        missing = [key for _, key in referenced if key not in _REGISTERED]
        assert missing == []

    @pytest.mark.xfail(strict=True, reason="crash probes join a symptom class in plan Task 8; remove this marker then")
    def test_every_registered_probe_is_referenced(self):
        assert {key for _, key in _referenced_probes()} == set(_REGISTERED)

    def test_probes_never_share_a_function_with_remediation(self):
        probe_fns = {p.fn for p in _REGISTERED.values()}
        assert probe_fns.isdisjoint(set(remediation._REMEDIATION_DISPATCH.values()))

    def test_probe_function_names_are_disjoint_from_remediation_names(self):
        probe_names = {p.fn.__name__ for p in _REGISTERED.values()}
        assert probe_names.isdisjoint({f.__name__ for f in remediation._REMEDIATION_DISPATCH.values()})

    def test_probe_needs_are_slots_of_every_class_that_uses_them(self):
        for name, key in _referenced_probes():
            slots = set(diagnose.SYMPTOM_CLASSES[name]["slots"])
            assert set(_REGISTERED[key].needs) <= slots, key

    def test_categories_are_known(self):
        assert {p.category for p in _REGISTERED.values()} <= {"network", "crash", "storage", "perf"}

    def test_subprocess_run_only_in_allow_listed_probes(self):
        for key, p in _REGISTERED.items():
            if p.fn.__name__ not in _SUBPROCESS_ALLOWED:
                assert "subprocess.run(" not in inspect.getsource(p.fn), key

    def test_allow_listed_probes_do_use_subprocess_run(self):
        # Guards the allow-list: if a probe stops shelling out, shrink the list.
        by_name = {p.fn.__name__: p for p in _REGISTERED.values()}
        assert set(by_name) >= _SUBPROCESS_ALLOWED
        for name in _SUBPROCESS_ALLOWED:
            assert "subprocess.run(" in inspect.getsource(by_name[name].fn), name
