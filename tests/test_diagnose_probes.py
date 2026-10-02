"""Tests for diagnose_probes.py -- the closed probe registry and bounded runner."""

from __future__ import annotations

import json
import os
import re
import socket
import struct
import time
import winreg

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

import diagnose_probes as dp

# Snapshot before the autouse fixture empties PROBES: the real wave-one registrations.
_REGISTERED = dict(dp.PROBES)


@pytest.fixture(autouse=True)
def _isolated_registry(mocker):
    """Every test starts with an empty PROBES dict and registers throwaway probes."""
    mocker.patch.dict(dp.PROBES, {}, clear=True)


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


class TestWaveOneRegistration:
    @pytest.mark.parametrize(
        ("key", "label", "timeout"),
        [
            ("dns.resolve_cached", "Resolve through Windows (uses the DNS cache)", 8),
            ("dns.resolve_direct", "Ask DNS servers directly (bypasses the cache)", 8),
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
            "rcode": "NOERROR",
            "nodata": False,
            "answers": ["1.2.3.4"],
        }
        assert d["resolvers"][2]["nodata"] is True
        assert all(c.args[1] == "hynote.ai" and c.args[2] == "A" for c in q.call_args_list)

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

    def test_non_string_passes_through(self):
        assert dp._scrub_userinfo(1) == 1


class TestProxyConfigCredentials:
    def test_no_secret_anywhere_in_the_payload(self, mocker):
        _patch_registry(
            mocker,
            values={
                (winreg.HKEY_CURRENT_USER, _INET): {
                    "ProxyServer": "http=bob:s3cret@a:1;https=b:2",
                    "AutoConfigURL": "http://carol:s3cret@wpad/wpad.dat",
                },
                (winreg.HKEY_LOCAL_MACHINE, _CONNS): {"WinHttpSettings": _winhttp_blob(3, "dave:s3cret@proxy:8080")},
            },
        )
        mocker.patch.object(
            dp.os, "environ", {"HTTP_PROXY": "http://erin:s3cret@e:1", "https_proxy": "http://frank:s3cret@f:2"}
        )
        d = dp._p_proxy_config({})
        assert "s3cret" not in json.dumps(d)
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
