"""Tests for diagnose_probes.py -- the closed probe registry and bounded runner."""

from __future__ import annotations

import time

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

import diagnose_probes as dp


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
