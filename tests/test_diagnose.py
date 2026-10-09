"""Tests for diagnose.py -- symptom classes and the deterministic classifier."""

from __future__ import annotations

import copy
import json
import os
import re
import threading
import time
import types
from pathlib import Path

import pytest

import diagnose
import remediation

CHROME_BLOB = (
    "This site can’t be reached\n"
    "hynote.ai’s server IP address could not be found.\n"
    "Try:\n"
    "Checking the connection\n"
    "Checking the proxy, firewall, and DNS configuration\n"
    "Running Windows Network Diagnostics\n"
    "ERR_NAME_NOT_RESOLVED"
)


class TestClassify:
    def test_chrome_name_not_resolved_blob(self):
        r = diagnose.classify(CHROME_BLOB)
        assert r["symptom_class"] == "network_dns"
        assert r["slots"] == {"target_host": "hynote.ai"}
        assert r["candidates"] == ["hynote.ai"]
        assert r["missing"] == []

    def test_url_host_extracted(self):
        r = diagnose.classify("DNS_PROBE_FINISHED_NXDOMAIN https://foo.example.com/x")
        assert r["symptom_class"] == "network_dns"
        assert r["slots"] == {"target_host": "foo.example.com"}

    def test_no_host_asks_for_one(self):
        r = diagnose.classify("the internet is broken")
        assert r["symptom_class"] == "network_dns"
        assert r["slots"] == {}
        assert r["candidates"] == []
        assert r["missing"] == ["target_host"]

    def test_two_hosts_is_ambiguous_not_a_guess(self):
        r = diagnose.classify("google.com works but hynote.ai doesn't load")
        assert r["symptom_class"] == "network_dns"
        assert r["candidates"] == ["google.com", "hynote.ai"]
        assert r["slots"] == {}
        assert r["missing"] == ["target_host"]

    def test_unrelated_symptom_has_no_class(self):
        r = diagnose.classify("my printer jams")
        assert r == {"symptom_class": None, "slots": {}, "candidates": [], "missing": []}

    def test_file_like_tokens_are_not_hosts(self):
        r = diagnose.classify("error in app.js and config.json")
        assert r["candidates"] == []
        assert r["slots"] == {}

    def test_driver_file_in_a_crash_report_is_not_a_host(self):
        r = diagnose.classify("nvlddmkm.sys crashed with a BSOD")
        assert r["candidates"] == []
        # Not a host, so not a network question; since PR 2 it is a crash report.
        assert r["symptom_class"] == "crashes"

    def test_dump_file_is_not_a_host(self):
        assert diagnose.classify("memory.dmp was written")["candidates"] == []

    @pytest.mark.parametrize(
        "ext",
        ["sys", "dmp", "pdf", "zip", "gif", "jpeg", "docx", "xlsx", "msi", "dat", "tmp", "php", "asp", "aspx", "dll"],
    )
    def test_common_file_extensions_are_not_tlds(self, ext):
        assert diagnose.classify(f"the site broke after report.{ext} opened")["candidates"] == []

    def test_file_like_token_next_to_a_real_host_is_ignored(self):
        r = diagnose.classify("hynote.ai won't load, see app.js")
        assert r["slots"] == {"target_host": "hynote.ai"}

    def test_path_file_name_inside_url_is_not_a_second_host(self):
        r = diagnose.classify("https://hynote.ai/static/page.php won't load")
        assert r["candidates"] == ["hynote.ai"]
        assert r["slots"] == {"target_host": "hynote.ai"}

    def test_sentence_ending_in_a_period_is_not_a_host(self):
        r = diagnose.classify("Windows Network Diagnostics.")
        assert r["symptom_class"] == "network_dns"
        assert r["candidates"] == []

    def test_url_and_same_bare_host_count_once(self):
        r = diagnose.classify("https://hynote.ai/login fails, hynote.ai is down")
        assert r["candidates"] == ["hynote.ai"]
        assert r["slots"] == {"target_host": "hynote.ai"}

    def test_ip_literal_is_a_candidate(self):
        r = diagnose.classify("can't reach 192.168.1.50")
        assert r["symptom_class"] == "network_dns"
        assert r["candidates"] == ["192.168.1.50"]
        assert r["slots"] == {"target_host": "192.168.1.50"}
        assert r["missing"] == []

    def test_ip_with_trailing_period(self):
        assert diagnose.classify("I can't reach 10.0.0.1.")["slots"] == {"target_host": "10.0.0.1"}

    def test_ascii_possessive_stripped(self):
        assert diagnose.classify("hynote.ai's server is down")["slots"] == {"target_host": "hynote.ai"}

    def test_url_with_trailing_punctuation(self):
        assert diagnose.classify("(see https://hynote.ai/x).")["slots"] == {"target_host": "hynote.ai"}

    def test_host_is_lowercased(self):
        assert diagnose.classify("HyNote.AI won't load")["slots"] == {"target_host": "hynote.ai"}

    def test_host_alone_is_enough_to_classify(self):
        r = diagnose.classify("hynote.ai")
        assert r["symptom_class"] == "network_dns"
        assert r["slots"] == {"target_host": "hynote.ai"}

    @pytest.mark.parametrize("text", ["ERR_CONNECTION_RESET", "err_timed_out", "my website is not loading", "no DNS"])
    def test_keywords_classify_without_a_host(self, text):
        r = diagnose.classify(text)
        assert r["symptom_class"] == "network_dns"
        assert r["missing"] == ["target_host"]

    @pytest.mark.parametrize("text", ["", "   ", None, 5])
    def test_empty_or_non_string_input_is_unclassified(self, text):
        assert diagnose.classify(text)["symptom_class"] is None


class TestSymptomClassesShape:
    def test_network_dns_declares_label_slots_and_probe_lists(self):
        c = diagnose.SYMPTOM_CLASSES["network_dns"]
        assert c["label"] == "Website or network unreachable"
        assert c["slots"] == ("target_host",)
        assert len(c["wave1"]) == 10
        assert c["wave1"][0] == "dns.interception"
        assert len(c["escalate"]) == 5
        assert set(c["wave1"]).isdisjoint(c["escalate"])


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "diagnose"
FIXTURES = sorted(FIXTURE_DIR.glob("*.json"))


def _ok(data):
    return {"ok": True, "data": data}


def _res(rcode, *answers, nodata=False, name="r", transport="udp"):
    return {
        "name": name,
        "server": "x",
        "transport": transport,
        "rcode": rcode,
        "nodata": nodata,
        "answers": list(answers),
    }


def _tls(rcode, *answers, nodata=False):
    return _res(rcode, *answers, nodata=nodata, transport="tls")


def _intercepted(ev, value=True):
    ev["dns.interception"] = _ok({"intercepted": value, "probe_server": "192.0.2.1", "answered_rcode": "NOERROR"})
    return ev


def _cache_ev(cached_resolved, *resolvers, addresses=()):
    return {
        "dns.resolve_cached": _ok({"resolved": cached_resolved, "addresses": list(addresses)}),
        "dns.resolve_direct": _ok({"resolvers": list(resolvers)}),
    }


class TestCacheAgrees:
    def test_none_when_a_probe_is_missing(self):
        assert diagnose.cache_agrees({}) is None
        assert diagnose.cache_agrees({"dns.resolve_cached": _ok({"resolved": True, "addresses": ["1.1.1.1"]})}) is None

    def test_none_on_a_failed_probe(self):
        ev = _cache_ev(True, _res("NOERROR", "1.1.1.1"), addresses=["1.1.1.1"])
        ev["dns.resolve_cached"] = {"ok": False, "error": "boom"}
        assert diagnose.cache_agrees(ev) is None

    def test_none_when_direct_has_no_resolvers(self):
        assert diagnose.cache_agrees(_cache_ev(True, addresses=["1.1.1.1"])) is None

    def test_false_on_disjoint_addresses(self):
        ev = _cache_ev(True, _res("NOERROR", "104.21.0.1"), addresses=["0.0.0.0"])
        assert diagnose.cache_agrees(ev) is False

    def test_false_when_only_the_cache_fails(self):
        assert diagnose.cache_agrees(_cache_ev(False, _res("NOERROR", "104.21.0.1"))) is False

    def test_false_when_only_direct_fails(self):
        assert diagnose.cache_agrees(_cache_ev(True, _res("NXDOMAIN"), addresses=["1.1.1.1"])) is False

    def test_true_when_addresses_intersect(self):
        ev = _cache_ev(True, _res("NOERROR", "2.2.2.2"), _res("NOERROR", nodata=True), addresses=["1.1.1.1", "2.2.2.2"])
        assert diagnose.cache_agrees(ev) is True

    def test_true_when_both_fail(self):
        assert diagnose.cache_agrees(_cache_ev(False, _res("NOERROR", nodata=True))) is True

    def test_none_when_cached_resolves_and_every_resolver_times_out(self):
        ev = _cache_ev(True, _res("TIMEOUT"), _res("TIMEOUT"), addresses=["1.1.1.1"])
        assert diagnose.cache_agrees(ev) is None

    def test_none_when_cached_resolves_and_every_resolver_servfails(self):
        ev = _cache_ev(True, _res("SERVFAIL"), _res("SERVFAIL"), addresses=["1.1.1.1"])
        assert diagnose.cache_agrees(ev) is None

    def test_timeout_is_ignored_next_to_a_matching_answer(self):
        ev = _cache_ev(True, _res("TIMEOUT"), _res("NOERROR", "1.1.1.1"), addresses=["1.1.1.1"])
        assert diagnose.cache_agrees(ev) is True

    def test_servfail_is_ignored_next_to_nxdomain(self):
        assert diagnose.cache_agrees(_cache_ev(False, _res("SERVFAIL"), _res("NXDOMAIN"))) is True

    def test_noerror_without_answers_or_nodata_flag_is_not_definitive(self):
        assert diagnose.cache_agrees(_cache_ev(True, _res("NOERROR"), addresses=["1.1.1.1"])) is None

    def test_only_ipv4_cached_addresses_are_compared(self):
        ev = _cache_ev(True, _res("NOERROR", "104.21.0.1"), addresses=["2606:4700::1", "104.21.0.1"])
        assert diagnose.cache_agrees(ev) is True

    def test_ipv4_mismatch_next_to_an_ipv6_address_is_false(self):
        ev = _cache_ev(True, _res("NOERROR", "104.21.0.1"), addresses=["2606:4700::1", "0.0.0.0"])
        assert diagnose.cache_agrees(ev) is False

    @pytest.mark.parametrize("direct", [_res("NOERROR", "104.21.0.1"), _res("NXDOMAIN")])
    def test_ipv6_only_cache_is_not_comparable(self, direct):
        # The direct probes ask for A records only, so an AAAA-only cache says nothing either way.
        assert diagnose.cache_agrees(_cache_ev(True, direct, addresses=["2606:4700::1"])) is None

    def test_non_address_strings_in_the_cache_are_ignored(self):
        ev = _cache_ev(True, _res("NOERROR", "104.21.0.1"), addresses=["junk", 5, "104.21.0.1"])
        assert diagnose.cache_agrees(ev) is True

    def test_intercepted_counts_only_tls_resolvers(self):
        # The UDP answer comes from the interceptor; only the encrypted lookup is a measurement.
        ev = _cache_ev(
            True,
            _res("NOERROR", "10.9.9.9", name="system"),
            _tls("NOERROR", "34.110.213.225"),
            addresses=["10.9.9.9"],
        )
        assert diagnose.cache_agrees(ev) is True  # not intercepted: the system answer intersects the cache
        assert diagnose.cache_agrees(_intercepted(ev)) is False

    def test_intercepted_without_a_definitive_tls_answer_is_none(self):
        ev = _cache_ev(
            True,
            _res("NOERROR", "1.1.1.1", name="system"),
            _tls("TIMEOUT"),
            _res("NOERROR", "1.1.1.1"),
            addresses=["1.1.1.1"],
        )
        assert diagnose.cache_agrees(_intercepted(ev)) is None

    @pytest.mark.parametrize("value", [False, None])
    def test_interception_false_or_unknown_counts_every_resolver(self, value):
        ev = _cache_ev(True, _res("NOERROR", "1.1.1.1"), addresses=["1.1.1.1"])
        assert diagnose.cache_agrees(_intercepted(ev, value)) is True

    def test_failed_interception_probe_counts_every_resolver(self):
        ev = _cache_ev(True, _res("NOERROR", "1.1.1.1"), addresses=["1.1.1.1"])
        ev["dns.interception"] = {"ok": False, "error": "timed out after 4s"}
        assert diagnose.cache_agrees(ev) is True


class TestRuleFixtures:
    def test_fixture_dir_is_populated(self):
        assert len(FIXTURES) >= 8

    @pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
    def test_rule_fixture(self, path):
        fx = json.loads(path.read_text(encoding="utf-8"))
        if fx.get("symptom_class") == "crashes":
            self._check_crash_fixture(fx)
            return
        cls = diagnose.classify(fx["symptom"])
        host = fx["expect"].get("target_host") or cls["slots"].get("target_host")
        if "target_host" in fx["expect"]:
            assert cls["slots"].get("target_host") == fx["expect"]["target_host"]
        verdict = diagnose.evaluate_rules(fx["evidence"], host)
        assert verdict["locus"] == fx["expect"]["locus"]
        for key in fx["expect"]["must_include"]:
            assert key in verdict["suggested_actions"]
        for key in fx["expect"]["must_exclude"]:
            assert key not in verdict["suggested_actions"]
        if verdict["locus"] == "external_cause":
            assert verdict["suggested_actions"] == []

    @staticmethod
    def _check_crash_fixture(fx):
        import diagnose_crash_rules as dcr

        expect = fx["expect"]
        verdict = dcr.evaluate_crash_rules(fx["evidence"])
        assert verdict["rule_hits"][0] == expect["rule"]
        assert (verdict["status"], verdict["locus"]) == (expect["status"], expect["locus"])
        for key in expect["context"]:
            assert key in verdict["rule_hits"], key
        for key in expect["must_include"]:
            assert key in verdict["suggested_actions"]
        for key in expect["must_exclude"]:
            assert key not in verdict["suggested_actions"]
        assert 1 <= len(verdict["manual_steps"]) <= diagnose.MAX_MANUAL_STEPS or expect["rule"] == "nothing_found"


def _fixture_evidence(name):
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))["evidence"]


VERDICT_KEYS = {
    "status",
    "locus",
    "headline",
    "reasoning",
    "evidence_refs",
    "suggested_actions",
    "manual_steps",
    "no_local_fix_reason",
    "source",
    "rule_hits",
}


class TestEvaluateRulesVerdicts:
    def test_golden_verdict_shape_and_wording(self):
        v = diagnose.evaluate_rules(_fixture_evidence("hynote_zone_missing_a"), "hynote.ai")
        assert set(v) == VERDICT_KEYS
        assert v["status"] == "confident"
        assert v["source"] == "rules"
        assert v["headline"] == "hynote.ai exists but publishes no web address"
        assert v["rule_hits"] == ["external_no_address", "cache_agrees"]
        assert "nothing on this PC can" in v["no_local_fix_reason"]
        assert "dns.authoritative" in v["evidence_refs"]
        assert "dns.record_sweep" in v["evidence_refs"]

    def test_nxdomain_headline_and_reason(self):
        v = diagnose.evaluate_rules(_fixture_evidence("nxdomain_nonexistent_domain"), "no-such-name-zq7.ai")
        assert v["headline"] == "no-such-name-zq7.ai does not exist"
        assert v["no_local_fix_reason"] == "The domain's own nameservers say this name does not exist."

    def test_nodata_with_empty_sweep_uses_plain_headline(self):
        ev = _fixture_evidence("hynote_zone_missing_a")
        ev["dns.record_sweep"]["data"]["records"] = {"A": [], "MX": [], "TXT": [], "SOA": [], "NS": []}
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert v["locus"] == "external_cause"
        assert v["headline"] == "hynote.ai has no web address record"
        assert "nothing on this PC can" in v["no_local_fix_reason"]

    def test_nodata_without_sweep_evidence_still_fires(self):
        ev = _fixture_evidence("hynote_zone_missing_a")
        del ev["dns.record_sweep"]
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert v["headline"] == "hynote.ai has no web address record"
        assert "dns.record_sweep" not in v["evidence_refs"]

    def test_external_needs_an_authoritative_answer(self):
        ev = _fixture_evidence("hynote_zone_missing_a")
        ev["dns.authoritative"]["data"]["nameservers"][0]["aa"] = False
        assert diagnose.evaluate_rules(ev, "hynote.ai")["locus"] == "unknown"
        ev["dns.authoritative"] = {"ok": False, "error": "no dnspython"}
        assert diagnose.evaluate_rules(ev, "hynote.ai")["locus"] == "unknown"

    def test_external_needs_two_agreeing_resolvers(self):
        ev = _fixture_evidence("hynote_zone_missing_a")
        ev["dns.resolve_direct"]["data"]["resolvers"] = ev["dns.resolve_direct"]["data"]["resolvers"][:1]
        assert diagnose.evaluate_rules(ev, "hynote.ai")["locus"] == "unknown"

    def test_hosts_override_headline_names_line_and_ip(self):
        v = diagnose.evaluate_rules(_fixture_evidence("hosts_file_override"), "hynote.ai")
        assert v["headline"] == "hosts file line 22 sends hynote.ai to 0.0.0.0"
        assert v["status"] == "confident"
        assert v["no_local_fix_reason"] == ""
        assert v["rule_hits"] == ["hosts_override"]

    def test_stale_cache_verdict(self):
        v = diagnose.evaluate_rules(_fixture_evidence("stale_cache_direct_resolves"), "hynote.ai")
        assert v["status"] == "confident"
        assert v["suggested_actions"] == ["flush_dns"]
        assert v["rule_hits"] == ["stale_cache"]

    def test_dead_gateway_verdict(self):
        v = diagnose.evaluate_rules(_fixture_evidence("dead_gateway"), "example.com")
        assert v["status"] == "likely"
        assert v["suggested_actions"] == ["reset_network_adapter"]
        assert v["rule_hits"] == ["dead_gateway"]

    def test_aaaa_in_the_sweep_vetoes_external_cause(self):
        ev = _fixture_evidence("hynote_zone_missing_a")
        ev["dns.record_sweep"]["data"]["records"]["AAAA"] = ["2606:4700::1"]
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert v["locus"] != "external_cause"
        assert "external_no_address" not in v["rule_hits"]

    @pytest.mark.parametrize("rtype", ["A", "CNAME"])
    def test_any_address_record_in_the_sweep_vetoes_external_cause(self, rtype):
        ev = _fixture_evidence("nxdomain_nonexistent_domain")
        ev["dns.record_sweep"]["data"]["records"][rtype] = ["x.example."]
        assert diagnose.evaluate_rules(ev, "no-such-name-zq7.ai")["locus"] != "external_cause"

    def test_a_second_authoritative_server_with_an_address_vetoes_external_cause(self):
        ev = _fixture_evidence("hynote_zone_missing_a")
        ev["dns.authoritative"]["data"]["nameservers"].append(
            {
                "name": "ns2",
                "ip": "198.51.100.54",
                "rcode": "NOERROR",
                "nodata": False,
                "aa": True,
                "answers": ["104.21.0.1"],
            }
        )
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert v["locus"] != "external_cause"
        assert "external_no_address" not in v["rule_hits"]

    def test_cache_resolves_live_has_no_address_and_authority_agrees_is_external(self):
        ev = _fixture_evidence("nxdomain_nonexistent_domain")
        ev["dns.resolve_cached"]["data"] = {"resolved": True, "addresses": ["104.21.0.9"], "error": None}
        v = diagnose.evaluate_rules(ev, "no-such-name-zq7.ai")
        assert v["locus"] == "external_cause"
        assert v["status"] == "likely"
        assert v["suggested_actions"] == []
        assert v["headline"] == "no-such-name-zq7.ai no longer has a web address at its DNS provider"
        assert "old cached copy" in v["no_local_fix_reason"]
        assert v["rule_hits"] == ["stale_cache_external"]
        assert "dns.authoritative" in v["evidence_refs"]

    def test_cache_resolves_live_has_no_address_without_authority_is_local_flush(self):
        ev = _fixture_evidence("nxdomain_nonexistent_domain")
        ev["dns.resolve_cached"]["data"] = {"resolved": True, "addresses": ["104.21.0.9"], "error": None}
        del ev["dns.authoritative"]
        v = diagnose.evaluate_rules(ev, "no-such-name-zq7.ai")
        assert v["locus"] == "local"
        assert v["status"] == "likely"
        assert v["suggested_actions"] == ["flush_dns"]
        assert v["reasoning"] == (
            "This PC's DNS cache still holds an address for no-such-name-zq7.ai that the live DNS servers "
            "no longer return."
        )
        assert v["rule_hits"] == ["stale_cache"]

    def test_cache_resolves_live_has_no_address_and_authority_has_answers_is_local_flush(self):
        ev = _fixture_evidence("nxdomain_nonexistent_domain")
        ev["dns.resolve_cached"]["data"] = {"resolved": True, "addresses": ["104.21.0.9"], "error": None}
        ev["dns.authoritative"]["data"]["nameservers"][0].update(rcode="NOERROR", nodata=False, answers=["1.2.3.4"])
        v = diagnose.evaluate_rules(ev, "no-such-name-zq7.ai")
        assert v["locus"] == "local"
        assert v["suggested_actions"] == ["flush_dns"]

    def test_ipv6_only_cache_never_triggers_stale_cache(self):
        ev = _cache_ev(True, _res("NOERROR", "104.21.0.1"), _res("NOERROR", "104.21.0.1"), addresses=["2606:4700::1"])
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert "stale_cache" not in v["rule_hits"]
        assert "flush_dns" not in v["suggested_actions"]

    @pytest.mark.parametrize("rtype", ["A", "AAAA", "CNAME"])
    def test_sweep_address_record_vetoes_stale_cache_external(self, rtype):
        ev = _fixture_evidence("nxdomain_nonexistent_domain")
        ev["dns.resolve_cached"]["data"] = {"resolved": True, "addresses": ["104.21.0.9"], "error": None}
        ev["dns.record_sweep"]["data"]["records"][rtype] = ["104.21.0.9" if rtype == "A" else "x.example."]
        v = diagnose.evaluate_rules(ev, "no-such-name-zq7.ai")
        assert v["locus"] == "local"
        assert v["rule_hits"] == ["stale_cache"]
        assert v["suggested_actions"] == ["flush_dns"]

    @pytest.mark.parametrize("rtype", ["MX", "TXT", "SOA", "NS"])
    def test_nxdomain_with_other_records_in_the_sweep_says_exists_but_no_web_address(self, rtype):
        ev = _fixture_evidence("nxdomain_nonexistent_domain")
        ev["dns.record_sweep"]["data"]["records"][rtype] = ["something."]
        v = diagnose.evaluate_rules(ev, "no-such-name-zq7.ai")
        assert v["locus"] == "external_cause"
        assert v["headline"] == "no-such-name-zq7.ai exists but publishes no web address"
        assert "dns.record_sweep" in v["evidence_refs"]

    def test_nxdomain_with_an_empty_sweep_still_says_does_not_exist(self):
        v = diagnose.evaluate_rules(_fixture_evidence("nxdomain_nonexistent_domain"), "no-such-name-zq7.ai")
        assert v["headline"] == "no-such-name-zq7.ai does not exist"

    def test_cached_and_live_addresses_that_differ_are_a_confident_local_flush(self):
        ev = _cache_ev(True, _res("NOERROR", "104.21.0.1"), _res("NOERROR", "104.21.0.1"), addresses=["0.0.0.0"])
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert v["status"] == "confident"
        assert v["locus"] == "local"
        assert v["suggested_actions"] == ["flush_dns"]
        assert "different addresses" in v["reasoning"]
        assert v["rule_hits"] == ["stale_cache"]

    def test_blocked_udp53_does_not_make_a_working_cache_stale(self):
        ev = _cache_ev(True, _res("TIMEOUT"), _res("TIMEOUT"), _res("TIMEOUT"), addresses=["1.1.1.1"])
        v = diagnose.evaluate_rules(ev, "example.com")
        assert "stale_cache" not in v["rule_hits"]
        assert "flush_dns" not in v["suggested_actions"]
        assert v["status"] == "inconclusive"

    def test_untestable_gateway_is_not_a_dead_gateway(self):
        ev = _fixture_evidence("dead_gateway")
        ev["net.gateway"]["data"].update(reachable=None, error="ping.exe missing")
        assert diagnose.evaluate_rules(ev, "example.com")["locus"] == "unknown"

    def test_no_match_is_inconclusive_with_cache_agrees_hit(self):
        v = diagnose.evaluate_rules(_fixture_evidence("healthy_name_resolves"), "example.com")
        assert v["status"] == "inconclusive"
        assert v["headline"] == "No rule matched this evidence"
        assert v["suggested_actions"] == []
        assert v["rule_hits"] == ["cache_agrees"]

    @pytest.mark.parametrize("evidence", [{}, {"dns.resolve_cached": {"ok": False, "error": "x"}}, None])
    def test_missing_or_failed_evidence_never_raises(self, evidence):
        v = diagnose.evaluate_rules(evidence, "hynote.ai")
        assert set(v) == VERDICT_KEYS
        assert v["status"] == "inconclusive"
        assert v["rule_hits"] == []

    def test_malformed_nested_fields_do_not_raise(self):
        ev = {
            "dns.hosts_file": {"ok": True, "data": {"matches": ["junk"]}},
            "dns.resolve_cached": {"ok": True, "data": {"resolved": False}},
            "dns.resolve_direct": {"ok": True, "data": {"resolvers": ["junk", {}]}},
            "dns.authoritative": {"ok": True, "data": {"nameservers": [None]}},
            "net.gateway": {"ok": True, "data": None},
        }
        assert diagnose.evaluate_rules(ev, None)["status"] == "inconclusive"


class TestInterceptionRules:
    def test_dns_filtered_verdict(self):
        v = diagnose.evaluate_rules(_fixture_evidence("dns_filtered_by_network"), "hynote.ai")
        assert set(v) == VERDICT_KEYS
        assert v["status"] == "likely"
        assert v["locus"] == "local"
        assert v["headline"] == "Your network's DNS is blocking hynote.ai"
        assert "encrypted DNS" in v["reasoning"]
        assert v["suggested_actions"] == []
        assert v["no_local_fix_reason"] == ""
        assert v["rule_hits"] == ["dns_filtered", "dns_intercepted"]
        assert v["evidence_refs"] == ["dns.interception", "dns.resolve_direct"]

    def test_dns_filtered_never_becomes_external_on_aa_false_nxdomain(self):
        # Today's real shape: the "authoritative" NXDOMAIN came from the interceptor (aa false).
        v = diagnose.evaluate_rules(_fixture_evidence("dns_filtered_by_network"), "hynote.ai")
        assert "external_no_address" not in v["rule_hits"]
        assert "stale_cache" not in v["rule_hits"]

    def test_hosts_override_still_wins(self):
        ev = _fixture_evidence("dns_filtered_by_network")
        ev["dns.hosts_file"]["data"]["matches"] = [{"line_no": 3, "ip": "0.0.0.0", "names": ["hynote.ai"]}]
        assert diagnose.evaluate_rules(ev, "hynote.ai")["rule_hits"][0] == "hosts_override"

    def test_dns_filtered_needs_interception(self):
        ev = _fixture_evidence("dns_filtered_by_network")
        del ev["dns.interception"]
        assert "dns_filtered" not in diagnose.evaluate_rules(ev, "hynote.ai")["rule_hits"]

    @pytest.mark.parametrize(
        "system",
        [
            {"name": "system", "transport": "udp", "rcode": "TIMEOUT", "nodata": False, "answers": []},
            {"name": "system", "transport": "udp", "rcode": "NOERROR", "nodata": False, "answers": ["10.0.0.9"]},
            None,
        ],
    )
    def test_dns_filtered_needs_a_definitive_no_address_from_the_system_resolver(self, system):
        ev = _fixture_evidence("dns_filtered_by_network")
        resolvers = [r for r in ev["dns.resolve_direct"]["data"]["resolvers"] if r["name"] != "system"]
        if system is not None:
            resolvers.insert(0, system)
        ev["dns.resolve_direct"]["data"]["resolvers"] = resolvers
        assert "dns_filtered" not in diagnose.evaluate_rules(ev, "hynote.ai")["rule_hits"]

    def test_system_nodata_counts_as_no_address(self):
        ev = _fixture_evidence("dns_filtered_by_network")
        ev["dns.resolve_direct"]["data"]["resolvers"][0].update(rcode="NOERROR", nodata=True, answers=[])
        assert diagnose.evaluate_rules(ev, "hynote.ai")["rule_hits"][0] == "dns_filtered"

    def test_dns_filtered_needs_a_tls_resolver_with_an_address(self):
        ev = _fixture_evidence("dns_filtered_by_network")
        for r in ev["dns.resolve_direct"]["data"]["resolvers"][1:]:
            r["transport"] = "udp"  # port 853 blocked: the fallback answers are the interceptor's too
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert "dns_filtered" not in v["rule_hits"]
        assert v["rule_hits"] == ["dns_intercepted"]
        assert v["status"] == "inconclusive"

    def test_external_no_address_never_fires_when_intercepted(self):
        ev = _intercepted(_fixture_evidence("hynote_zone_missing_a"))
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert v["locus"] != "external_cause"
        assert "external_no_address" not in v["rule_hits"]

    def test_intercepted_with_nothing_else_is_inconclusive(self):
        v = diagnose.evaluate_rules(_fixture_evidence("network_intercepts_everything"), "example.com")
        assert set(v) == VERDICT_KEYS
        assert v["status"] == "inconclusive"
        assert v["locus"] == "unknown"
        assert v["suggested_actions"] == []
        assert v["headline"] == "Something on this network answers DNS queries itself"
        assert "cannot be trusted" in v["reasoning"]
        assert v["rule_hits"] == ["dns_intercepted", "cache_agrees"]

    def test_dns_intercepted_hit_is_added_once_whichever_rule_fires(self):
        ev = _intercepted(_fixture_evidence("dead_gateway"))
        v = diagnose.evaluate_rules(ev, "example.com")
        assert v["rule_hits"][0] == "dead_gateway"
        assert v["rule_hits"].count("dns_intercepted") == 1

    def test_dead_gateway_still_wins_over_the_interception_fallback(self):
        v = diagnose.evaluate_rules(_intercepted(_fixture_evidence("dead_gateway")), "example.com")
        assert v["suggested_actions"] == ["reset_network_adapter"]

    def test_intercepted_cache_that_matches_the_network_dns_is_not_stale(self):
        # A DNS filter that sinkholes: the cache holds what this network's DNS still returns,
        # so flushing changes nothing even though encrypted DNS returns the real address.
        ev = _intercepted(
            _cache_ev(
                True,
                _res("NOERROR", "10.9.9.9", name="system"),
                _tls("NOERROR", "34.110.213.225"),
                addresses=["10.9.9.9"],
            )
        )
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert "stale_cache" not in v["rule_hits"]
        assert "flush_dns" not in v["suggested_actions"]

    def test_intercepted_cache_that_differs_from_the_network_dns_is_still_stale(self):
        ev = _intercepted(
            _cache_ev(
                True,
                _res("NOERROR", "34.110.213.225", name="system"),
                _tls("NOERROR", "34.110.213.225"),
                addresses=["10.1.1.1"],
            )
        )
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert v["rule_hits"][0] == "stale_cache"
        assert v["suggested_actions"] == ["flush_dns"]

    def test_flush_dns_from_the_model_is_dropped_when_the_network_filters_the_name(self):
        ev = _fixture_evidence("dns_filtered_by_network")
        rule = diagnose.evaluate_rules(ev, "hynote.ai")
        out = diagnose.apply_guards(
            {
                "status": "likely",
                "locus": "local",
                "headline": "h",
                "reasoning": "r",
                "evidence_refs": [],
                "suggested_actions": ["flush_dns", "reset_network_adapter"],
                "no_local_fix_reason": "",
            },
            ev,
            rule,
        )
        assert out["suggested_actions"] == ["reset_network_adapter"]

    def test_system_prompt_tells_the_model_to_trust_only_tls_when_intercepted(self):
        prompt = diagnose._system_prompt("network_dns")
        assert "dns.interception" in prompt
        assert 'transport "tls"' in prompt
        for key in ("dns.authoritative", "dns.record_sweep", "dns.trace_delegation", "dns.dnssec_check"):
            assert key in prompt


def _hop_paths(*hops):
    """dns.interception paths: one (gateway, answering_hop) pair per connection."""
    return [
        {"source": f"10.0.{i}.2", "gateway": gw, "answering_hop": hop, "error": None}
        for i, (gw, hop) in enumerate(hops)
    ]


def _with_paths(ev, paths):
    ev["dns.interception"]["data"]["paths"] = paths
    return ev


class TestInterceptorLocation:
    @pytest.mark.parametrize(
        ("paths", "where", "gateway"),
        [
            # Today's real case: Ethernet's router answers at hop 1, Wi-Fi's router sits behind it (hop 2).
            ([("192.168.1.1", 1), ("10.0.0.1", 2)], "router", "192.168.1.1"),
            ([("10.0.0.1", 2)], "upstream", "10.0.0.1"),
            ([("10.0.0.1", 3), ("192.168.1.1", 2)], "upstream", "10.0.0.1"),
            # A connection with no interception at all rules this PC out too.
            ([("192.168.1.1", 1), ("10.0.0.1", None)], "router", "192.168.1.1"),
            ([("192.168.1.1", 1), ("10.0.0.1", 1)], "pc", None),
            ([("192.168.1.1", 1)], "pc_or_router", "192.168.1.1"),
            ([("192.168.1.1", 1), ("192.168.1.1", 1)], "pc_or_router", "192.168.1.1"),
            ([("192.168.1.1", None)], "unknown", None),
            ([], "unknown", None),
        ],
    )
    def test_where_from_hops(self, paths, where, gateway):
        ev = _with_paths(_fixture_evidence("dns_filtered_by_network"), _hop_paths(*paths))
        assert diagnose.interceptor_location(ev) == {"where": where, "gateway": gateway}

    @pytest.mark.parametrize(
        "evidence",
        [
            {},
            {"dns.interception": {"ok": False, "error": "x"}},
            {"dns.interception": {"ok": True, "data": {"intercepted": True, "paths": "junk"}}},
            {"dns.interception": {"ok": True, "data": {"intercepted": True, "paths": [None, {"answering_hop": 1}]}}},
        ],
    )
    def test_missing_or_malformed_paths_are_unknown(self, evidence):
        assert diagnose.interceptor_location(evidence) == {"where": "unknown", "gateway": None}


class TestDnsFilteredByLocation:
    def test_router_case_names_the_router_and_its_admin_page(self):
        v = diagnose.evaluate_rules(_fixture_evidence("dns_filtered_by_router"), "hynote.ai")
        assert v["headline"] == "Your router is blocking hynote.ai"
        assert "not from software on this PC" in v["reasoning"]
        assert v["rule_hits"][0] == "dns_filtered"
        assert v["suggested_actions"] == []  # advice only: nothing here is runnable
        steps = v["manual_steps"]
        assert "http://192.168.1.1" in steps[0]
        assert "Parental Controls" in steps[0]
        assert any("DNS over HTTPS" in s for s in steps)
        assert any("nslookup hynote.ai" in s for s in steps)
        assert "ipconfig /flushdns" in steps[-1]

    @pytest.mark.parametrize(
        ("hops", "headline", "first_step"),
        [
            ([("10.0.0.1", 2)], "A device past your router is blocking hynote.ai", "past your own router"),
            ([("192.168.1.1", 1), ("10.0.0.1", 1)], "Software on this PC is probably blocking hynote.ai", "VPN apps"),
            ([("192.168.1.1", 1)], "Your network's DNS is blocking hynote.ai", "http://192.168.1.1"),
        ],
    )
    def test_headline_and_first_step_follow_the_location(self, hops, headline, first_step):
        ev = _with_paths(_fixture_evidence("dns_filtered_by_network"), _hop_paths(*hops))
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        assert v["headline"] == headline
        assert first_step in v["manual_steps"][0]

    def test_pc_case_checks_pc_software_first_and_the_router_last(self):
        # Two gateway IPs can still be one router (main + guest network), so the router stays on the list.
        ev = _with_paths(_fixture_evidence("dns_filtered_by_network"), _hop_paths(("a", 1), ("b", 1)))
        steps = diagnose.evaluate_rules(ev, "hynote.ai")["manual_steps"]
        assert "router" not in steps[0]
        assert "same router" in steps[-2]
        assert "http://" not in " ".join(steps)  # no single gateway to point at

    def test_unknown_location_covers_router_and_pc_without_an_address(self):
        v = diagnose.evaluate_rules(_fixture_evidence("dns_filtered_by_network"), "hynote.ai")
        steps = v["manual_steps"]
        assert "http://" not in steps[0]  # no gateway known: no made-up admin URL
        assert "router" in steps[0]
        assert "VPN apps" in steps[1]

    def test_steps_stay_within_the_caps(self):
        for name in ("dns_filtered_by_router", "dns_filtered_by_network"):
            steps = diagnose.evaluate_rules(_fixture_evidence(name), "hynote.ai")["manual_steps"]
            assert steps == diagnose.clean_steps(steps)


class TestRuleSteps:
    def test_hosts_override_steps_name_the_line(self):
        ev = _fixture_evidence("hosts_file_override")
        v = diagnose.evaluate_rules(ev, "hynote.ai")
        line = ev["dns.hosts_file"]["data"]["matches"][0]["line_no"]
        assert any(f"Delete line {line}" in s for s in v["manual_steps"])
        assert any(r"C:\Windows\System32\drivers\etc\hosts" in s for s in v["manual_steps"])

    def test_external_steps_never_claim_a_local_fix(self):
        v = diagnose.evaluate_rules(_fixture_evidence("nxdomain_nonexistent_domain"), "no-such-name-zq7.ai")
        assert v["manual_steps"][0] == "Check the spelling of no-such-name-zq7.ai."
        assert any("nothing on this PC needs changing" in s for s in v["manual_steps"])

    @pytest.mark.parametrize(
        ("fixture", "phrase"),
        [
            ("stale_cache_direct_resolves", "ipconfig /flushdns"),
            ("dead_gateway", "Restart the router"),
            ("hynote_zone_missing_a", "A) record"),
        ],
    )
    def test_each_rule_carries_steps(self, fixture, phrase):
        fx = json.loads((FIXTURE_DIR / f"{fixture}.json").read_text(encoding="utf-8"))
        host = fx["expect"].get("target_host") or diagnose.classify(fx["symptom"])["slots"].get("target_host")
        v = diagnose.evaluate_rules(fx["evidence"], host)
        assert any(phrase in s for s in v["manual_steps"])

    def test_inconclusive_fallbacks_have_no_steps(self):
        assert diagnose.evaluate_rules({}, "hynote.ai")["manual_steps"] == []
        v = diagnose.evaluate_rules(_fixture_evidence("network_intercepts_everything"), "example.com")
        assert v["manual_steps"] == []


class TestCleanSteps:
    def test_strips_dedupes_and_drops_non_strings(self):
        assert diagnose.clean_steps(["  a\n  b ", "a b", "", "   ", 7, None, {"x": 1}, "c"]) == ["a b", "c"]

    def test_caps_count_and_length(self):
        steps = [f"step {i}" for i in range(10)]
        assert diagnose.clean_steps(steps) == steps[: diagnose.MAX_MANUAL_STEPS]
        long = diagnose.clean_steps(["x" * 1000])[0]
        assert len(long) == diagnose.MAX_STEP_CHARS
        assert long.endswith("…")

    @pytest.mark.parametrize("junk", [None, "one string", 5, {"a": "b"}])
    def test_non_list_is_empty(self, junk):
        assert diagnose.clean_steps(junk) == []


class TestManualStepsFromModel:
    def test_schema_requires_a_string_list(self):
        schema = diagnose.reply_schema("network_dns")
        assert "manual_steps" in schema["required"]
        assert schema["properties"]["manual_steps"] == {"type": "array", "items": {"type": "string"}}

    def test_prompt_asks_for_steps_and_explains_the_hop_test(self):
        prompt = diagnose._system_prompt("network_dns")
        assert "manual_steps" in prompt
        assert "never run" in prompt
        assert "hop" in prompt

    def test_system_prompt_is_base_plus_class_hint(self):
        prompt = diagnose._system_prompt("network_dns")
        assert prompt.startswith(diagnose._BASE_PROMPT)
        assert diagnose.SYMPTOM_CLASSES["network_dns"]["prompt"] in prompt

    def test_base_prompt_is_class_neutral(self):
        assert "dns" not in diagnose._BASE_PROMPT.lower()
        assert "hop" not in diagnose._BASE_PROMPT.lower()

    def test_drive_uses_the_class_rules(self, engine, monkeypatch):
        sentinel = diagnose._verdict("likely", "local", "SENTINEL", "r", rule_hits=["sentinel"])
        monkeypatch.setitem(
            diagnose.SYMPTOM_CLASSES,
            "t_rules",
            {"label": "T", "slots": (), "wave1": (), "escalate": (), "prompt": "", "rules": lambda ev, host: sentinel},
        )
        monkeypatch.setattr(diagnose, "model_unavailable_reason", lambda: "no_api_key")
        started = diagnose.start_diagnosis("x", symptom_class="t_rules")
        diagnose._run_session(started["session_id"])
        assert diagnose._sessions[started["session_id"]]["rule_verdict"]["headline"] == "SENTINEL"

    def test_repair_image_needs_the_system_modules_hit(self):
        v = {"status": "likely", "locus": "local", "suggested_actions": ["repair_image"], "manual_steps": []}
        dropped = diagnose.apply_guards(v, {}, {"rule_hits": ["app_crash_repeat"]})
        assert dropped["suggested_actions"] == []
        kept = diagnose.apply_guards(
            v, {}, {"rule_hits": ["app_crash_repeat", "system_modules"], "status": "likely", "locus": "local"}
        )
        assert kept["suggested_actions"] == ["repair_image"]

    def test_parse_reply_cleans_steps(self):
        _, v = diagnose.parse_reply({**REPLY, "manual_steps": ["  Do X ", "Do X", 3]}, "network_dns")
        assert v["manual_steps"] == ["Do X"]

    @pytest.mark.parametrize("junk", [None, "Do X", 7])
    def test_missing_or_malformed_steps_are_not_fatal(self, junk):
        reply = {**REPLY, "manual_steps": junk}
        if junk is None:
            del reply["manual_steps"]
        kind, v = diagnose.parse_reply(reply, "network_dns")
        assert kind == "verdict"
        assert v["manual_steps"] == []

    def test_model_steps_kept_and_capped(self):
        out = diagnose.apply_guards(_model_verdict(manual_steps=[f"s{i}" for i in range(9)]), {}, {})
        assert out["manual_steps"] == [f"s{i}" for i in range(diagnose.MAX_MANUAL_STEPS)]

    def test_agreeing_model_without_steps_borrows_the_rule_steps(self):
        rule = diagnose.evaluate_rules(_fixture_evidence("dns_filtered_by_router"), "hynote.ai")
        out = diagnose.apply_guards(_model_verdict(manual_steps=[]), {}, rule)
        assert out["manual_steps"] == rule["manual_steps"]

    @pytest.mark.parametrize("over", [{"status": "inconclusive"}, {"locus": "unknown"}])
    def test_no_borrowing_when_the_model_disagrees_or_is_unsure(self, over):
        rule = diagnose.evaluate_rules(_fixture_evidence("dns_filtered_by_router"), "hynote.ai")
        out = diagnose.apply_guards(_model_verdict(manual_steps=[], **over), {}, rule)
        assert out["manual_steps"] == []

    def test_model_steps_win_over_rule_steps(self):
        rule = diagnose.evaluate_rules(_fixture_evidence("dns_filtered_by_router"), "hynote.ai")
        out = diagnose.apply_guards(_model_verdict(manual_steps=["Model step"]), {}, rule)
        assert out["manual_steps"] == ["Model step"]

    def test_external_override_replaces_the_model_steps(self):
        rule = diagnose.evaluate_rules(_fixture_evidence("hynote_zone_missing_a"), "hynote.ai")
        out = diagnose.apply_guards(_model_verdict(manual_steps=["Flush your DNS"]), {}, rule)
        assert out["locus"] == "external_cause"
        assert out["manual_steps"] == rule["manual_steps"]

    def test_out_of_rounds_stand_in_has_steps_key(self):
        assert diagnose._OUT_OF_ROUNDS["manual_steps"] == []


class TestRedact:
    @pytest.fixture(autouse=True)
    def _user(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "Al")

    def test_username_in_paths_any_case(self):
        assert diagnose.redact(r"C:\Users\Al\x", ["username"]) == r"C:\Users\<user>\x"
        assert diagnose.redact(r"C:\USERS\al\x", ["username"]) == r"C:\USERS\<user>\x"

    def test_username_is_whole_word_only(self):
        assert diagnose.redact("local alpha", ["username"]) == "local alpha"

    def test_username_plain_word(self):
        assert diagnose.redact("Al reported", ["username"]) == "<user> reported"

    def test_self_host_is_replaced_whole_token_any_case(self, monkeypatch):
        monkeypatch.setattr(diagnose.socket, "gethostname", lambda: "shigs78-pc24")
        assert diagnose.redact({"m": "SHIGS78-PC24 restarted"}, ["self_host"]) == {"m": "<this-pc> restarted"}
        assert diagnose.redact(r"\\shigs78-pc24\share", ["self_host"]) == r"\\<this-pc>\share"

    def test_self_host_leaves_longer_tokens_alone(self, monkeypatch):
        monkeypatch.setattr(diagnose.socket, "gethostname", lambda: "shigs78-pc24")
        text = "myshigs78-pc24x and shigs78-pc245"
        assert diagnose.redact(text, ["self_host"]) == text

    def test_self_host_empty_hostname_is_a_no_op(self, monkeypatch):
        monkeypatch.setattr(diagnose.socket, "gethostname", lambda: "")
        assert diagnose.redact("anything", ["self_host"]) == "anything"

    def test_self_host_placeholder_survives_username_pass(self, monkeypatch):
        monkeypatch.setattr(diagnose.socket, "gethostname", lambda: "box")
        assert diagnose.redact("box", ["self_host", "username"]) == "<this-pc>"

    def test_crash_style_evidence_leaks_nothing_into_the_payload(self, monkeypatch):
        """C4: planted user name, PC name, serial and MAC never reach the preview."""
        monkeypatch.setattr(diagnose.socket, "gethostname", lambda: "SHIGS78-PC24")
        monkeypatch.setitem(
            diagnose.dp.PROBES,
            "t.crash",
            diagnose.dp.Probe("t.crash", "T", "crash", lambda s: {}, redact=("username", "serial", "mac", "self_host")),
        )
        session = {
            "symptom": "the computer crashed",
            "symptom_class": "network_dns",
            "slots": {},
            "evidence": [
                {
                    "key": "t.crash",
                    "label": "T",
                    "ok": True,
                    "data": {
                        "path": r"C:\Users\Al\AppData\x.dll",
                        "host": "SHIGS78-PC24",
                        "serialNumber": "S6S2NS0TA41838Z",
                        "nic": "3c:ed:12:aa:bb:cc",
                    },
                }
            ],
        }
        text = diagnose.build_payload(session)
        for leak in ("\\\\Al\\\\", "SHIGS78-PC24", "S6S2NS0TA41838Z", "3c:ed:12:aa:bb:cc"):
            assert leak not in text, leak
        for placeholder in ("<this-pc>", "<serial>", "<mac>", "<user>"):
            assert placeholder in text, placeholder

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_username_unset_or_blank_leaves_input(self, monkeypatch, value):
        if value is None:
            monkeypatch.delenv("USERNAME", raising=False)
        else:
            monkeypatch.setenv("USERNAME", value)
        assert diagnose.redact("Al reported", ["username"]) == "Al reported"

    def test_username_is_regex_escaped(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "a.b")
        assert diagnose.redact("a.b and axb", ["username"]) == "<user> and axb"

    def test_username_idempotent_even_for_placeholder_like_name(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "user")
        once = diagnose.redact(r"user at C:\Users\user", ["username"])
        assert once == r"<user> at C:\Users\<user>"
        assert diagnose.redact(once, ["username"]) == once

    @pytest.mark.parametrize("mac", ["aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "Aa:bB-cC:dd-Ee:fF"])
    def test_mac_both_separators(self, mac):
        assert diagnose.redact(f"adapter {mac} up", ["mac"]) == "adapter <mac> up"

    def test_mac_not_applied_unless_requested(self):
        assert diagnose.redact("aa:bb:cc:dd:ee:ff", ["username"]) == "aa:bb:cc:dd:ee:ff"

    def test_serial_key_value_replaced(self):
        assert diagnose.redact({"SerialNumber": "S3Z9NX0K"}, ["serial"]) == {"SerialNumber": "<serial>"}

    def test_serial_replaces_nested_value_and_matches_any_key_containing_serial(self):
        out = diagnose.redact({"a": [{"disk_serial_no": {"x": 1}, "ok": "S3Z9NX0K"}]}, ["serial"])
        assert out == {"a": [{"disk_serial_no": "<serial>", "ok": "S3Z9NX0K"}]}

    def test_local_ip_redacts_only_private(self):
        assert diagnose.redact("192.168.1.1 and 8.8.8.8", ["local_ip"]) == "<private-ip> and 8.8.8.8"

    @pytest.mark.parametrize(
        ("ip", "private"),
        [
            ("10.0.0.5", True),
            ("172.16.0.1", True),
            ("172.31.255.254", True),
            ("172.32.0.1", False),
            ("172.15.0.1", False),
            ("192.168.255.1", True),
            ("192.169.0.1", False),
            ("127.0.0.1", False),
            ("198.51.100.53", False),
            ("999.168.1.1", False),
        ],
    )
    def test_local_ip_boundaries(self, ip, private):
        assert diagnose.redact(ip, ["local_ip"]) == ("<private-ip>" if private else ip)

    def test_local_ip_ignores_longer_dotted_numbers(self):
        assert diagnose.redact("v10.0.0.1.2", ["local_ip"]) == "v10.0.0.1.2"

    def test_local_ip_off_keeps_private_address(self):
        assert diagnose.redact("192.168.1.1", ["username", "mac"]) == "192.168.1.1"

    def test_does_not_mutate_input_and_handles_containers(self):
        original = {"p": ["Al", ("aa:bb:cc:dd:ee:ff", {"n": "Al"})], "n": 5, "f": 1.5, "b": True, "z": None}
        snapshot = copy.deepcopy(original)
        out = diagnose.redact(original, ["username", "mac"])
        assert original == snapshot
        assert out == {"p": ["<user>", ("<mac>", {"n": "<user>"})], "n": 5, "f": 1.5, "b": True, "z": None}
        assert isinstance(out["p"][1], tuple)

    def test_username_never_rewrites_dict_keys(self):
        assert diagnose.redact({"Al": "Al"}, ["username"]) == {"Al": "<user>"}

    def test_mac_still_scrubs_dict_keys(self):
        assert diagnose.redact({"aa:bb:cc:dd:ee:ff": 1}, ["mac"]) == {"<mac>": 1}

    def test_username_applied_last_so_it_cannot_eat_mac_octets(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "Ed")
        assert diagnose.redact("3c:ed:12:34:56:78", ["username", "mac"]) == "<mac>"
        assert diagnose.redact("10.0.0.5 and 3C-ED-12-34-56-78", ["username", "mac", "local_ip"]) == (
            "<private-ip> and <mac>"
        )
        assert diagnose.redact("Ed at 3c:ed:12:34:56:78", ["username", "mac"]) == "<user> at <mac>"

    def test_protect_keeps_host_but_not_profile_path(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "al")
        text = r"al.example.com sub.al.example.com. AL.EXAMPLE.COM C:\Users\al\x al"
        out = diagnose.redact(text, ["username"], protect="al.example.com")
        assert out == r"al.example.com sub.al.example.com. AL.EXAMPLE.COM C:\Users\<user>\x <user>"

    def test_protect_gives_no_exemption_for_single_label_or_username_itself(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "al")
        assert diagnose.redact("al", ["username"], protect="al") == "<user>"
        assert diagnose.redact("al", ["username"], protect="AL") == "<user>"
        assert diagnose.redact("al.example.com", ["username"], protect=None) == "<user>.example.com"

    def test_unknown_class_is_ignored(self):
        assert diagnose.redact("Al", ["nonsense"]) == "Al"


def _session(**over):
    session = {
        "symptom": "hynote.ai won't load",
        "symptom_class": "network_dns",
        "slots": {"target_host": "hynote.ai"},
        "round": 0,
        "evidence": [],
        "rule_verdict": {
            "status": "confident",
            "locus": "external_cause",
            "headline": "hynote.ai has no web address record",
            "rule_hits": ["external_no_address"],
        },
    }
    session.update(over)
    return session


class TestBuildPayload:
    @pytest.fixture(autouse=True)
    def _user(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "Al")

    def test_planted_secrets_never_leave_but_diagnostic_facts_do(self):
        session = _session(
            symptom=r"Al says hynote.ai won't load, log at C:\Users\Al\err.txt",
            evidence=[
                {
                    "key": "dns.client_config",
                    "label": "This PC's DNS settings",
                    "ok": True,
                    "data": {
                        "adapters": [{"mac": "AA-BB-CC-DD-EE-FF", "dns": ["198.51.100.53"]}],
                        "profile": r"C:\Users\al\AppData",
                    },
                    "elapsed_ms": 3.0,
                },
                {
                    "key": "net.gateway",
                    "label": "Ping the default gateway",
                    "ok": True,
                    "data": {"gateway": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"},
                    "elapsed_ms": 4.0,
                },
            ],
        )
        text = diagnose.build_payload(session)
        assert "AA-BB-CC-DD-EE-FF" not in text
        assert "aa:bb:cc:dd:ee:ff" not in text
        assert not re.search(r"(?<![A-Za-z0-9])al(?![A-Za-z0-9])", text, re.IGNORECASE)
        assert "hynote.ai" in text
        assert "198.51.100.53" in text
        assert "<user>" in text
        assert "<mac>" in text
        # local_ip is off for the network class, so the gateway address stays.
        assert "192.168.1.1" in text

    def test_serial_redacted_only_where_the_probe_declares_it(self, monkeypatch):
        probe = diagnose.dp.Probe("x.y", "X", "c", lambda s: {}, redact=("serial",))
        monkeypatch.setitem(diagnose.dp.PROBES, "x.y", probe)
        ev = [{"key": "x.y", "label": "X", "ok": True, "data": {"SerialNumber": "S3Z9NX0K"}, "elapsed_ms": 1}]
        text = diagnose.build_payload(_session(evidence=ev))
        assert "S3Z9NX0K" not in text
        assert "<serial>" in text

    def test_unknown_probe_key_gets_only_username(self):
        ev = [{"key": "nope", "label": "N", "ok": True, "data": {"mac": "aa:bb:cc:dd:ee:ff", "u": "Al"}}]
        text = diagnose.build_payload(_session(evidence=ev))
        assert "aa:bb:cc:dd:ee:ff" in text
        assert "<user>" in text

    def test_shape_and_fields(self):
        payload = json.loads(diagnose.build_payload(_session(round=1)))
        assert set(payload) == {
            "schema_version",
            "symptom",
            "symptom_class",
            "slots",
            "round",
            "rounds_remaining",
            "capabilities",
            "evidence",
            "rule_finding",
            "available_probes",
            "available_actions",
            "local_utc_offset",
        }
        assert payload["schema_version"] == 1
        assert payload["round"] == 1
        assert payload["rounds_remaining"] == diagnose.MAX_ROUNDS - 1
        assert payload["capabilities"] == {"dnspython": diagnose.dp.HAVE_DNSPYTHON}
        assert payload["slots"] == {"target_host": "hynote.ai"}
        assert payload["rule_finding"] == {
            "status": "confident",
            "locus": "external_cause",
            "headline": "hynote.ai has no web address record",
            "rule_hits": ["external_no_address"],
        }

    def test_max_rounds_is_two(self):
        assert diagnose.MAX_ROUNDS == 2

    def test_capabilities_follow_have_dnspython(self, monkeypatch):
        monkeypatch.setattr(diagnose.dp, "HAVE_DNSPYTHON", False)
        assert json.loads(diagnose.build_payload(_session()))["capabilities"] == {"dnspython": False}

    def test_available_actions_is_the_whole_registry_sorted(self):
        actions = json.loads(diagnose.build_payload(_session()))["available_actions"]
        registry = diagnose.remediation.REMEDIATION_REGISTRY
        assert [a["key"] for a in actions] == sorted(registry)
        assert set(actions[0]) == {"key", "label", "description"}
        assert actions[0]["label"] == registry[actions[0]["key"]]["label"]

    def test_available_probes_excludes_already_run_escalations(self):
        ev = [{"key": "dns.trace_delegation", "label": "T", "ok": True, "data": {}}]
        probes = json.loads(diagnose.build_payload(_session(evidence=ev)))["available_probes"]
        escalate = diagnose.SYMPTOM_CLASSES["network_dns"]["escalate"]
        assert [p["key"] for p in probes] == [k for k in escalate if k != "dns.trace_delegation"]
        assert probes[0] == {"key": "dns.dnssec_check", "label": diagnose.dp.PROBES["dns.dnssec_check"].label}

    def test_available_probes_empty_for_unknown_class(self):
        payload = json.loads(diagnose.build_payload(_session(symptom_class=None)))
        assert payload["available_probes"] == []

    def test_deterministic(self):
        session = _session(symptom="Al: hynote.ai down")
        assert diagnose.build_payload(session) == diagnose.build_payload(session)

    def test_session_is_not_mutated(self):
        session = _session(symptom="Al: hynote.ai down")
        snapshot = copy.deepcopy(session)
        diagnose.build_payload(session)
        assert session == snapshot

    def test_non_ascii_kept_and_keys_sorted(self):
        text = diagnose.build_payload(_session(symptom="can’t be reached"))
        assert "can’t be reached" in text
        keys = list(json.loads(text))
        assert keys == sorted(keys)

    def test_minimal_session_does_not_raise(self):
        payload = json.loads(diagnose.build_payload({}))
        assert payload["evidence"] == []
        assert payload["rule_finding"]["rule_hits"] == []

    def test_mac_octets_survive_username_that_is_a_hex_pair(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "Ed")
        ev = [{"key": "dns.client_config", "label": "L", "ok": True, "data": {"mac": "3C-ED-12-34-56-78"}}]
        text = diagnose.build_payload(_session(evidence=ev))
        assert "3C" not in text
        assert "12-34" not in text
        assert "<mac>" in text

    def test_target_host_containing_username_is_not_rewritten(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "al")
        host = "al.example.com"
        session = _session(
            symptom=rf"{host} won't load, see C:\Users\al\x",
            slots={"target_host": host},
            evidence=[
                {
                    "key": "dns.resolve_direct",
                    "label": "L",
                    "ok": False,
                    "error": "timeout resolving sub.al.example.com. for al",
                }
            ],
            rule_verdict={"status": "confident", "locus": "local", "headline": f"{host} is blocked", "rule_hits": []},
        )
        payload = json.loads(diagnose.build_payload(session))
        assert payload["slots"] == {"target_host": host}
        assert payload["symptom"] == rf"{host} won't load, see C:\Users\<user>\x"
        assert payload["evidence"][0]["error"] == "timeout resolving sub.al.example.com. for <user>"
        assert payload["rule_finding"]["headline"] == f"{host} is blocked"

    def test_single_label_target_equal_to_username_gets_no_exemption(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "al")
        payload = json.loads(diagnose.build_payload(_session(symptom="al is down", slots={"target_host": "al"})))
        assert payload["symptom"] == "<user> is down"
        assert payload["slots"] == {"target_host": "<user>"}

    @pytest.mark.parametrize("name", ["dns", "local", "data"])
    def test_username_equal_to_our_vocabulary_leaves_structure_alone(self, monkeypatch, name):
        monkeypatch.setenv("USERNAME", name)
        ev = [
            {
                "key": "dns.trace_delegation",
                "label": "Follow the dns delegation chain from the local data",
                "ok": True,
                "data": {"data": f"{name} says hi", "local": [name], "dns": {"who": name}},
                "elapsed_ms": 1.0,
            }
        ]
        verdict = {"status": "confident", "locus": "local", "headline": f"{name} h", "rule_hits": ["stale_cache"]}
        payload = json.loads(diagnose.build_payload(_session(evidence=ev, rule_verdict=verdict)))
        item = payload["evidence"][0]
        assert item["key"] == "dns.trace_delegation"
        assert item["label"] == ev[0]["label"]
        assert set(item["data"]) == {"data", "local", "dns"}
        assert item["data"] == {"data": "<user> says hi", "local": ["<user>"], "dns": {"who": "<user>"}}
        assert payload["rule_finding"]["locus"] == "local"
        assert payload["rule_finding"]["headline"] == "<user> h"
        assert payload["rule_finding"]["rule_hits"] == ["stale_cache"]
        assert payload["symptom_class"] == "network_dns"
        assert [p["key"] for p in payload["available_probes"]] == [
            k for k in diagnose.SYMPTOM_CLASSES["network_dns"]["escalate"] if k != "dns.trace_delegation"
        ]
        assert all(a["label"] and a["key"] for a in payload["available_actions"])

    def test_username_dns_keeps_wave1_probe_keys_and_labels(self, monkeypatch):
        monkeypatch.setenv("USERNAME", "dns")
        ev = [{"key": "dns.resolve_cached", "label": "DNS cache", "ok": True, "data": {"resolved": True}}]
        item = json.loads(diagnose.build_payload(_session(evidence=ev)))["evidence"][0]
        assert item["key"] == "dns.resolve_cached"
        assert item["label"] == "DNS cache"


# ---------------------------------------------------------------------------
# Model call, reply validation, guards (Task 10)
# ---------------------------------------------------------------------------


@pytest.fixture
def model_env(monkeypatch):
    """A fake API key and a zeroed call counter, restored after the test."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(diagnose, "_model_calls", 0)


def _fake_client(content=None, stop_reason="end_turn", raises=None):
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        if raises is not None:
            raise raises
        return types.SimpleNamespace(content=content, stop_reason=stop_reason)

    client = types.SimpleNamespace(beta=types.SimpleNamespace(messages=types.SimpleNamespace(create=create)))
    client.calls = calls
    return client


def _text(obj):
    return types.SimpleNamespace(type="text", text=obj if isinstance(obj, str) else json.dumps(obj))


REPLY = {
    "kind": "verdict",
    "need_probes": [],
    "status": "likely",
    "locus": "local",
    "headline": "h",
    "reasoning": "r",
    "evidence_refs": ["dns.resolve_cached"],
    "suggested_actions": ["flush_dns"],
    "manual_steps": ["Restart the browser."],
    "no_local_fix_reason": "",
}


class TestModelUnavailableReason:
    def test_sdk_missing(self, monkeypatch):
        monkeypatch.setattr(diagnose, "anthropic", None)
        assert diagnose.model_unavailable_reason() == "sdk_missing"

    def test_no_api_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert diagnose.model_unavailable_reason() == "no_api_key"

    def test_call_cap(self, model_env, monkeypatch):
        monkeypatch.setattr(diagnose, "_model_calls", diagnose.MAX_DIAGNOSE_CALLS)
        assert diagnose.model_unavailable_reason() == "call_cap"

    def test_available(self, model_env):
        assert diagnose.model_unavailable_reason() is None


class TestCallModel:
    def test_happy_path_returns_dict_and_counts_the_call(self, model_env, mocker):
        fake = _fake_client([_text(REPLY)])
        mocker.patch.object(diagnose, "_get_client", return_value=fake)
        assert diagnose._call_model("payload", "network_dns") == REPLY
        assert diagnose._model_calls == 1

    def test_create_kwargs(self, model_env, mocker):
        fake = _fake_client([_text(REPLY)])
        mocker.patch.object(diagnose, "_get_client", return_value=fake)
        diagnose._call_model("the payload text", "network_dns")
        kw = fake.calls[0]
        if "DIAGNOSE_MODEL" not in os.environ:
            assert diagnose.DIAGNOSE_MODEL == "claude-opus-5-5"
        assert kw["model"] == diagnose.DIAGNOSE_MODEL
        assert kw["messages"][0]["content"] == "the payload text"
        assert kw["system"] == diagnose._system_prompt("network_dns")
        assert kw["max_tokens"] == 16000
        # Opus 5.5 defaults to medium effort; a diagnosis is reasoning work.
        assert kw["output_config"]["effort"] == "high"
        assert kw["output_config"]["format"]["type"] == "json_schema"
        assert kw["output_config"]["format"]["schema"] == diagnose.reply_schema("network_dns")
        assert "server-side-fallback-2026-07-01" in kw["betas"]
        assert kw["extra_body"] == {"fallbacks": "default"}
        assert "thinking" not in kw

    def test_reads_the_text_block_among_thinking_and_fallback_blocks(self, model_env, mocker):
        content = [
            types.SimpleNamespace(type="thinking", thinking="hmm"),
            types.SimpleNamespace(type="fallback", reason="declined"),
            _text(REPLY),
        ]
        mocker.patch.object(diagnose, "_get_client", return_value=_fake_client(content))
        assert diagnose._call_model("p", "network_dns") == REPLY

    @pytest.mark.parametrize("stop_reason", ["refusal", "max_tokens"])
    def test_refusal_or_truncation_is_none_and_refunded(self, model_env, mocker, stop_reason):
        fake = _fake_client([_text(REPLY)], stop_reason=stop_reason)
        mocker.patch.object(diagnose, "_get_client", return_value=fake)
        assert diagnose._call_model("p", "network_dns") is None
        assert diagnose._model_calls == 0

    def test_api_connection_error_is_none_and_refunded(self, model_env, mocker, capsys):
        import anthropic

        err = anthropic.APIConnectionError(request=mocker.Mock())
        mocker.patch.object(diagnose, "_get_client", return_value=_fake_client(raises=err))
        assert diagnose._call_model("secret payload", "network_dns") is None
        assert diagnose._model_calls == 0
        out = capsys.readouterr().out
        assert "[Diagnose] model call failed: APIConnectionError" in out
        assert "secret payload" not in out
        assert "test-key" not in out

    def test_unexpected_exception_is_none(self, model_env, mocker):
        mocker.patch.object(diagnose, "_get_client", return_value=_fake_client(raises=RuntimeError("boom")))
        assert diagnose._call_model("p", "network_dns") is None
        assert diagnose._model_calls == 0

    @pytest.mark.parametrize("text", ["not json {", "[1, 2]", ""])
    def test_bad_text_is_none_and_refunded(self, model_env, mocker, text):
        mocker.patch.object(diagnose, "_get_client", return_value=_fake_client([_text(text)]))
        assert diagnose._call_model("p", "network_dns") is None
        assert diagnose._model_calls == 0

    def test_no_text_block_is_none(self, model_env, mocker):
        content = [types.SimpleNamespace(type="thinking", thinking="hmm")]
        mocker.patch.object(diagnose, "_get_client", return_value=_fake_client(content))
        assert diagnose._call_model("p", "network_dns") is None
        assert diagnose._model_calls == 0

    def test_unavailable_never_builds_a_client(self, monkeypatch, mocker):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        get = mocker.patch.object(diagnose, "_get_client")
        assert diagnose._call_model("p", "network_dns") is None
        get.assert_not_called()

    def test_cap_reached_never_calls(self, model_env, monkeypatch, mocker):
        monkeypatch.setattr(diagnose, "_model_calls", diagnose.MAX_DIAGNOSE_CALLS)
        get = mocker.patch.object(diagnose, "_get_client")
        assert diagnose._call_model("p", "network_dns") is None
        get.assert_not_called()
        assert diagnose._model_calls == diagnose.MAX_DIAGNOSE_CALLS

    def test_get_client_is_built_once_with_the_timeout(self, monkeypatch, mocker):
        monkeypatch.setattr(diagnose, "_client", None)
        ctor = mocker.patch.object(diagnose, "anthropic")
        first = diagnose._get_client("k")
        assert diagnose._get_client("k") is first
        ctor.Anthropic.assert_called_once_with(api_key="k", timeout=diagnose.DIAGNOSE_TIMEOUT_S)


class TestReplySchema:
    def test_action_enum_matches_registry_and_probes_match_class(self):
        schema = diagnose.reply_schema("network_dns")
        props = schema["properties"]
        assert props["suggested_actions"]["items"]["enum"] == sorted(remediation.REMEDIATION_REGISTRY)
        assert props["need_probes"]["items"]["enum"] == list(diagnose.SYMPTOM_CLASSES["network_dns"]["escalate"])
        assert props["kind"]["enum"] == ["verdict", "need_probes"]
        assert props["status"]["enum"] == ["confident", "likely", "inconclusive"]
        assert props["locus"]["enum"] == ["local", "external_cause", "unknown"]

    def test_flat_strict_and_every_field_required(self):
        schema = diagnose.reply_schema("network_dns")
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])

        def objects(node):
            if isinstance(node, dict):
                if node.get("type") == "object":
                    yield node
                for v in node.values():
                    yield from objects(v)
            elif isinstance(node, list):
                for v in node:
                    yield from objects(v)

        assert all(o["additionalProperties"] is False for o in objects(schema))


class TestParseReply:
    def test_verdict_has_exactly_the_model_keys(self):
        kind, verdict = diagnose.parse_reply(dict(REPLY), "network_dns")
        assert kind == "verdict"
        assert set(verdict) == {
            "status",
            "locus",
            "headline",
            "reasoning",
            "evidence_refs",
            "suggested_actions",
            "manual_steps",
            "no_local_fix_reason",
        }
        assert verdict["suggested_actions"] == ["flush_dns"]

    def test_unknown_action_dropped_and_logged_once(self, capsys):
        reply = {**REPLY, "suggested_actions": ["flush_dns", "format_c", "format_c", "reset_winsock"]}
        _, verdict = diagnose.parse_reply(reply, "network_dns")
        assert verdict["suggested_actions"] == ["flush_dns", "reset_winsock"]
        assert capsys.readouterr().out.count("[Diagnose] dropped unknown action") == 1

    def test_non_string_action_entry_is_dropped(self):
        _, verdict = diagnose.parse_reply(
            {**REPLY, "suggested_actions": [["flush_dns"], None, "flush_dns"]}, "network_dns"
        )
        assert verdict["suggested_actions"] == ["flush_dns"]

    def test_unknown_probe_dropped(self, capsys):
        reply = {**REPLY, "kind": "need_probes", "need_probes": ["net.tcp_connect", "dns.resolve_cached", "bogus"]}
        # dns.resolve_cached is a wave-1 probe, not an escalation probe: also dropped.
        assert diagnose.parse_reply(reply, "network_dns") == ("need_probes", ["net.tcp_connect"])
        assert "[Diagnose] dropped unknown probe" in capsys.readouterr().out

    def test_probe_requests_are_capped_at_four(self):
        escalate = list(diagnose.SYMPTOM_CLASSES["network_dns"]["escalate"])
        reply = {**REPLY, "kind": "need_probes", "need_probes": escalate}
        assert diagnose.parse_reply(reply, "network_dns") == ("need_probes", escalate[:4])

    def test_evidence_refs_coerced_to_strings(self):
        _, verdict = diagnose.parse_reply({**REPLY, "evidence_refs": ["a", 2]}, "network_dns")
        assert verdict["evidence_refs"] == ["a", "2"]

    @pytest.mark.parametrize(
        "patch",
        [
            {"status": "certain"},
            {"locus": "cloud"},
            {"kind": "other"},
            {"headline": None},
            {"reasoning": 5},
            {"no_local_fix_reason": None},
            {"evidence_refs": "dns.resolve_cached"},
            {"suggested_actions": "flush_dns"},
        ],
    )
    def test_wrong_types_or_values_are_none(self, patch):
        assert diagnose.parse_reply({**REPLY, **patch}, "network_dns") is None

    def test_need_probes_not_a_list_is_none(self):
        assert diagnose.parse_reply({**REPLY, "kind": "need_probes", "need_probes": "x"}, "network_dns") is None

    def test_non_dict_is_none(self):
        assert diagnose.parse_reply([REPLY], "network_dns") is None


def _model_verdict(**over):
    return {
        "status": "likely",
        "locus": "local",
        "headline": "h",
        "reasoning": "r",
        "evidence_refs": ["dns.resolve_cached"],
        "suggested_actions": ["flush_dns"],
        "no_local_fix_reason": "",
        **over,
    }


def _agreeing_evidence():
    return _cache_ev(True, _res("NOERROR", "1.2.3.4"), addresses=["1.2.3.4"])


class TestApplyGuards:
    def test_s1_model_says_local_flush_dns_but_rules_say_external(self):
        evidence = _fixture_evidence("hynote_zone_missing_a")
        rule = diagnose.evaluate_rules(evidence, "hynote.ai")
        assert (rule["status"], rule["locus"]) == ("confident", "external_cause")
        out = diagnose.apply_guards(_model_verdict(), evidence, rule)
        assert out["locus"] == "external_cause"
        assert out["suggested_actions"] == []
        # The model's text contradicted the override, so the rule's text replaces it.
        assert out["headline"] == rule["headline"]
        assert out["status"] == rule["status"] == "confident"
        assert out["reasoning"] == rule["reasoning"]
        assert out["no_local_fix_reason"] == rule["no_local_fix_reason"]
        assert out["source"] == "rules"
        assert out["overridden_model_locus"] == "local"
        assert out["rule_hits"] == rule["rule_hits"]

    def test_override_merges_evidence_refs_rule_first_deduplicated(self):
        evidence = _fixture_evidence("hynote_zone_missing_a")
        rule = diagnose.evaluate_rules(evidence, "hynote.ai")
        verdict = _model_verdict(evidence_refs=["net.gateway", "dns.resolve_cached"])
        out = diagnose.apply_guards(verdict, evidence, rule)
        assert out["evidence_refs"] == [*rule["evidence_refs"], "net.gateway"]

    def test_inconclusive_model_does_not_hide_a_confident_external_rule(self):
        evidence = _fixture_evidence("hynote_zone_missing_a")
        rule = diagnose.evaluate_rules(evidence, "hynote.ai")
        out = diagnose.apply_guards(_model_verdict(status="inconclusive", locus="unknown"), evidence, rule)
        assert (out["status"], out["locus"]) == ("confident", "external_cause")
        assert out["headline"] == rule["headline"]
        assert out["suggested_actions"] == []
        assert out["overridden_model_locus"] == "unknown"

    def test_model_already_external_keeps_its_text(self):
        evidence = _fixture_evidence("hynote_zone_missing_a")
        rule = diagnose.evaluate_rules(evidence, "hynote.ai")
        verdict = _model_verdict(locus="external_cause", headline="model words", no_local_fix_reason="mine")
        out = diagnose.apply_guards(verdict, evidence, rule)
        assert out["locus"] == "external_cause"
        assert out["headline"] == "model words"
        assert out["no_local_fix_reason"] == "mine"
        assert out["source"] == "model"
        assert "overridden_model_locus" not in out
        assert out["evidence_refs"] == ["dns.resolve_cached"]

    def test_model_already_external_with_empty_reason_gets_the_rules(self):
        evidence = _fixture_evidence("hynote_zone_missing_a")
        rule = diagnose.evaluate_rules(evidence, "hynote.ai")
        out = diagnose.apply_guards(_model_verdict(locus="external_cause"), evidence, rule)
        assert out["no_local_fix_reason"] == rule["no_local_fix_reason"]
        assert out["source"] == "model"

    def test_cache_agrees_drops_flush_dns_keeps_other_actions(self):
        verdict = _model_verdict(suggested_actions=["flush_dns", "reset_winsock"])
        out = diagnose.apply_guards(verdict, _agreeing_evidence(), {"rule_hits": ["cache_agrees"]})
        assert out["suggested_actions"] == ["reset_winsock"]

    def test_flush_dns_kept_when_cache_disagrees(self):
        evidence = _cache_ev(False, _res("NOERROR", "1.2.3.4"))
        out = diagnose.apply_guards(_model_verdict(), evidence, {"rule_hits": []})
        assert out["suggested_actions"] == ["flush_dns"]

    def test_unknown_actions_dropped(self):
        verdict = _model_verdict(suggested_actions=["format_c", "reset_winsock", 7])
        out = diagnose.apply_guards(verdict, {}, {})
        assert out["suggested_actions"] == ["reset_winsock"]

    def test_inconclusive_carries_no_actions(self):
        out = diagnose.apply_guards(_model_verdict(status="inconclusive", locus="unknown"), {}, {})
        assert out["suggested_actions"] == []

    def test_model_external_cause_carries_no_actions(self):
        out = diagnose.apply_guards(_model_verdict(locus="external_cause"), {}, {})
        assert out["suggested_actions"] == []

    @pytest.mark.parametrize(
        "rule",
        [
            {"status": "likely", "locus": "external_cause", "rule_hits": ["stale_cache_external"]},
            {"status": "confident", "locus": "local", "rule_hits": ["hosts_override"]},
        ],
    )
    def test_rule_that_is_not_confident_external_leaves_locus_alone(self, rule):
        out = diagnose.apply_guards(_model_verdict(locus="local"), {}, rule)
        assert out["locus"] == "local"
        assert out["suggested_actions"] == ["flush_dns"]
        assert out["rule_hits"] == rule["rule_hits"]

    def test_inputs_are_not_mutated_and_all_keys_present(self):
        verdict = _model_verdict(suggested_actions=["flush_dns", "bogus"])
        rule = {"status": "confident", "locus": "external_cause", "rule_hits": ["x"], "no_local_fix_reason": "why"}
        v0, r0 = copy.deepcopy(verdict), copy.deepcopy(rule)
        out = diagnose.apply_guards(verdict, _agreeing_evidence(), rule)
        assert verdict == v0
        assert rule == r0
        assert set(out) == VERDICT_KEYS | {"overridden_model_locus"}
        out["rule_hits"].append("y")
        assert rule["rule_hits"] == ["x"]

    def test_non_overridden_verdict_has_exactly_the_verdict_keys(self):
        out = diagnose.apply_guards(_model_verdict(), {}, {})
        assert set(out) == VERDICT_KEYS

    @pytest.mark.parametrize(
        "odd",
        [
            {"status": "Inconclusive"},
            {"status": None},
            {"locus": None},
            {"locus": "Local"},
            {"locus": "cloud"},
            {"status": "certain"},
        ],
    )
    def test_odd_status_or_locus_carries_no_actions(self, odd):
        out = diagnose.apply_guards(_model_verdict(**odd), {}, {})
        assert out["suggested_actions"] == []

    def test_missing_locus_carries_no_actions(self):
        verdict = _model_verdict()
        del verdict["locus"]
        assert diagnose.apply_guards(verdict, {}, {})["suggested_actions"] == []

    @pytest.mark.parametrize(("status", "locus"), [("confident", "local"), ("likely", "unknown"), ("likely", "local")])
    def test_actions_survive_on_confident_or_likely_local_or_unknown(self, status, locus):
        out = diagnose.apply_guards(_model_verdict(status=status, locus=locus), {}, {})
        assert out["suggested_actions"] == ["flush_dns"]

    def test_tolerates_a_sparse_verdict(self):
        out = diagnose.apply_guards({"status": "likely", "locus": "local"}, {}, None)
        assert out["suggested_actions"] == []
        assert out["evidence_refs"] == []
        assert out["no_local_fix_reason"] == ""
        assert out["rule_hits"] == []


# ---------------------------------------------------------------------------
# Session engine, egress gate, history (Task 11)
# ---------------------------------------------------------------------------

_TERMINAL = ("done", "evidence_only", "error")
_REAL_WAIT_FOR_CONSENT = diagnose._wait_for_consent
_WAVE1 = list(diagnose.SYMPTOM_CLASSES["network_dns"]["wave1"])
_ESCALATE = list(diagnose.SYMPTOM_CLASSES["network_dns"]["escalate"])


@pytest.fixture(autouse=True)
def _isolated_history(tmp_path, monkeypatch):
    """No test in this file may touch the real diagnose_history.json."""
    path = tmp_path / "diagnose_history.json"
    monkeypatch.setattr(diagnose, "DIAGNOSE_HISTORY_FILE", str(path))
    return path


class FakeProbes:
    """Stands in for dp.run_probes: fixture evidence for its keys, an empty success otherwise."""

    def __init__(self, fixture="hynote_zone_missing_a", raises=None):
        self.evidence = _fixture_evidence(fixture)
        self.raises = raises
        self.calls = []
        self.slots = []

    def __call__(self, keys, slots):
        self.calls.append(list(keys))
        self.slots.append(dict(slots))
        if self.raises is not None:
            raise self.raises
        return [
            {"key": k, "label": k, **self.evidence.get(k, {"ok": True, "data": {}}), "elapsed_ms": 1.0} for k in keys
        ]


class FakeModel:
    """Stands in for diagnose._call_model: scripted replies, the last one repeating."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, payload_text, class_key):
        self.calls.append(payload_text)
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


def _need(*keys):
    return {**REPLY, "kind": "need_probes", "need_probes": list(keys)}


@pytest.fixture
def engine(monkeypatch):
    """The engine with probes, the model and the worker thread faked. Consent approves by default.

    ``answer`` scripts the consent waits: each takes the next decision (the
    last repeats), records the status it saw, and approves or declines through
    the real ``submit_consent``; ``None`` is a timeout.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(diagnose, "anthropic", types.SimpleNamespace())
    spawned = []
    monkeypatch.setattr(diagnose, "_spawn_worker", spawned.append)
    eng = types.SimpleNamespace(spawned=spawned, waits=[], previews=[])

    def use_probes(probes):
        eng.probes = probes
        monkeypatch.setattr(diagnose.dp, "run_probes", probes)

    def use_model(*replies):
        eng.model = FakeModel(*replies)
        monkeypatch.setattr(diagnose, "_call_model", eng.model)

    def answer(*decisions, auto=False):
        queue = list(decisions)

        def wait(session):
            sid = session["session_id"]
            status = diagnose.get_status(sid)
            eng.waits.append(status["state"])
            eng.previews.append(status["preview"])
            decision = queue.pop(0) if len(queue) > 1 else queue[0]
            if decision is not None:
                assert diagnose.submit_consent(sid, decision, auto_followups=auto) == {"ok": True}
            return decision

        monkeypatch.setattr(diagnose, "_wait_for_consent", wait)

    def run(symptom=CHROME_BLOB, **kwargs):
        started = diagnose.start_diagnosis(symptom, **kwargs)
        assert started["state"] == "probing_wave1"
        diagnose._run_session(started["session_id"])
        return diagnose.get_status(started["session_id"])

    eng.use_probes, eng.use_model, eng.answer, eng.run = use_probes, use_model, answer, run
    use_probes(FakeProbes())
    use_model(REPLY)
    answer(True)
    return eng


class TestOptionalSlots:
    """Spec 2026-10-09 §4: a class may declare optional slots, which are kept
    when given but never asked for."""

    @pytest.fixture(autouse=True)
    def _opt_class(self, monkeypatch):
        monkeypatch.setitem(
            diagnose.SYMPTOM_CLASSES,
            "t_opt",
            {"label": "T", "slots": (), "optional_slots": ("app_name",), "wave1": (), "escalate": ()},
        )

    def test_optional_slot_is_kept_when_given(self, engine):
        r = diagnose.start_diagnosis("x", slots={"app_name": "Chrome"}, symptom_class="t_opt")
        assert r["state"] == "probing_wave1"
        assert diagnose._sessions[r["session_id"]]["slots"] == {"app_name": "Chrome"}

    def test_optional_slot_is_never_asked_for(self, engine):
        r = diagnose.start_diagnosis("x", symptom_class="t_opt")
        assert r["state"] == "probing_wave1"
        assert diagnose._sessions[r["session_id"]]["slots"] == {}

    def test_slot_outside_the_class_is_still_dropped(self, engine):
        r = diagnose.start_diagnosis("x", slots={"target_host": "a.com"}, symptom_class="t_opt")
        assert diagnose._sessions[r["session_id"]]["slots"] == {}


class TestCrashClassify:
    """Spec 2026-10-09 §8: crash words pick the crashes class; a crash plus a
    site is a question, never a guess."""

    @pytest.mark.parametrize(
        ("text", "cls", "expected_app"),
        [
            ("the computer crashed last evening - cna you investigate?", "crashes", None),
            ("Chrome keeps crashing", "crashes", "Chrome"),
            ("Microsoft Teams keeps crashing", "crashes", "Microsoft Teams"),
            ('"Chrome" crashed!', "crashes", "Chrome"),
            ("My computer keeps crashing", "crashes", None),
            ("Today Spotify froze again", "crashes", "Spotify"),
            ("blue screen this morning", "crashes", None),
            ("PC won't boot sometimes", "crashes", None),
            ("it won’t start", "crashes", None),
            ("the screen went black and it shut down", "crashes", None),
            ("I need to change my DNS", "network_dns", None),
        ],
    )
    def test_table(self, text, cls, expected_app):
        r = diagnose.classify(text)
        assert r["symptom_class"] == cls
        assert r["slots"].get("app_name") == expected_app
        if cls == "crashes":
            assert r["missing"] == []

    def test_crash_plus_site_asks(self):
        r = diagnose.classify("Chrome crashed loading example.com")
        assert r["symptom_class"] is None
        assert r["candidates"] == ["example.com"]

    def test_crash_plus_network_word_asks(self):
        assert diagnose.classify("the internet crashed")["symptom_class"] is None

    def test_hang_is_a_whole_word(self):
        assert diagnose.classify("please change the wallpaper")["symptom_class"] is None
        assert diagnose.classify("my hungry cat")["symptom_class"] is None


class TestCrashClass:
    def test_registered_with_spec_values(self):
        spec = diagnose.SYMPTOM_CLASSES["crashes"]
        assert spec["label"] == "Crashes, freezes & startup problems"
        assert spec["slots"] == ()
        assert spec["optional_slots"] == ("app_name",)
        assert len(spec["wave1"]) == 10
        assert set(spec["escalate"]) == {"crash.window_30d", "crash.app_detail", "crash.event_context"}

    def test_rules_are_the_crash_rules(self):
        import diagnose_crash_rules as dcr

        ev = json.loads((FIXTURE_DIR / "crash_power_loss.json").read_text(encoding="utf-8"))["evidence"]
        assert diagnose.SYMPTOM_CLASSES["crashes"]["rules"](ev, None) == dcr.evaluate_crash_rules(ev)

    def test_prompt_mentions_local_time_and_repair_image(self):
        prompt = diagnose._system_prompt("crashes")
        assert "local_utc_offset" in prompt
        assert "repair_image" in prompt
        assert "dns" not in diagnose.SYMPTOM_CLASSES["crashes"]["prompt"].lower()

    def test_c1_sentence_starts_a_session_without_asking(self, engine):
        r = diagnose.start_diagnosis("the computer crashed last evening - cna you investigate?")
        assert r["state"] == "probing_wave1"
        assert diagnose._sessions[r["session_id"]]["symptom_class"] == "crashes"

    def test_named_app_is_kept_as_a_slot(self, engine):
        r = diagnose.start_diagnosis("Chrome keeps crashing")
        assert diagnose._sessions[r["session_id"]]["slots"] == {"app_name": "Chrome"}

    def test_typed_app_name_is_trimmed(self, engine):
        r = diagnose.start_diagnosis("my pc froze", slots={"app_name": "  Spotify  "}, symptom_class="crashes")
        assert diagnose._sessions[r["session_id"]]["slots"] == {"app_name": "Spotify"}

    @pytest.mark.parametrize("bad", [42, ["Chrome"], "x" * 81])
    def test_bad_app_name_is_rejected(self, engine, bad):
        with pytest.raises(ValueError):
            diagnose.start_diagnosis("my pc froze", slots={"app_name": bad}, symptom_class="crashes")

    def test_blank_app_name_counts_as_not_given(self, engine):
        r = diagnose.start_diagnosis("my pc froze", slots={"app_name": "   "}, symptom_class="crashes")
        assert diagnose._sessions[r["session_id"]]["slots"] == {}

    def test_payload_carries_the_local_utc_offset(self):
        payload = json.loads(diagnose.build_payload(_session()))
        assert re.fullmatch(r"[+-]\d\d:\d\d", payload["local_utc_offset"])


class TestStartDiagnosis:
    def test_no_host_asks_for_one_and_creates_no_session(self, engine):
        r = diagnose.start_diagnosis("the internet is broken")
        assert r == {
            "ok": True,
            "state": "awaiting_slots",
            "symptom_class": "network_dns",
            "need": ["target_host"],
            "candidates": [],
        }
        assert diagnose._sessions == {}
        assert engine.spawned == []

    def test_two_candidates_are_offered_not_guessed(self, engine):
        r = diagnose.start_diagnosis("google.com works but hynote.ai doesn't load")
        assert r["state"] == "awaiting_slots"
        assert r["candidates"] == ["google.com", "hynote.ai"]
        assert r["need"] == ["target_host"]
        assert diagnose._sessions == {}

    def test_unclassified_symptom_asks_for_the_class(self, engine):
        r = diagnose.start_diagnosis("my printer jams")
        assert r["state"] == "awaiting_slots"
        assert r["symptom_class"] is None
        assert r["need"] == ["symptom_class"]
        assert diagnose._sessions == {}

    def test_creates_a_session_and_spawns_its_worker(self, engine):
        r = diagnose.start_diagnosis(CHROME_BLOB)
        assert r["ok"] is True
        assert r["state"] == "probing_wave1"
        assert re.fullmatch(r"[A-Za-z0-9_-]{16,32}", r["session_id"])
        assert engine.spawned == [r["session_id"]]
        status = diagnose.get_status(r["session_id"])
        assert status["state"] == "probing_wave1"
        assert status["slots"] == {"target_host": "hynote.ai"}
        assert status["symptom_class"] == "network_dns"

    def test_slots_override_the_classifier(self, engine):
        r = diagnose.start_diagnosis("hynote.ai won't load", slots={"target_host": "Example.COM."})
        assert diagnose.get_status(r["session_id"])["slots"] == {"target_host": "example.com"}

    def test_slots_fill_the_missing_host(self, engine):
        r = diagnose.start_diagnosis("google.com works but hynote.ai doesn't", slots={"target_host": "hynote.ai"})
        assert r["state"] == "probing_wave1"

    @pytest.mark.parametrize("host", ["", "not a host", 42, "a" * 300])
    def test_invalid_host_in_slots_raises(self, engine, host):
        with pytest.raises(ValueError, match="invalid host"):
            diagnose.start_diagnosis("hynote.ai won't load", slots={"target_host": host})
        assert diagnose._sessions == {}

    def test_unknown_slot_names_are_dropped(self, engine):
        r = diagnose.start_diagnosis("hynote.ai won't load", slots={"target_host": "hynote.ai", "evil": "x"})
        assert diagnose.get_status(r["session_id"])["slots"] == {"target_host": "hynote.ai"}

    def test_none_valued_slot_does_not_hide_the_classifiers_host(self, engine):
        r = diagnose.start_diagnosis("hynote.ai won't load", slots={"target_host": None})
        assert r["state"] == "probing_wave1"
        assert diagnose.get_status(r["session_id"])["slots"] == {"target_host": "hynote.ai"}

    def test_none_valued_slot_still_asks_when_the_classifier_found_nothing(self, engine):
        r = diagnose.start_diagnosis("the internet is broken", slots={"target_host": None})
        assert r["state"] == "awaiting_slots"
        assert r["need"] == ["target_host"]

    def test_non_dict_slots_raise(self, engine):
        with pytest.raises(ValueError):
            diagnose.start_diagnosis("hynote.ai won't load", slots=["hynote.ai"])

    def test_symptom_class_with_slots_works_without_keywords(self, engine):
        r = diagnose.start_diagnosis("my printer jams", slots={"target_host": "hynote.ai"}, symptom_class="network_dns")
        assert r["state"] == "probing_wave1"
        assert diagnose.get_status(r["session_id"])["symptom_class"] == "network_dns"

    def test_symptom_class_without_a_host_still_asks_for_it(self, engine):
        r = diagnose.start_diagnosis("my printer jams", symptom_class="network_dns")
        assert r["state"] == "awaiting_slots"
        assert r["need"] == ["target_host"]

    def test_unknown_symptom_class_raises(self, engine):
        with pytest.raises(ValueError, match="unknown symptom class"):
            diagnose.start_diagnosis("hynote.ai won't load", symptom_class="printer")

    @pytest.mark.parametrize("symptom", [None, 7, b"hynote.ai", "", "   \n", "x" * (diagnose.MAX_SYMPTOM_CHARS + 1)])
    def test_bad_symptom_raises(self, engine, symptom):
        with pytest.raises(ValueError):
            diagnose.start_diagnosis(symptom)

    def test_symptom_at_the_length_limit_is_accepted(self, engine):
        head = "hynote.ai won't load "
        symptom = head + "x" * (diagnose.MAX_SYMPTOM_CHARS - len(head))
        assert diagnose.start_diagnosis(symptom)["state"] == "probing_wave1"

    def test_busy_when_max_active_sessions_are_running(self, engine):
        for _ in range(diagnose._MAX_ACTIVE):
            assert diagnose.start_diagnosis(CHROME_BLOB)["ok"] is True
        assert diagnose.start_diagnosis(CHROME_BLOB) == {"ok": False, "error": "busy"}
        assert len(diagnose._sessions) == diagnose._MAX_ACTIVE
        assert not any(s["superseded"] or s["consent_event"].is_set() for s in diagnose._sessions.values())

    @staticmethod
    def _park(sid):
        """Put a (worker-less) session where a real worker sits while the preview shows."""
        diagnose._sessions[sid]["state"] = "awaiting_consent"

    def test_at_the_limit_the_parked_session_is_superseded_not_the_probing_one(self, engine):
        parked = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        probing = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        self._park(parked)
        new = diagnose.start_diagnosis(CHROME_BLOB)
        assert new["ok"] is True
        old = diagnose._sessions[parked]
        assert (old["superseded"], old["consent"], old["consent_event"].is_set()) == (True, False, True)
        assert diagnose._sessions[probing]["superseded"] is False
        assert diagnose._sessions[probing]["consent_event"].is_set() is False

    def test_the_oldest_parked_session_is_superseded_first(self, engine):
        first = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        second = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        self._park(second)
        self._park(first)
        diagnose._sessions[first]["created"] -= 10
        assert diagnose.start_diagnosis(CHROME_BLOB)["ok"] is True
        assert diagnose._sessions[first]["superseded"] is True
        assert diagnose._sessions[second]["superseded"] is False
        # The superseded one no longer counts, so the next start supersedes the other parked one.
        assert diagnose.start_diagnosis(CHROME_BLOB)["ok"] is True
        assert diagnose._sessions[second]["superseded"] is True
        # Now both active sessions are probing: busy.
        assert diagnose.start_diagnosis(CHROME_BLOB) == {"ok": False, "error": "busy"}

    def test_an_answered_preview_is_not_superseded(self, engine):
        sids = [diagnose.start_diagnosis(CHROME_BLOB)["session_id"] for _ in range(diagnose._MAX_ACTIVE)]
        for sid in sids:
            self._park(sid)
            assert diagnose.submit_consent(sid, True) == {"ok": True}  # the worker just has not woken yet
        assert diagnose.start_diagnosis(CHROME_BLOB) == {"ok": False, "error": "busy"}
        assert all(diagnose._sessions[sid]["consent"] is True for sid in sids)

    def test_superseded_worker_ends_superseded_without_calling_the_model(self, engine, monkeypatch):
        def wait(session):
            # Two more diagnoses start while this one's preview is showing: the
            # first fits, the second supersedes this parked one.
            assert diagnose.start_diagnosis(CHROME_BLOB)["ok"] is True
            assert diagnose.start_diagnosis(CHROME_BLOB)["ok"] is True
            return _REAL_WAIT_FOR_CONSENT(session)  # returns at once: the event is set

        monkeypatch.setattr(diagnose, "_wait_for_consent", wait)
        status = engine.run()
        assert (status["state"], status["reason"]) == ("evidence_only", "superseded")
        assert engine.model.calls == []
        assert diagnose.load_history()[0]["sent"] == []
        assert diagnose.submit_consent(status["session_id"], True) == {"ok": False, "error": "not awaiting consent"}

    def test_finished_sessions_do_not_count_as_busy(self, engine):
        for _ in range(diagnose._MAX_ACTIVE + 1):
            assert engine.run()["state"] == "done"

    def test_worker_start_failure_marks_the_session_error(self, engine, monkeypatch):
        def boom(sid):
            raise RuntimeError("can't start new thread")

        monkeypatch.setattr(diagnose, "_spawn_worker", boom)
        r = diagnose.start_diagnosis(CHROME_BLOB)
        status = diagnose.get_status(r["session_id"])
        assert status["state"] == "error"
        assert "can't start new thread" in status["error"]


class TestEgressGate:
    def test_declined_never_calls_the_model(self, engine):
        engine.answer(False)
        status = engine.run()
        assert engine.model.calls == []
        assert (status["state"], status["reason"]) == ("evidence_only", "declined")
        assert diagnose.load_history()[0]["sent"] == []

    def test_consent_timeout_never_calls_the_model(self, engine):
        engine.answer(None)
        status = engine.run()
        assert engine.model.calls == []
        assert (status["state"], status["reason"]) == ("evidence_only", "consent_timeout")
        assert diagnose.load_history()[0]["sent"] == []

    def test_the_model_gets_exactly_the_previewed_payload(self, engine):
        status = engine.run()
        assert engine.waits == ["awaiting_consent"]
        assert isinstance(engine.previews[0], str)
        assert engine.previews[0]
        assert engine.model.calls == [engine.previews[0]]
        assert status["state"] == "done"
        assert diagnose.load_history()[0]["sent"] == [engine.previews[0]]

    def test_preview_is_the_redacted_payload(self, engine, monkeypatch):
        monkeypatch.setenv("USERNAME", "Zed")
        engine.run("hynote.ai won't load for Zed")
        preview = json.loads(engine.previews[0])
        assert preview["symptom"] == "hynote.ai won't load for <user>"
        assert preview["round"] == 0
        assert [e["key"] for e in preview["evidence"]] == _WAVE1

    @pytest.mark.parametrize("reason", ["no_api_key", "sdk_missing", "call_cap"])
    def test_model_unavailable_is_evidence_only_without_asking(self, engine, monkeypatch, reason):
        if reason == "no_api_key":
            monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        elif reason == "sdk_missing":
            monkeypatch.setattr(diagnose, "anthropic", None)
        else:
            monkeypatch.setattr(diagnose, "_model_calls", diagnose.MAX_DIAGNOSE_CALLS)
        status = engine.run()
        assert (status["state"], status["reason"]) == ("evidence_only", reason)
        assert engine.waits == []
        assert engine.model.calls == []
        assert status["rule_verdict"]["locus"] == "external_cause"  # S3: the rules still answer
        assert diagnose.load_history()[0]["sent"] == []

    def test_preview_only_exposed_while_awaiting_consent(self, engine):
        sid = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        assert diagnose.get_status(sid)["preview"] is None
        diagnose._run_session(sid)
        assert engine.previews[0]
        assert diagnose.get_status(sid)["preview"] is None


class TestEscalation:
    def test_escalation_cap_still_lets_a_confident_external_rule_win(self, engine):
        # R22: the forced verdict goes through apply_guards, so the hynote answer is not hidden.
        engine.use_model(_need("dns.trace_delegation"))
        status = engine.run()
        assert len(engine.model.calls) == 3
        assert status["state"] == "done"
        assert status["round"] == diagnose.MAX_ROUNDS == 2
        verdict = status["verdict"]
        assert (verdict["status"], verdict["locus"]) == ("confident", "external_cause")
        assert verdict["source"] == "rules"
        assert verdict["overridden_model_locus"] == "unknown"
        assert verdict["headline"] == status["rule_verdict"]["headline"]
        assert verdict["suggested_actions"] == []
        assert status["actions"] == []

    def test_escalation_cap_without_a_confident_rule_is_inconclusive(self, engine):
        engine.use_probes(FakeProbes("healthy_name_resolves"))
        engine.use_model(_need("dns.trace_delegation"))
        status = engine.run("example.com won't load")
        assert len(engine.model.calls) == 3
        assert status["round"] == 2
        verdict = status["verdict"]
        assert (verdict["status"], verdict["locus"]) == ("inconclusive", "unknown")
        assert verdict["headline"] == "Ran out of probe rounds before reaching a conclusion"
        assert verdict["source"] == "engine"
        assert verdict["suggested_actions"] == []
        assert status["actions"] == []

    def test_each_round_asks_for_consent_again(self, engine):
        engine.use_model(_need("dns.trace_delegation"), REPLY)
        engine.run()
        assert engine.waits == ["awaiting_consent", "awaiting_consent"]
        second = json.loads(engine.previews[1])
        assert second["round"] == 1
        assert second["evidence"][-1]["key"] == "dns.trace_delegation"
        assert engine.model.calls == engine.previews

    def test_auto_followups_skips_later_consent(self, engine):
        engine.use_model(_need("dns.trace_delegation"), _need("net.tcp_connect"), REPLY)
        engine.answer(True, auto=True)
        status = engine.run()
        assert len(engine.waits) == 1
        assert len(engine.model.calls) == 3
        assert status["state"] == "done"
        assert len(diagnose.load_history()[0]["sent"]) == 3

    @staticmethod
    def _bypass_parse_reply(monkeypatch, *parsed):
        """Script parse_reply's output so the engine's own key checks are what is tested."""
        replies = iter(parsed)
        monkeypatch.setattr(diagnose, "parse_reply", lambda obj, class_key: next(replies))

    def test_unknown_escalation_key_is_dropped_but_the_round_counts(self, engine, monkeypatch):
        self._bypass_parse_reply(monkeypatch, ("need_probes", ["evil.rm_rf"]), ("verdict", _model_verdict()))
        status = engine.run()
        assert engine.probes.calls == [_WAVE1]
        assert status["round"] == 1
        assert status["state"] == "done"

    def test_unknown_key_from_the_model_never_reaches_the_probes(self, engine):
        engine.use_model(_need("evil.rm_rf", "dns.resolve_cached"), REPLY)
        status = engine.run()
        assert engine.probes.calls == [_WAVE1]
        assert status["round"] == 1

    def test_at_most_four_probes_per_round(self, engine, monkeypatch):
        assert diagnose.MAX_PROBES_PER_ROUND == 4
        assert len(_ESCALATE) == 5
        self._bypass_parse_reply(monkeypatch, ("need_probes", list(_ESCALATE)), ("verdict", _model_verdict()))
        engine.run()
        assert engine.probes.calls[1] == _ESCALATE[:4]

    def test_model_asking_for_five_runs_four(self, engine):
        engine.use_model(_need(*_ESCALATE), REPLY)
        engine.run()
        assert engine.probes.calls[1] == _ESCALATE[:4]

    def test_probes_already_run_are_not_run_again(self, engine):
        engine.use_model(_need("dns.trace_delegation"), _need("dns.trace_delegation", "net.tcp_connect"), REPLY)
        status = engine.run()
        assert engine.probes.calls[1:] == [["dns.trace_delegation"], ["net.tcp_connect"]]
        assert [e["key"] for e in status["evidence"]] == [*_WAVE1, "dns.trace_delegation", "net.tcp_connect"]

    def test_escalation_runs_with_the_session_slots(self, engine):
        engine.use_model(_need("net.tcp_connect"), REPLY)
        engine.run()
        assert engine.probes.slots == [{"target_host": "hynote.ai"}] * 2


def _ip_literal_evidence(authoritative=True):
    """Evidence for a ``192.168.1.50`` target as the DNS probes would misreport it (R38)."""
    ev = {
        "dns.interception": _ok({"intercepted": False}),
        "dns.resolve_cached": _ok({"resolved": True, "addresses": ["192.168.1.50"], "error": None}),
        "dns.resolve_direct": _ok(
            {
                "dnspython": True,
                "resolvers": [
                    _res("NXDOMAIN", name="cloudflare", transport="tls"),
                    _res("NXDOMAIN", name="google", transport="tls"),
                ],
            }
        ),
        "dns.record_sweep": _ok(
            {"rcode": "NXDOMAIN", "records": {k: [] for k in ("A", "AAAA", "CNAME", "MX", "TXT", "SOA", "NS")}}
        ),
        "net.gateway": _ok({"gateways": ["192.168.1.1"], "reachable": True}),
        "net.control_domain": _ok({"connected": True, "resolved": True}),
    }
    if authoritative:
        ev["dns.authoritative"] = _ok(
            {
                "zone": "",
                "nameservers": [
                    {
                        "name": "a.root-servers.net",
                        "ip": "198.41.0.4",
                        "rcode": "NXDOMAIN",
                        "nodata": False,
                        "aa": True,
                        "answers": [],
                    }
                ],
            }
        )
    return ev


class TestIpLiteralTarget:
    """An IP literal has no DNS, so the name probes and DNS rules must stay out of it (R38)."""

    @pytest.mark.parametrize("host", ["192.168.1.50", "10.0.0.1", "::1", "2001:db8::1"])
    def test_is_ip_literal_true(self, host):
        assert diagnose._is_ip_literal(host) is True

    @pytest.mark.parametrize("host", ["example.com", "", None, 42, "192.168.1", "999.1.1.1", "not an ip"])
    def test_is_ip_literal_false_never_raises(self, host):
        assert diagnose._is_ip_literal(host) is False

    def test_dns_only_set_covers_exactly_the_name_probes(self):
        assert set(diagnose._DNS_ONLY_PROBES) == {
            "dns.resolve_cached",
            "dns.resolve_direct",
            "dns.authoritative",
            "dns.record_sweep",
            "dns.hosts_file",
            "dns.trace_delegation",
            "dns.dnssec_check",
        }
        assert {"dns.interception", "dns.client_config"}.isdisjoint(diagnose._DNS_ONLY_PROBES)

    @pytest.mark.parametrize("authoritative", [True, False])
    def test_no_dns_rule_fires_for_an_ip(self, authoritative):
        v = diagnose.evaluate_rules(_ip_literal_evidence(authoritative), "192.168.1.50")
        assert v["locus"] != "external_cause"
        assert (v["status"], v["locus"]) == ("inconclusive", "unknown")
        assert "flush_dns" not in v["suggested_actions"]
        assert v["suggested_actions"] == []
        assert v["rule_hits"] == []

    def test_same_evidence_for_a_name_still_fires_dns_rules(self):
        v = diagnose.evaluate_rules(_ip_literal_evidence(), "example.com")
        assert v["rule_hits"] != []

    def test_interception_is_not_reported_for_an_ip(self):
        ev = _ip_literal_evidence()
        ev["dns.interception"] = _ok({"intercepted": True})
        v = diagnose.evaluate_rules(ev, "192.168.1.50")
        assert v["rule_hits"] == []

    def test_dead_gateway_still_fires_for_an_ip(self):
        ev = _ip_literal_evidence()
        ev["net.gateway"] = _ok({"gateways": ["192.168.1.1"], "reachable": False})
        ev["net.control_domain"] = _ok({"connected": False, "resolved": False})
        v = diagnose.evaluate_rules(ev, "192.168.1.50")
        assert v["rule_hits"] == ["dead_gateway"]
        assert v["suggested_actions"] == ["reset_network_adapter"]
        assert "192.168.1.50" in v["reasoning"]

    def test_apply_guards_drops_flush_dns_for_an_ip_target(self):
        out = diagnose.apply_guards(_model_verdict(), {}, {"rule_hits": []}, "192.168.1.50")
        assert out["suggested_actions"] == []
        out = diagnose.apply_guards(
            _model_verdict(suggested_actions=["flush_dns", "reset_network_adapter"]), {}, {}, "192.168.1.50"
        )
        assert out["suggested_actions"] == ["reset_network_adapter"]

    def test_apply_guards_keeps_flush_dns_for_a_name_target(self):
        out = diagnose.apply_guards(_model_verdict(), {}, {}, "example.com")
        assert out["suggested_actions"] == ["flush_dns"]
        assert diagnose.apply_guards(_model_verdict(), {}, {})["suggested_actions"] == ["flush_dns"]

    def test_build_payload_lists_no_dns_only_probes_for_an_ip(self):
        session = _session(slots={"target_host": "192.168.1.50"}, symptom="can't reach 192.168.1.50")
        keys = [p["key"] for p in json.loads(diagnose.build_payload(session))["available_probes"]]
        assert keys == ["net.tcp_connect", "net.tls_handshake", "net.traceroute"]
        assert set(keys).isdisjoint(diagnose._DNS_ONLY_PROBES)

    def test_build_payload_still_lists_dns_probes_for_a_name(self):
        keys = [p["key"] for p in json.loads(diagnose.build_payload(_session()))["available_probes"]]
        assert "dns.trace_delegation" in keys
        assert "dns.dnssec_check" in keys

    def test_drive_runs_no_dns_only_probe_in_wave_one(self, engine):
        engine.use_probes(FakeProbes("ip_literal_target"))
        status = engine.run("can't reach 192.168.1.50 from this PC")
        assert status["slots"] == {"target_host": "192.168.1.50"}
        assert engine.probes.calls == [[k for k in _WAVE1 if k not in diagnose._DNS_ONLY_PROBES]]
        assert "dns.interception" in engine.probes.calls[0]
        assert "dns.client_config" in engine.probes.calls[0]
        assert set(engine.probes.calls[0]).isdisjoint(diagnose._DNS_ONLY_PROBES)

    def test_drive_final_verdict_has_no_flush_dns_for_an_ip(self, engine):
        engine.use_probes(FakeProbes("ip_literal_target"))
        status = engine.run("can't reach 192.168.1.50 from this PC")
        assert status["state"] == "done"
        assert "flush_dns" not in status["verdict"]["suggested_actions"]
        assert status["actions"] == []

    def test_model_dns_escalation_for_an_ip_runs_nothing_but_the_round_counts(self, engine):
        engine.use_probes(FakeProbes("ip_literal_target"))
        engine.use_model(_need("dns.trace_delegation", "dns.dnssec_check"), REPLY)
        status = engine.run("can't reach 192.168.1.50 from this PC")
        assert len(engine.probes.calls) == 1
        assert status["round"] == 1
        assert status["state"] == "done"

    def test_non_dns_escalation_still_runs_for_an_ip(self, engine):
        engine.use_probes(FakeProbes("ip_literal_target"))
        engine.use_model(_need("dns.trace_delegation", "net.tcp_connect"), REPLY)
        engine.run("can't reach 192.168.1.50 from this PC")
        assert engine.probes.calls[1] == ["net.tcp_connect"]


class TestModelFailures:
    @pytest.mark.parametrize("bad", [None, {"kind": "nonsense"}, {"kind": "verdict", "status": "maybe"}])
    def test_one_failure_then_success_is_done(self, engine, bad):
        engine.use_model(bad, REPLY)
        status = engine.run()
        assert len(engine.model.calls) == 2
        assert engine.model.calls[0] == engine.model.calls[1] == engine.previews[0]
        assert len(engine.waits) == 1  # the retry re-sends the text already approved
        assert status["state"] == "done"

    def test_two_failures_are_evidence_only(self, engine):
        engine.use_model(None)
        status = engine.run()
        assert len(engine.model.calls) == 2
        assert (status["state"], status["reason"]) == ("evidence_only", "model_error")
        assert diagnose.load_history()[0]["sent"] == [engine.previews[0]]


class TestOutcome:
    def test_s1_model_local_flush_dns_ends_external_with_no_actions(self, engine):
        engine.use_model({**REPLY, "locus": "local", "suggested_actions": ["flush_dns"]})
        status = engine.run()
        assert status["state"] == "done"
        assert status["verdict"]["locus"] == "external_cause"
        assert status["verdict"]["suggested_actions"] == []
        assert status["verdict"]["overridden_model_locus"] == "local"
        assert status["actions"] == []

    def test_done_offers_registry_entries_for_the_verdict(self, engine):
        engine.use_probes(FakeProbes("stale_cache_direct_resolves"))
        status = engine.run("example.com won't load")
        assert status["verdict"]["suggested_actions"] == ["flush_dns"]
        assert status["actions"] == [remediation.REMEDIATION_REGISTRY["flush_dns"]]

    def test_evidence_only_offers_the_rule_verdicts_actions(self, engine, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        engine.use_probes(FakeProbes("stale_cache_direct_resolves"))
        status = engine.run("example.com won't load")
        assert status["state"] == "evidence_only"
        assert status["verdict"] is None
        assert [a["id"] for a in status["actions"]] == ["flush_dns"]

    def test_probe_exception_is_error_with_the_message(self, engine):
        engine.use_probes(FakeProbes(raises=RuntimeError("resolver exploded")))
        status = engine.run()
        assert status["state"] == "error"
        assert status["error"] == "resolver exploded"
        assert status["actions"] == []
        assert diagnose.load_history()[0]["state"] == "error"

    def test_model_exception_is_error_and_does_not_escape(self, engine, monkeypatch):
        def boom(payload_text, class_key):
            raise RuntimeError("sdk bug")

        monkeypatch.setattr(diagnose, "_call_model", boom)
        assert engine.run()["state"] == "error"

    def test_history_failure_does_not_escape(self, engine, monkeypatch):
        monkeypatch.setattr(diagnose, "DIAGNOSE_HISTORY_FILE", os.path.join("Z:\\no", "such", "dir", "h.json"))
        assert engine.run()["state"] == "done"

    def test_unknown_session_is_a_no_op(self, engine):
        diagnose._run_session("nope")
        assert diagnose.load_history() == []

    def test_get_status_unknown_id_is_none(self, engine):
        assert diagnose.get_status("nope") is None

    def test_status_carries_the_documented_keys(self, engine):
        status = engine.run()
        assert set(status) == {
            "ok",
            "session_id",
            "state",
            "symptom_class",
            "slots",
            "round",
            "evidence",
            "rule_verdict",
            "preview",
            "verdict",
            "actions",
            "reason",
            "error",
        }
        assert status["ok"] is True
        assert [e["key"] for e in status["evidence"]] == _WAVE1

    def test_status_is_a_snapshot(self, engine):
        status = engine.run()
        status["evidence"].clear()
        status["rule_verdict"]["locus"] = "x"
        again = diagnose.get_status(status["session_id"])
        assert again["evidence"]
        assert again["rule_verdict"]["locus"] == "external_cause"


class TestSubmitConsent:
    def test_unknown_id_is_none(self, engine):
        assert diagnose.submit_consent("nope", True) is None

    def test_wrong_state_is_refused(self, engine):
        sid = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        assert diagnose.submit_consent(sid, True) == {"ok": False, "error": "not awaiting consent"}

    def test_second_consent_after_the_session_moved_on_is_refused(self, engine):
        sid = engine.run()["session_id"]
        assert diagnose.submit_consent(sid, True) == {"ok": False, "error": "not awaiting consent"}

    def test_double_click_while_awaiting_is_refused(self, engine, monkeypatch):
        second = []

        def wait(session):
            sid = session["session_id"]
            assert diagnose.submit_consent(sid, False) == {"ok": True}
            second.append(diagnose.submit_consent(sid, True))
            return session["consent"]

        monkeypatch.setattr(diagnose, "_wait_for_consent", wait)
        status = engine.run()
        assert second == [{"ok": False, "error": "not awaiting consent"}]
        assert status["reason"] == "declined"
        assert engine.model.calls == []


class TestWaitForConsent:
    @staticmethod
    def _session():
        return {"session_id": "s", "state": "awaiting_consent", "consent": None, "consent_event": threading.Event()}

    def test_returns_the_recorded_decision(self):
        session = self._session()
        session["consent"] = False
        session["consent_event"].set()
        assert diagnose._wait_for_consent(session) is False

    def test_timeout_is_none(self, monkeypatch):
        monkeypatch.setattr(diagnose, "_CONSENT_TIMEOUT_S", 0.01)
        assert diagnose._wait_for_consent(self._session()) is None


class TestSessionEviction:
    def test_old_finished_sessions_are_evicted_and_live_ones_kept(self, engine):
        done_sid = engine.run()["session_id"]
        live_sid = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        stale = time.time() - diagnose._SESSION_TTL_S - 1
        diagnose._sessions[done_sid]["updated"] = stale
        diagnose._sessions[live_sid]["updated"] = stale
        diagnose.start_diagnosis(CHROME_BLOB)
        assert done_sid not in diagnose._sessions
        assert live_sid in diagnose._sessions

    def test_fresh_finished_sessions_survive(self, engine):
        sid = engine.run()["session_id"]
        diagnose.start_diagnosis(CHROME_BLOB)
        assert sid in diagnose._sessions

    def test_session_count_is_bounded_oldest_finished_first(self, engine):
        sids = [engine.run()["session_id"] for _ in range(diagnose._SESSIONS_MAX)]
        now = time.time()
        for i, sid in enumerate(reversed(sids)):
            diagnose._sessions[sid]["updated"] = now - i  # sids[0] is the oldest
        new = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        assert len(diagnose._sessions) == diagnose._SESSIONS_MAX
        assert sids[0] not in diagnose._sessions
        assert new in diagnose._sessions
        assert sids[1] in diagnose._sessions


class TestHistory:
    def test_entry_records_what_was_sent(self, engine, monkeypatch):
        monkeypatch.setenv("USERNAME", "Zed")
        status = engine.run(r"hynote.ai won't load, see C:\Users\Zed\log.txt")
        (entry,) = diagnose.load_history()
        assert set(entry) == {
            "ts",
            "session_id",
            "symptom",
            "symptom_class",
            "target_host",
            "state",
            "reason",
            "verdict",
            "sent",
            "model",
        }
        assert entry["session_id"] == status["session_id"]
        assert entry["symptom"] == r"hynote.ai won't load, see C:\Users\<user>\log.txt"
        assert entry["symptom_class"] == "network_dns"
        assert entry["target_host"] == "hynote.ai"
        assert entry["state"] == "done"
        assert entry["verdict"] == status["verdict"]
        assert entry["sent"] == engine.previews
        assert entry["model"] == diagnose.DIAGNOSE_MODEL

    def test_nothing_sent_records_no_model(self, engine):
        engine.answer(False)
        engine.run()
        assert diagnose.load_history()[0]["model"] is None

    def test_newest_first_and_capped(self, engine, monkeypatch, _isolated_history):
        monkeypatch.setattr(diagnose, "_HISTORY_MAX", 3)
        engine.answer(False)
        sids = [engine.run()["session_id"] for _ in range(5)]
        assert [e["session_id"] for e in diagnose.load_history()] == sids[:1:-1]
        on_disk = json.loads(_isolated_history.read_text(encoding="utf-8"))
        assert [e["session_id"] for e in on_disk] == sids[2:]  # newest last on disk

    def test_write_is_atomic(self, engine, _isolated_history):
        engine.run()
        assert _isolated_history.exists()
        assert not Path(str(_isolated_history) + ".tmp").exists()

    def test_missing_file_is_empty(self):
        assert diagnose.load_history() == []

    @pytest.mark.parametrize("content", ["{not json", '{"a": 1}', ""])
    def test_corrupt_file_is_empty(self, _isolated_history, content):
        _isolated_history.write_text(content, encoding="utf-8")
        assert diagnose.load_history() == []

    def test_corrupt_file_is_replaced_on_the_next_append(self, engine, _isolated_history):
        _isolated_history.write_text("{not json", encoding="utf-8")
        engine.run()
        assert len(diagnose.load_history()) == 1


def _poll(sid, states, timeout=5.0):
    deadline = time.monotonic() + timeout
    status = diagnose.get_status(sid)
    while status["state"] not in states and time.monotonic() < deadline:
        time.sleep(0.02)
        status = diagnose.get_status(sid)
    return status


@pytest.fixture
def live(monkeypatch):
    """Real worker threads and the real consent wait; probes and the model faked.

    Every worker thread is captured. Teardown declines whatever is still
    waiting and joins each thread BEFORE monkeypatch is undone, so no worker
    can write history after the test's history path is restored (R25).
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(diagnose, "anthropic", types.SimpleNamespace())
    monkeypatch.setattr(diagnose, "_CONSENT_TIMEOUT_S", 10)
    monkeypatch.setattr(diagnose.dp, "run_probes", FakeProbes())
    model = FakeModel(REPLY)
    monkeypatch.setattr(diagnose, "_call_model", model)
    threads = []
    real_spawn = diagnose._spawn_worker

    def spawn(sid):
        threads.append(real_spawn(sid))
        return threads[-1]

    monkeypatch.setattr(diagnose, "_spawn_worker", spawn)
    yield types.SimpleNamespace(model=model, threads=threads)
    deadline = time.monotonic() + 10
    while any(t.is_alive() for t in threads) and time.monotonic() < deadline:
        for sid in list(diagnose._sessions):
            diagnose.submit_consent(sid, False)
        time.sleep(0.02)
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - time.monotonic()))
    assert not any(t.is_alive() for t in threads), "a diagnose worker outlived its test"


class TestRealThreads:
    def test_model_is_not_called_until_consent_then_exactly_once(self, live):
        sid = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        status = _poll(sid, ("awaiting_consent", *_TERMINAL))
        assert status["state"] == "awaiting_consent"
        preview = status["preview"]
        assert live.model.calls == []
        assert diagnose.submit_consent(sid, True) == {"ok": True}
        status = _poll(sid, _TERMINAL)
        assert status["state"] == "done"
        assert live.model.calls == [preview]
        live.threads[0].join(timeout=10)
        assert not live.threads[0].is_alive()
        assert diagnose.load_history()[0]["session_id"] == sid  # written before the thread ended

    def test_two_parked_previews_do_not_lock_out_a_new_diagnosis(self, live):
        first = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        assert _poll(first, ("awaiting_consent", *_TERMINAL))["state"] == "awaiting_consent"
        second = diagnose.start_diagnosis(CHROME_BLOB)["session_id"]
        assert _poll(second, ("awaiting_consent", *_TERMINAL))["state"] == "awaiting_consent"
        third = diagnose.start_diagnosis(CHROME_BLOB)
        assert third["ok"] is True
        status = _poll(first, _TERMINAL)
        assert (status["state"], status["reason"]) == ("evidence_only", "superseded")
        assert diagnose.get_status(second)["state"] == "awaiting_consent"
        assert live.model.calls == []


# ---------------------------------------------------------------------------
# /api/diagnose/* routes
# ---------------------------------------------------------------------------


class TestRoutes:
    @pytest.fixture(autouse=True)
    def _no_worker(self, engine):
        """``engine`` stubs ``_spawn_worker`` so no route test starts a thread."""
        self.engine = engine

    @staticmethod
    def _start(client, **body):
        return client.post("/api/diagnose/start", json=body)

    @staticmethod
    def _park(sid, state="awaiting_consent"):
        with diagnose._sessions_lock:
            diagnose._sessions[sid]["state"] = state

    # --- GET /api/diagnose/classes ---
    def test_classes_lists_every_class(self, client):
        resp = client.get("/api/diagnose/classes")
        assert resp.status_code == 200
        data = resp.get_json()
        assert [c["key"] for c in data] == list(diagnose.SYMPTOM_CLASSES)
        net = data[0]
        assert net["label"] == diagnose.SYMPTOM_CLASSES["network_dns"]["label"]
        assert net["slots"] == ["target_host"]
        assert net["optional_slots"] == []

    # --- POST /api/diagnose/start ---
    def test_start_returns_session_id(self, client):
        resp = self._start(client, symptom=CHROME_BLOB)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert data["state"] == "probing_wave1"
        assert data["session_id"] in diagnose._sessions
        assert self.engine.spawned == [data["session_id"]]

    def test_start_accepts_slots_and_class(self, client):
        resp = self._start(
            client, symptom="cannot open it", slots={"target_host": "example.com"}, symptom_class="network_dns"
        )
        assert resp.status_code == 200
        sid = resp.get_json()["session_id"]
        assert diagnose.get_status(sid)["slots"] == {"target_host": "example.com"}

    def test_start_awaiting_slots_is_200_unchanged(self, client):
        resp = self._start(client, symptom="my printer keeps jamming")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["state"] == "awaiting_slots"
        assert data["need"] == ["symptom_class"]
        assert self.engine.spawned == []

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"symptom": ""},
            {"symptom": "   "},
            {"symptom": 5},
            {"symptom": ["a"]},
            {"symptom": None},
            {"symptom": "x" * (diagnose.MAX_SYMPTOM_CHARS + 1)},
            {"symptom": "site down", "slots": "target_host=a.com"},
            {"symptom": "site down", "slots": ["a.com"]},
            {"symptom": "site down", "symptom_class": 7},
            {"symptom": "site down", "symptom_class": "no_such_class"},
            {"symptom": "site down", "slots": {"target_host": "not a host!!"}},
            {"symptom": "site down", "slots": {"target_host": 12345}},
        ],
    )
    def test_start_rejects_bad_input_with_400(self, client, body):
        resp = self._start(client, **body)
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["ok"] is False
        assert data["error"]
        assert self.engine.spawned == []

    def test_start_error_text_comes_from_the_engine(self, client):
        resp = self._start(client, symptom="x", symptom_class="no_such_class")
        assert resp.get_json() == {"ok": False, "error": "unknown symptom class"}

    def test_start_body_that_is_not_an_object_is_400(self, client):
        resp = client.post("/api/diagnose/start", json=["symptom"])
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    def test_start_form_post_is_415(self, client):
        resp = client.post("/api/diagnose/start", data="symptom=x", content_type="application/x-www-form-urlencoded")
        assert resp.status_code == 415
        assert self.engine.spawned == []

    def test_start_malformed_json_is_400(self, client):
        resp = client.post("/api/diagnose/start", data="{not json", content_type="application/json")
        assert resp.status_code == 400
        assert self.engine.spawned == []

    def test_start_busy_is_429(self, client):
        for _ in range(diagnose._MAX_ACTIVE):
            assert self._start(client, symptom=CHROME_BLOB).status_code == 200
        resp = self._start(client, symptom=CHROME_BLOB)
        assert resp.status_code == 429
        assert resp.get_json() == {"ok": False, "error": "busy"}

    # --- GET /api/diagnose/status/<session_id> ---
    def test_status_returns_snapshot(self, client):
        sid = self._start(client, symptom=CHROME_BLOB).get_json()["session_id"]
        resp = client.get(f"/api/diagnose/status/{sid}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["session_id"] == sid
        assert data["state"] == "probing_wave1"
        assert data["symptom_class"] == "network_dns"
        for key in ("evidence", "preview", "verdict", "actions", "reason", "error"):
            assert key in data

    def test_status_unknown_id_is_404(self, client):
        resp = client.get("/api/diagnose/status/" + "a" * 22)
        assert resp.status_code == 404
        assert resp.get_json()["ok"] is False

    @pytest.mark.parametrize("bad", ["short", "a" * 33, "has.dot." + "a" * 12, "bad%20space" + "a" * 8])
    def test_status_bad_id_format_is_400_not_404(self, client, bad):
        resp = client.get(f"/api/diagnose/status/{bad}")
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    # --- POST /api/diagnose/consent ---
    def test_consent_approves_awaiting_session(self, client):
        sid = self._start(client, symptom=CHROME_BLOB).get_json()["session_id"]
        self._park(sid)
        resp = client.post("/api/diagnose/consent", json={"session_id": sid, "approved": True})
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True}
        assert diagnose._sessions[sid]["consent"] is True
        assert diagnose._sessions[sid]["auto_followups"] is False

    def test_consent_passes_auto_followups(self, client):
        sid = self._start(client, symptom=CHROME_BLOB).get_json()["session_id"]
        self._park(sid)
        resp = client.post("/api/diagnose/consent", json={"session_id": sid, "approved": True, "auto_followups": True})
        assert resp.status_code == 200
        assert diagnose._sessions[sid]["auto_followups"] is True

    def test_consent_decline_is_200(self, client):
        sid = self._start(client, symptom=CHROME_BLOB).get_json()["session_id"]
        self._park(sid)
        resp = client.post("/api/diagnose/consent", json={"session_id": sid, "approved": False})
        assert resp.status_code == 200
        assert diagnose._sessions[sid]["consent"] is False

    def test_consent_wrong_state_is_409(self, client):
        sid = self._start(client, symptom=CHROME_BLOB).get_json()["session_id"]
        resp = client.post("/api/diagnose/consent", json={"session_id": sid, "approved": True})
        assert resp.status_code == 409
        assert resp.get_json() == {"ok": False, "error": "not awaiting consent"}

    def test_consent_unknown_id_is_404(self, client):
        resp = client.post("/api/diagnose/consent", json={"session_id": "a" * 22, "approved": True})
        assert resp.status_code == 404
        assert resp.get_json()["ok"] is False

    @pytest.mark.parametrize(
        "body",
        [
            {"approved": True},
            {"session_id": "", "approved": True},
            {"session_id": 12345, "approved": True},
            {"session_id": "short", "approved": True},
            {"session_id": "a" * 22},
            {"session_id": "a" * 22, "approved": 1},
            {"session_id": "a" * 22, "approved": "true"},
            {"session_id": "a" * 22, "approved": None},
            {"session_id": "a" * 22, "approved": True, "auto_followups": "yes"},
            {"session_id": "a" * 22, "approved": True, "auto_followups": 1},
        ],
    )
    def test_consent_rejects_bad_input_with_400(self, client, body):
        resp = client.post("/api/diagnose/consent", json=body)
        assert resp.status_code == 400
        assert resp.get_json()["ok"] is False

    def test_consent_bad_input_does_not_touch_the_session(self, client):
        sid = self._start(client, symptom=CHROME_BLOB).get_json()["session_id"]
        self._park(sid)
        resp = client.post("/api/diagnose/consent", json={"session_id": sid, "approved": "true"})
        assert resp.status_code == 400
        assert diagnose._sessions[sid]["consent"] is None

    def test_consent_body_that_is_not_an_object_is_400(self, client):
        resp = client.post("/api/diagnose/consent", json=[1, 2])
        assert resp.status_code == 400

    def test_consent_form_post_is_415(self, client):
        resp = client.post(
            "/api/diagnose/consent", data="session_id=x", content_type="application/x-www-form-urlencoded"
        )
        assert resp.status_code == 415

    # --- GET /api/diagnose/history ---
    def test_history_is_a_list_newest_first(self, client):
        assert client.get("/api/diagnose/history").get_json() == []
        for sid in ("first", "second"):
            diagnose._append_history({"session_id": sid, "symptom": "x"})
        resp = client.get("/api/diagnose/history")
        assert resp.status_code == 200
        assert [e["session_id"] for e in resp.get_json()] == ["second", "first"]


class TestCrashReviewFixes:
    """Fixes from the whole-branch review of the crash bundle (2026-10-09)."""

    @pytest.mark.parametrize(
        ("text", "expected_app"),
        [
            ("Spotify has crashed", "Spotify"),
            ("since yesterday Outlook keeps crashing", "Outlook"),
            ("after the update Outlook keeps crashing", "Outlook"),
            ("Chrome keeps freezing", "Chrome"),
            ("Discord has just frozen", "Discord"),
            ("I think the driver crashed", None),
            ("it has crashed", None),
            ("Word, Excel and Outlook keep crashing", None),
        ],
    )
    def test_app_name_phrasings(self, text, expected_app):
        r = diagnose.classify(text)
        assert r["symptom_class"] == "crashes"
        assert r["slots"].get("app_name") == expected_app

    def test_crash_class_offers_only_repair_image(self):
        session = _session(symptom="it crashed", symptom_class="crashes", slots={}, rule_verdict={})
        actions = json.loads(diagnose.build_payload(session))["available_actions"]
        assert [a["key"] for a in actions] == ["repair_image"]

    def test_network_class_still_offers_the_whole_registry(self):
        actions = json.loads(diagnose.build_payload(_session()))["available_actions"]
        assert [a["key"] for a in actions] == sorted(remediation.REMEDIATION_REGISTRY)

    def test_guard_drops_actions_outside_the_class_allowlist(self):
        v = {
            "status": "likely",
            "locus": "local",
            "suggested_actions": ["reboot_system", "clear_temp", "repair_image"],
            "manual_steps": [],
        }
        rule = {"rule_hits": ["app_crash_repeat", "system_modules"], "status": "likely", "locus": "local"}
        out = diagnose.apply_guards(v, {}, rule, class_key="crashes")
        assert out["suggested_actions"] == ["repair_image"]
        # No class given (or a class with no allowlist): the registry is the limit.
        assert diagnose.apply_guards(v, {}, rule)["suggested_actions"] == [
            "reboot_system",
            "clear_temp",
            "repair_image",
        ]

    def test_this_pc_name_typed_into_a_crash_symptom_is_hidden(self, monkeypatch):
        monkeypatch.setattr(diagnose.socket, "gethostname", lambda: "shigs78-pc24")
        session = _session(
            symptom="shigs78-pc24 crashed",
            symptom_class="crashes",
            slots={"app_name": "shigs78-pc24 helper"},
            rule_verdict={"headline": "shigs78-pc24 was fine"},
        )
        text = diagnose.build_payload(session)
        assert "shigs78-pc24" not in text
        assert "<this-pc> crashed" in text

    def test_network_symptom_keeps_a_typed_pc_name(self, monkeypatch):
        """The network class diagnoses a NAME; it may be this PC's own."""
        monkeypatch.setattr(diagnose.socket, "gethostname", lambda: "shigs78-pc24")
        session = _session(symptom="shigs78-pc24 won't resolve", slots={"target_host": "shigs78-pc24"})
        assert json.loads(diagnose.build_payload(session))["symptom"] == "shigs78-pc24 won't resolve"
