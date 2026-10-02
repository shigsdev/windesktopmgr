"""Tests for diagnose.py -- symptom classes and the deterministic classifier."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import diagnose

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
        assert len(c["wave1"]) == 9
        assert len(c["escalate"]) == 5
        assert set(c["wave1"]).isdisjoint(c["escalate"])


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "diagnose"
FIXTURES = sorted(FIXTURE_DIR.glob("*.json"))


def _ok(data):
    return {"ok": True, "data": data}


class TestCacheAgrees:
    def test_none_when_a_probe_is_missing(self):
        assert diagnose.cache_agrees({}) is None
        assert diagnose.cache_agrees({"dns.resolve_cached": _ok({"resolved": True, "addresses": ["1.1.1.1"]})}) is None

    def test_none_on_a_failed_probe(self):
        ev = {
            "dns.resolve_cached": {"ok": False, "error": "boom"},
            "dns.resolve_direct": _ok({"resolvers": [{"name": "system", "answers": ["1.1.1.1"]}]}),
        }
        assert diagnose.cache_agrees(ev) is None

    def test_none_when_direct_has_no_resolvers(self):
        ev = {
            "dns.resolve_cached": _ok({"resolved": True, "addresses": ["1.1.1.1"]}),
            "dns.resolve_direct": _ok({"dnspython": False, "resolvers": []}),
        }
        assert diagnose.cache_agrees(ev) is None

    def test_false_on_disjoint_addresses(self):
        ev = {
            "dns.resolve_cached": _ok({"resolved": True, "addresses": ["0.0.0.0"]}),
            "dns.resolve_direct": _ok({"resolvers": [{"name": "google", "answers": ["104.21.0.1"]}]}),
        }
        assert diagnose.cache_agrees(ev) is False

    def test_false_when_only_the_cache_fails(self):
        ev = {
            "dns.resolve_cached": _ok({"resolved": False, "addresses": []}),
            "dns.resolve_direct": _ok({"resolvers": [{"name": "google", "answers": ["104.21.0.1"]}]}),
        }
        assert diagnose.cache_agrees(ev) is False

    def test_true_when_addresses_intersect(self):
        ev = {
            "dns.resolve_cached": _ok({"resolved": True, "addresses": ["1.1.1.1", "2.2.2.2"]}),
            "dns.resolve_direct": _ok(
                {"resolvers": [{"name": "system", "answers": ["2.2.2.2"]}, {"name": "google", "answers": []}]}
            ),
        }
        assert diagnose.cache_agrees(ev) is True

    def test_true_when_both_fail(self):
        ev = {
            "dns.resolve_cached": _ok({"resolved": False, "addresses": []}),
            "dns.resolve_direct": _ok({"resolvers": [{"name": "system", "rcode": "NOERROR", "answers": []}]}),
        }
        assert diagnose.cache_agrees(ev) is True


class TestRuleFixtures:
    def test_fixture_dir_is_populated(self):
        assert len(FIXTURES) >= 6

    @pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
    def test_rule_fixture(self, path):
        fx = json.loads(path.read_text(encoding="utf-8"))
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


def _fixture_evidence(name):
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))["evidence"]


VERDICT_KEYS = {
    "status",
    "locus",
    "headline",
    "reasoning",
    "evidence_refs",
    "suggested_actions",
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
        assert v["rule_hits"] == ["dead_gateway", "cache_agrees"]

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
