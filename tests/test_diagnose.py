"""Tests for diagnose.py -- symptom classes and the deterministic classifier."""

from __future__ import annotations

import copy
import json
import os
import re
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


def _res(rcode, *answers, nodata=False):
    return {"name": "r", "server": "x", "rcode": rcode, "nodata": nodata, "answers": list(answers)}


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
            assert diagnose.DIAGNOSE_MODEL == "claude-sonnet-5-5"
        assert kw["model"] == diagnose.DIAGNOSE_MODEL
        assert kw["messages"][0]["content"] == "the payload text"
        assert kw["system"] == diagnose._SYSTEM_PROMPT
        assert kw["max_tokens"] == 16000
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
        assert out["no_local_fix_reason"] == rule["no_local_fix_reason"]
        assert out["source"] == "model"
        assert out["rule_hits"] == rule["rule_hits"]

    def test_models_own_no_local_fix_reason_is_kept(self):
        evidence = _fixture_evidence("hynote_zone_missing_a")
        rule = diagnose.evaluate_rules(evidence, "hynote.ai")
        out = diagnose.apply_guards(_model_verdict(no_local_fix_reason="mine"), evidence, rule)
        assert out["no_local_fix_reason"] == "mine"

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
        assert set(out) == VERDICT_KEYS
        out["rule_hits"].append("y")
        assert rule["rule_hits"] == ["x"]

    def test_tolerates_a_sparse_verdict(self):
        out = diagnose.apply_guards({"status": "likely", "locus": "local"}, {}, None)
        assert out["suggested_actions"] == []
        assert out["evidence_refs"] == []
        assert out["no_local_fix_reason"] == ""
        assert out["rule_hits"] == []
