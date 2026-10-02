"""Tests for diagnose.py -- symptom classes and the deterministic classifier."""

from __future__ import annotations

import copy
import json
import re
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

    def test_dict_keys_are_scrubbed_too(self):
        assert diagnose.redact({r"C:\Users\Al": 1}, ["username"]) == {r"C:\Users\<user>": 1}

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
