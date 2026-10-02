"""Tests for diagnose.py -- symptom classes and the deterministic classifier."""

from __future__ import annotations

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
