"""Tests for diagnose_crash_probes: the crash & stability bundle's evidence.

win32evtlog is always replaced by ``FakeEvt``: an "event" is just its XML
string, so each test states exactly what Windows would have logged.
"""

from __future__ import annotations

import pytest

import diagnose_crash_probes as dcp

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def evt_xml(eid, time, provider="Microsoft-Windows-Kernel-Power", level=4, data=None, data_list=None, user=None):
    """One event's XML as EvtFormatMessage(..., EvtFormatMessageXml) renders it."""
    if data is not None:
        body = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
        event_data = f"<EventData>{body}</EventData>"
    elif data_list is not None:
        event_data = "<EventData>" + "".join(f"<Data>{v}</Data>" for v in data_list) + "</EventData>"
    elif user is not None:
        inner = "".join(f"<{k}>{v}</{k}>" for k, v in user.items())
        event_data = f"<UserData><Ev xmlns='urn:x'>{inner}</Ev></UserData>"
    else:
        event_data = ""
    return (
        f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/>'
        f"<EventID>{eid}</EventID><Level>{level}</Level>"
        f'<TimeCreated SystemTime="{time}"/></System>{event_data}</Event>'
    )


class FakeEvt:
    """Stand-in for win32evtlog. ``channels`` maps channel -> list of event XML
    (newest first, as EvtQueryReverseDirection returns them); a channel mapped
    to an Exception raises it from EvtQuery."""

    EvtQueryReverseDirection = 0x200
    EvtQueryChannelPath = 0x1
    EvtFormatMessageXml = 9

    def __init__(self, channels):
        self.channels = channels
        self.queries = []

    def EvtQuery(self, channel, flags, xpath):  # noqa: N802 -- mirrors the pywin32 API
        self.queries.append((channel, xpath))
        events = self.channels.get(channel, [])
        if isinstance(events, Exception):
            raise events
        return iter(list(events))

    def EvtNext(self, handle, count):  # noqa: N802
        return [x for _, x in zip(range(count), handle, strict=False)]

    def EvtFormatMessage(self, meta, evt, flags):  # noqa: N802
        if evt == "BROKEN":
            raise RuntimeError("cannot render")
        return evt


@pytest.fixture
def fake_evt(monkeypatch):
    def install(channels):
        fake = FakeEvt(channels)
        monkeypatch.setattr(dcp, "win32evtlog", fake)
        return fake

    return install


class TestEvtQuery:
    def test_parses_system_fields_and_named_data(self, fake_evt):
        fake_evt({"System": [evt_xml(41, "2026-10-09T12:17:51.1234567Z", data={"BugcheckCode": "0"}, level=1)]})
        [e] = dcp.evt_query("System", "*")
        assert e == {
            "id": 41,
            "time": "2026-10-09T12:17:51Z",
            "provider": "Microsoft-Windows-Kernel-Power",
            "level": 1,
            "data": {"BugcheckCode": "0"},
            "data_list": ["0"],
        }

    def test_unnamed_data_goes_to_data_list(self, fake_evt):
        fake_evt(
            {
                "Application": [
                    evt_xml(1000, "2026-10-08T03:36:24Z", "Application Error", 2, data_list=["chrome.exe", "1.0"])
                ]
            }
        )
        [e] = dcp.evt_query("Application", "*")
        assert e["data"] == {}
        assert e["data_list"] == ["chrome.exe", "1.0"]

    def test_user_data_leaves_become_named_data(self, fake_evt):
        fake_evt(
            {
                "System": [
                    evt_xml(20001, "2026-10-08T03:00:00Z", "Microsoft-Windows-UserPnp", user={"DriverName": "x.inf"})
                ]
            }
        )
        [e] = dcp.evt_query("System", "*")
        assert e["data"] == {"DriverName": "x.inf"}

    def test_malformed_event_is_skipped(self, fake_evt):
        fake_evt({"System": ["BROKEN", "<not xml", evt_xml(12, "2026-10-08T03:36:08Z")]})
        assert [e["id"] for e in dcp.evt_query("System", "*")] == [12]

    def test_query_failure_raises_evt_unavailable(self, fake_evt):
        fake_evt({"Microsoft-Windows-StartupRepair/Operational": OSError(5, "Access is denied")})
        with pytest.raises(dcp.EvtUnavailable) as exc:
            dcp.evt_query("Microsoft-Windows-StartupRepair/Operational", "*")
        assert exc.value.channel == "Microsoft-Windows-StartupRepair/Operational"

    def test_missing_pywin32_raises_evt_unavailable(self, monkeypatch):
        monkeypatch.setattr(dcp, "win32evtlog", None)
        with pytest.raises(dcp.EvtUnavailable):
            dcp.evt_query("System", "*")

    def test_max_events_is_honoured(self, fake_evt):
        fake_evt({"System": [evt_xml(12, f"2026-10-08T03:{i:02d}:00Z") for i in range(50)]})
        assert len(dcp.evt_query("System", "*", max_events=7)) == 7

    def test_timeout_returns_empty(self, fake_evt, monkeypatch):
        fake = fake_evt({"System": [evt_xml(12, "2026-10-08T03:36:08Z")]})
        release = __import__("threading").Event()

        def slow(*a):
            release.wait(5)
            return iter([])

        monkeypatch.setattr(fake, "EvtQuery", slow)
        try:
            assert dcp.evt_query("System", "*", timeout_s=0.05) == []
        finally:
            release.set()


class TestWindowXpath:
    def test_ids_and_relative_window(self):
        x = dcp.window_xpath(ids=[41, 6008], days=7)
        assert "EventID=41 or EventID=6008" in x
        assert "timediff(@SystemTime) <= 604800000" in x

    def test_providers_and_levels(self):
        x = dcp.window_xpath(providers=["disk", "stornvme"], levels=[1, 2, 3])
        assert "@Name='disk' or @Name='stornvme'" in x
        assert "Level=1 or Level=2 or Level=3" in x

    def test_absolute_window(self):
        x = dcp.window_xpath(start="2026-10-09T03:37:03Z", end="2026-10-09T12:17:48Z")
        assert "@SystemTime>='2026-10-09T03:37:03Z'" in x
        assert "@SystemTime<='2026-10-09T12:17:48Z'" in x
        assert "timediff" not in x


# The real 2026-10-08 sequence (UTC): power-off requested 15 s after a boot,
# shutdown began and never finished, the next boot is unclean.
REAL_TIMELINE = [
    {"time": "2026-10-09T03:36:24Z", "kind": "boot", "id": 12},
    {"time": "2026-10-09T03:36:39Z", "kind": "shutdown_requested", "id": 1074},
    {"time": "2026-10-09T03:36:57Z", "kind": "eventlog_stop", "id": 6006},
    {"time": "2026-10-09T03:37:02Z", "kind": "shutdown_started", "id": 109},
    {"time": "2026-10-09T03:37:03Z", "kind": "shutdown_started", "id": 13},
    {"time": "2026-10-09T12:17:48Z", "kind": "boot", "id": 12},
    {"time": "2026-10-09T12:17:51Z", "kind": "unexpected", "id": 41},
    {"time": "2026-10-09T12:18:04Z", "kind": "dirty_noted", "id": 6008, "last_alive": "2026-10-09T08:45:35Z"},
    {"time": "2026-10-09T12:18:04Z", "kind": "eventlog_start", "id": 6005},
]


class TestDeriveEpisodes:
    def test_real_hung_shutdown_sequence(self):
        eps = dcp.derive_episodes(REAL_TIMELINE)
        assert len(eps) == 2
        assert eps[0] == {
            "boot": "2026-10-09T03:36:24Z",
            "next_boot": "2026-10-09T12:17:48Z",
            "shutdown_requested_at": "2026-10-09T03:36:39Z",
            "shutdown_started_at": "2026-10-09T03:37:02Z",
            "next_boot_unexpected": True,
            "last_alive": "2026-10-09T08:45:35Z",
        }
        assert eps[1]["boot"] == "2026-10-09T12:17:48Z"
        assert eps[1]["next_boot"] is None

    def test_clean_shutdown_then_normal_boot_is_not_unexpected(self):
        clean = [
            {"time": "2026-10-08T10:00:00Z", "kind": "boot", "id": 12},
            {"time": "2026-10-08T20:00:00Z", "kind": "shutdown_started", "id": 13},
            {"time": "2026-10-09T08:00:00Z", "kind": "boot", "id": 12},
        ]
        eps = dcp.derive_episodes(clean)
        assert eps[0]["shutdown_started_at"] == "2026-10-08T20:00:00Z"
        assert eps[0]["next_boot_unexpected"] is False
        assert eps[0]["last_alive"] is None

    def test_input_order_does_not_matter(self):
        assert dcp.derive_episodes(list(reversed(REAL_TIMELINE))) == dcp.derive_episodes(REAL_TIMELINE)

    def test_window_starting_mid_session_has_no_boot(self):
        eps = dcp.derive_episodes([{"time": "2026-10-08T20:00:00Z", "kind": "shutdown_started", "id": 13}])
        assert eps == [
            {
                "boot": None,
                "next_boot": None,
                "shutdown_requested_at": None,
                "shutdown_started_at": "2026-10-08T20:00:00Z",
                "next_boot_unexpected": False,
                "last_alive": None,
            }
        ]

    def test_empty(self):
        assert dcp.derive_episodes([]) == []


class TestActivityBetween:
    def test_counts_both_logs_and_returns_the_latest(self, fake_evt):
        fake = fake_evt(
            {
                "System": [evt_xml(98, "2026-10-09T04:31:13Z", "Ntfs"), evt_xml(98, "2026-10-09T04:00:18Z", "Ntfs")],
                "Application": [evt_xml(8194, "2026-10-09T05:06:00Z", "VSS")],
            }
        )
        assert dcp.activity_between("2026-10-09T03:37:03Z", "2026-10-09T12:17:48Z") == (3, "2026-10-09T05:06:00Z")
        assert all("@SystemTime>='2026-10-09T03:37:03Z'" in x for _, x in fake.queries)

    def test_unreadable_log_is_skipped(self, fake_evt):
        fake_evt({"System": OSError("denied"), "Application": [evt_xml(1, "2026-10-09T05:00:00Z", "X")]})
        assert dcp.activity_between("2026-10-09T03:00:00Z", "2026-10-09T06:00:00Z") == (1, "2026-10-09T05:00:00Z")

    def test_nothing(self, fake_evt):
        fake_evt({})
        assert dcp.activity_between("2026-10-09T03:00:00Z", "2026-10-09T06:00:00Z") == (0, None)
