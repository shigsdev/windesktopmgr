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


# ── Task 5: wave-one probes A ─────────────────────────────────────────────

KP = "Microsoft-Windows-Kernel-Power"
KG = "Microsoft-Windows-Kernel-General"
WER = "Microsoft-Windows-WER-SystemErrorReporting"
WHEA = "Microsoft-Windows-WHEA-Logger"
KB = "Microsoft-Windows-Kernel-Boot"
CRASH_REDACT = ("username", "serial", "mac", "self_host")
LRM = "‎"


def _real_system_log():
    """System log for the 2026-10-08 incident, newest first."""
    return [
        evt_xml(6005, "2026-10-09T12:18:04Z", "EventLog"),
        evt_xml(
            6008, "2026-10-09T12:18:04Z", "EventLog", 2, data_list=["4:45:35 AM", f"{LRM}10/{LRM}9/{LRM}2026", "", ""]
        ),
        evt_xml(41, "2026-10-09T12:17:51Z", KP, 1, data={"BugcheckCode": "0", "PowerButtonTimestamp": "0"}),
        evt_xml(12, "2026-10-09T12:17:48Z", KG),
        evt_xml(13, "2026-10-09T03:37:03Z", KG),
        evt_xml(109, "2026-10-09T03:37:02Z", KP),
        evt_xml(6006, "2026-10-09T03:36:57Z", "EventLog"),
        evt_xml(1074, "2026-10-09T03:36:39Z", "User32"),
        evt_xml(12, "2026-10-09T03:36:24Z", KG),
        evt_xml(12, "2026-10-09T03:36:24Z", "Some-Other-Provider"),  # same id, wrong provider: ignored
    ]


@pytest.fixture
def edt(monkeypatch):
    """Pin the machine's local zone to UTC-4 (EDT, as on 2026-10-08)."""
    from datetime import timedelta, timezone

    monkeypatch.setattr(dcp, "_LOCAL_TZ", timezone(timedelta(hours=-4)))


class TestPowerTimeline:
    def test_real_incident_episode_with_activity(self, fake_evt, monkeypatch, edt):
        fake_evt({"System": _real_system_log()})
        monkeypatch.setattr(dcp, "activity_between", lambda s, e, cap=500: (13, "2026-10-09T08:11:08Z"))
        d = dcp._p_power_timeline({})
        assert d["window_days"] == 7
        assert d["unavailable"] == []
        ep = d["episodes"][0]
        assert ep["shutdown_started_at"] == "2026-10-09T03:37:02Z"
        assert ep["next_boot_unexpected"] is True
        assert ep["last_alive"] == "2026-10-09T08:45:35Z"  # 4:45:35 AM EDT
        assert ep["activity_after_shutdown_start"] == 13
        assert ep["last_activity"] == "2026-10-09T08:11:08Z"
        kinds = [e["kind"] for e in d["events"]]
        assert kinds[0] == "boot"  # oldest first
        assert kinds.count("boot") == 2  # the foreign-provider id 12 is dropped

    def test_command_content(self, fake_evt):
        fake = fake_evt({"System": []})
        dcp._p_power_timeline({})
        channel, xpath = fake.queries[0]
        assert channel == "System"
        for eid in (12, 13, 41, 109, 1074, 6005, 6006, 6008):
            assert f"EventID={eid}" in xpath

    def test_events_capped_at_50(self, fake_evt):
        log = [evt_xml(12, f"2026-10-08T{i // 60:02d}:{i % 60:02d}:00Z", KG) for i in range(120)]
        fake_evt({"System": log})
        assert len(dcp._p_power_timeline({})["events"]) == 50

    def test_unreadable_system_log(self, fake_evt):
        fake_evt({"System": OSError("denied")})
        d = dcp._p_power_timeline({})
        assert d["unavailable"] == ["System"]
        assert d["episodes"] == []

    def test_unparseable_6008_gives_no_last_alive(self, fake_evt, monkeypatch):
        log = _real_system_log()
        log[1] = evt_xml(6008, "2026-10-09T12:18:04Z", "EventLog", 2, data_list=["garbage"])
        fake_evt({"System": log})
        monkeypatch.setattr(dcp, "activity_between", lambda s, e, cap=500: (0, None))
        ep = dcp._p_power_timeline({})["episodes"][0]
        assert ep["next_boot_unexpected"] is True
        assert ep["last_alive"] is None


class TestUnexpectedShutdowns:
    def test_fields(self, fake_evt):
        quiet = {
            "BugcheckCode": "0",
            "PowerButtonTimestamp": "0",
            "LongPowerButtonPressDetected": "false",
            "SleepInProgress": "0",
        }
        loud = {
            "BugcheckCode": "159",
            "PowerButtonTimestamp": "1337",
            "LongPowerButtonPressDetected": "true",
            "SleepInProgress": "4",
        }
        fake_evt(
            {
                "System": [
                    evt_xml(41, "2026-10-09T12:17:51Z", KP, 1, data=quiet),
                    evt_xml(41, "2026-10-05T10:00:00Z", KP, 1, data=loud),
                ]
            }
        )
        assert dcp._p_unexpected_shutdowns({})["events"] == [
            {
                "time": "2026-10-09T12:17:51Z",
                "bugcheck_code": 0,
                "power_button": False,
                "long_press": False,
                "sleep_in_progress": False,
            },
            {
                "time": "2026-10-05T10:00:00Z",
                "bugcheck_code": 159,
                "power_button": True,
                "long_press": True,
                "sleep_in_progress": True,
            },
        ]

    def test_missing_fields_default(self, fake_evt):
        fake_evt({"System": [evt_xml(41, "2026-10-09T12:17:51Z", KP, 1, data={})]})
        [e] = dcp._p_unexpected_shutdowns({})["events"]
        assert e["bugcheck_code"] == 0
        assert e["power_button"] is False

    def test_empty_and_command(self, fake_evt):
        fake = fake_evt({"System": []})
        assert dcp._p_unexpected_shutdowns({})["events"] == []
        assert "EventID=41" in fake.queries[0][1]


class TestBugchecks:
    def test_bugcheck_events_dumps_and_memory_dmp(self, fake_evt, tmp_path, monkeypatch):
        (tmp_path / "Minidump").mkdir()
        for i in range(12):
            (tmp_path / "Minidump" / f"10{i:02d}26-1-01.dmp").write_bytes(b"x" * (i + 1))
        (tmp_path / "MEMORY.DMP").write_bytes(b"y" * 10)
        monkeypatch.setenv("SystemRoot", str(tmp_path))
        code = "0x0000009f (0x0000000000000003, 0x1)"
        fake_evt({"System": [evt_xml(1001, "2026-10-05T10:00:00Z", WER, 2, data_list=[code, "x.dmp", "id"])]})
        d = dcp._p_bugchecks({})
        assert d["bugchecks"] == [
            {"time": "2026-10-05T10:00:00Z", "code": "0x0000009f", "name": "DRIVER_POWER_STATE_FAILURE"}
        ]
        assert len(d["minidumps"]) == 10
        assert d["memory_dmp"]["size"] == 10

    def test_no_dump_folder(self, fake_evt, tmp_path, monkeypatch):
        monkeypatch.setenv("SystemRoot", str(tmp_path))
        fake_evt({"System": []})
        assert dcp._p_bugchecks({}) == {"bugchecks": [], "minidumps": [], "memory_dmp": None}

    def test_never_triggers_a_web_lookup(self, fake_evt, tmp_path, monkeypatch):
        import bsod

        monkeypatch.setenv("SystemRoot", str(tmp_path))
        fake_evt({"System": [evt_xml(1001, "2026-10-05T10:00:00Z", WER, 2, data_list=["0x00000bad (0x0)"])]})
        monkeypatch.setattr(bsod, "get_stop_code_info", lambda *a, **k: pytest.fail("network-capable lookup used"))
        assert dcp._p_bugchecks({})["bugchecks"][0]["name"] is None


class TestWhea:
    def test_counts_by_severity_and_component(self, fake_evt):
        fake_evt(
            {
                "System": [
                    evt_xml(18, "2026-10-07T10:00:00Z", WHEA, 2),
                    evt_xml(47, "2026-10-06T10:00:00Z", WHEA, 3),
                    evt_xml(17, "2026-10-05T10:00:00Z", WHEA, 3),
                    evt_xml(99, "2026-10-04T10:00:00Z", WHEA, 3),
                ]
            }
        )
        assert dcp._p_whea({}) == {
            "fatal": 1,
            "corrected": 3,
            "by_component": {"processor": 1, "memory": 1, "pcie": 1, "other": 1},
            "first": "2026-10-04T10:00:00Z",
            "last": "2026-10-07T10:00:00Z",
        }

    def test_none_and_command(self, fake_evt):
        fake = fake_evt({"System": []})
        d = dcp._p_whea({})
        assert d["fatal"] == 0
        assert d["first"] is None
        assert WHEA in fake.queries[0][1]


class TestBootHealth:
    def test_failures_repairs_and_durations(self, fake_evt):
        fake_evt(
            {
                "System": [
                    evt_xml(20, "2026-10-08T10:00:00Z", KB, data={"LastBootGood": "false"}),
                    evt_xml(20, "2026-10-07T10:00:00Z", KB, data={"LastBootGood": "true"}),
                ],
                dcp.STARTUP_REPAIR_CHANNEL: [evt_xml(1, "2026-10-08T09:59:00Z", "StartupRepair")],
                dcp.BOOT_PERF_CHANNEL: [
                    evt_xml(
                        100,
                        "2026-10-08T10:01:00Z",
                        "Microsoft-Windows-Diagnostics-Performance",
                        data={"BootTime": "41234"},
                    )
                ],
            }
        )
        assert dcp._p_boot_health({}) == {
            "boot_failures": ["2026-10-08T10:00:00Z"],
            "startup_repair_runs": 1,
            "boot_durations_ms": [41234],
            "unavailable": [],
        }

    def test_unreadable_channels_are_listed_not_fatal(self, fake_evt):
        """Review Focus 1: an admin-only or missing channel never sinks the probe."""
        fake_evt(
            {
                "System": [],
                dcp.STARTUP_REPAIR_CHANNEL: OSError(5, "Access is denied"),
                dcp.BOOT_PERF_CHANNEL: OSError(15007, "channel not found"),
            }
        )
        d = dcp._p_boot_health({})
        assert d["unavailable"] == [dcp.STARTUP_REPAIR_CHANNEL, dcp.BOOT_PERF_CHANNEL]
        assert d["boot_failures"] == []
        assert d["startup_repair_runs"] == 0


class TestRegistrationA:
    @pytest.mark.parametrize(
        "key",
        ["crash.power_timeline", "crash.unexpected_shutdowns", "crash.bugchecks", "crash.whea", "crash.boot_health"],
    )
    def test_registered_with_crash_category_and_redaction(self, key):
        probe = dcp.REGISTERED[key]
        assert probe.category == "crash"
        assert probe.redact == CRASH_REDACT
        assert 8 <= probe.timeout_s <= 15


# ── Task 6: wave-one probes B + escalation probes ─────────────────────────

APP_ERR = "Application Error"
APP_HANG = "Application Hang"
SYS32 = r"C:\Windows\System32"


def app_crash(time, app, module, exc="0xc0000005", module_path=None, app_ver="1.0", mod_ver="2.0", offset="0x1234"):
    """An Application Error 1000 event; data_list positions as Windows writes them."""
    path = module_path or rf"C:\Program Files\{app}\{module}"
    fields = [app, app_ver, "ts", module, mod_ver, "ts", exc, offset, "pid", "start", rf"C:\Program Files\{app}", path]
    return evt_xml(1000, time, APP_ERR, 2, data_list=fields)


def app_hang(time, app):
    return evt_xml(1002, time, APP_HANG, 2, data_list=[app, "1.0", "pid"])


@pytest.fixture
def sysroot(monkeypatch):
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")


class TestAppCrashes:
    def test_groups_counts_modules_and_system_modules(self, fake_evt, sysroot):
        fake_evt(
            {
                "Application": [
                    app_crash("2026-10-08T10:00:00Z", "chrome.exe", "chrome.dll"),
                    app_crash("2026-10-08T09:00:00Z", "chrome.exe", "combase.dll", module_path=SYS32 + r"\combase.dll"),
                    app_hang("2026-10-08T08:00:00Z", "chrome.exe"),
                    app_crash(
                        "2026-10-07T10:00:00Z", "notepad.exe", "combase.dll", module_path=SYS32 + r"\combase.dll"
                    ),
                ]
            }
        )
        d = dcp._p_app_crashes({})
        assert d["named"] is None
        chrome, notepad = d["apps"]
        assert chrome["app"] == "chrome.exe"
        assert (chrome["crashes"], chrome["hangs"], chrome["last"]) == (2, 1, "2026-10-08T10:00:00Z")
        assert {"module": "chrome.dll", "count": 1} in chrome["modules"]
        assert chrome["system_module_crashes"] == 1
        assert notepad["system_module_crashes"] == 1

    def test_own_executable_installed_in_system32_is_not_a_system_module(self, fake_evt, sysroot):
        """Live 2026-10-09: Intel RST and Killer services live under System32 and
        crash in their OWN exe; that is not a damaged Windows file."""
        exe = SYS32 + r"\DriverStore\FileRepository\x\RstMwService.exe"
        fake_evt(
            {
                "Application": [
                    app_crash("2026-10-08T10:00:00Z", "RstMwService.exe", "RstMwService.exe", module_path=exe)
                ]
            }
        )
        assert dcp._p_app_crashes({})["apps"][0]["system_module_crashes"] == 0

    @pytest.mark.parametrize("module", ["KERNELBASE.dll", "ntdll.dll", "ucrtbase.dll"])
    def test_generic_exception_modules_are_not_evidence(self, fake_evt, sysroot, module):
        """Live 2026-10-09: most app crashes are reported in KERNELBASE/ntdll
        whoever caused them (ExpressVPN's helper: 967 times)."""
        fake_evt(
            {"Application": [app_crash("2026-10-08T10:00:00Z", "a.exe", module, module_path=SYS32 + "\\" + module)]}
        )
        assert dcp._p_app_crashes({})["apps"][0]["system_module_crashes"] == 0

    def test_named_app_goes_first(self, fake_evt, sysroot):
        log = [app_crash(f"2026-10-08T0{i}:00:00Z", "spotify.exe", "x.dll") for i in range(5)]
        log.append(app_crash("2026-10-07T10:00:00Z", "chrome.exe", "chrome.dll"))
        fake_evt({"Application": log})
        d = dcp._p_app_crashes({"app_name": "Chrome"})
        assert d["named"] == "Chrome"
        assert d["apps"][0]["app"] == "chrome.exe"

    def test_huge_log_is_capped_at_the_query_and_in_output(self, fake_evt, sysroot, monkeypatch):
        """Review Focus 5: 5,000 events still give at most 10 apps."""
        calls = []
        many = [app_crash("2026-10-08T10:00:00Z", f"app{i % 40}.exe", "m.dll") for i in range(5000)]

        def fake_query(channel, xpath, max_events=200, timeout_s=10.0):
            calls.append(max_events)
            return [dcp._parse_event(x) for x in many[:max_events]]

        monkeypatch.setattr(dcp, "evt_query", fake_query)
        d = dcp._p_app_crashes({})
        assert calls == [1000]
        assert len(d["apps"]) <= 10

    def test_short_event_data_is_tolerated(self, fake_evt, sysroot):
        fake_evt({"Application": [evt_xml(1000, "2026-10-08T10:00:00Z", APP_ERR, 2, data_list=["x.exe"])]})
        [app] = dcp._p_app_crashes({})["apps"]
        assert app["app"] == "x.exe"
        assert app["modules"] == []

    def test_dotnet_runtime_crash_counts(self, fake_evt, sysroot):
        msg = "Application: tool.exe\nFramework Version: v4.0\nDescription: unhandled exception"
        fake_evt({"Application": [evt_xml(1026, "2026-10-08T10:00:00Z", ".NET Runtime", 2, data_list=[msg])]})
        [app] = dcp._p_app_crashes({})["apps"]
        assert (app["app"], app["crashes"]) == ("tool.exe", 1)

    def test_empty_and_command(self, fake_evt, sysroot):
        fake = fake_evt({"Application": []})
        assert dcp._p_app_crashes({})["apps"] == []
        channel, xpath = fake.queries[0]
        assert channel == "Application"
        assert "EventID=1000" in xpath and "EventID=1002" in xpath


class TestStorageErrors:
    def test_providers_pool_and_storage_services(self, fake_evt):
        fake_evt(
            {
                "System": [
                    evt_xml(153, "2026-10-08T10:00:00Z", "disk", 3),
                    evt_xml(11, "2026-10-08T09:00:00Z", "stornvme", 2),
                    evt_xml(1, "2026-10-08T08:00:00Z", "unrelated", 2),
                ],
                dcp.STORAGE_SPACES_CHANNEL: [
                    evt_xml(313, "2026-10-09T03:36:24Z", "Microsoft-Windows-StorageSpaces-Driver", 2),
                    evt_xml(304, "2026-10-09T03:36:24Z", "Microsoft-Windows-StorageSpaces-Driver", 3),
                ],
                "Application": [
                    app_crash("2026-10-09T03:36:24Z", "RstMwService.exe", "KERNELBASE.dll"),
                    app_crash("2026-10-09T03:36:20Z", "chrome.exe", "chrome.dll"),
                ],
            }
        )
        d = dcp._p_storage_errors({})
        assert d["by_provider"] == {
            "disk": {"count": 1, "last": "2026-10-08T10:00:00Z"},
            "stornvme": {"count": 1, "last": "2026-10-08T09:00:00Z"},
        }
        assert d["pool_repair_failures"] == 1
        assert d["pool_times"] == ["2026-10-09T03:36:24Z"]
        assert d["storage_service_faults"] == [{"app": "RstMwService.exe", "time": "2026-10-09T03:36:24Z"}]

    def test_unreadable_pool_channel(self, fake_evt):
        fake_evt({"System": [], dcp.STORAGE_SPACES_CHANNEL: OSError("missing"), "Application": []})
        d = dcp._p_storage_errors({})
        assert d["pool_repair_failures"] == 0
        assert d["unavailable"] == [dcp.STORAGE_SPACES_CHANNEL]


class TestRecentChanges:
    def test_drivers_services_updates(self, fake_evt):
        fake_evt(
            {
                "System": [
                    evt_xml(
                        20001, "2026-10-08T10:00:00Z", "Microsoft-Windows-UserPnp", user={"DriverName": "iaStorVD.inf"}
                    ),
                    evt_xml(
                        7045, "2026-10-09T04:11:05Z", "Service Control Manager", data={"ServiceName": "McAfee Task"}
                    ),
                    evt_xml(
                        19,
                        "2026-10-07T10:00:00Z",
                        "Microsoft-Windows-WindowsUpdateClient",
                        data={"updateTitle": "KB5050001"},
                    ),
                    evt_xml(7045, "2026-10-06T10:00:00Z", "Some-Other", data={"ServiceName": "nope"}),
                ]
            }
        )
        assert dcp._p_recent_changes({})["installs"] == [
            {"time": "2026-10-09T04:11:05Z", "kind": "service", "name": "McAfee Task"},
            {"time": "2026-10-08T10:00:00Z", "kind": "driver", "name": "iaStorVD.inf"},
            {"time": "2026-10-07T10:00:00Z", "kind": "update", "name": "KB5050001"},
        ]

    def test_capped_at_30(self, fake_evt):
        log = [
            evt_xml(
                7045,
                f"2026-10-08T{i // 60:02d}:{i % 60:02d}:00Z",
                "Service Control Manager",
                data={"ServiceName": f"s{i}"},
            )
            for i in range(80)
        ]
        fake_evt({"System": log})
        assert len(dcp._p_recent_changes({})["installs"]) == 30


class TestHwChanges:
    def test_changes_in_window_with_serials_hidden(self, monkeypatch, edt):
        import bios_audit

        history = [
            {"kind": "baseline", "timestamp": "2026-10-08T11:00:00", "snapshot": {}},
            {
                "kind": "change",
                "context": "elevated",
                "timestamp": "2026-10-08T11:39:21",
                "changes": [
                    {"field": "secure_boot", "old": "enabled", "new": "disabled"},
                    {"field": "board_serial", "old": "AAA111", "new": "BBB222"},
                ],
            },
            {
                "kind": "change",
                "timestamp": "2026-08-21T08:52:20",
                "changes": [{"field": "bios_version", "old": "2.23.0", "new": "2.24.0"}],
            },
        ]
        monkeypatch.setattr(bios_audit, "load_history", lambda: history)
        monkeypatch.setattr(
            dcp,
            "_now_utc",
            lambda: __import__("datetime").datetime(2026, 10, 9, 13, 0, tzinfo=__import__("datetime").timezone.utc),
        )
        assert dcp._p_hw_changes({})["changes"] == [
            {"time": "2026-10-08T15:39:21Z", "field": "secure_boot", "old": "enabled", "new": "disabled"},
            {"time": "2026-10-08T15:39:21Z", "field": "board_serial", "old": "<changed>", "new": "<changed>"},
        ]

    def test_single_change_dict_and_bad_entries(self, monkeypatch, edt):
        import bios_audit

        monkeypatch.setattr(
            bios_audit,
            "load_history",
            lambda: [
                {
                    "kind": "change",
                    "timestamp": "2026-10-08T11:39:21",
                    "changes": {"field": "tpm", "old": "a", "new": "b"},
                },
                {"kind": "change", "timestamp": "not a time", "changes": []},
                "junk",
            ],
        )
        monkeypatch.setattr(
            dcp,
            "_now_utc",
            lambda: __import__("datetime").datetime(2026, 10, 9, 13, 0, tzinfo=__import__("datetime").timezone.utc),
        )
        assert [c["field"] for c in dcp._p_hw_changes({})["changes"]] == ["tpm"]


class TestPowerConfig:
    def test_reads_both_values(self, monkeypatch):
        values = {"HiberbootEnabled": 1, "HibernateEnabled": 0}
        monkeypatch.setattr(dcp, "_reg_dword", lambda path, name: values.get(name))
        assert dcp._p_power_config({}) == {"fast_startup": True, "hibernate": False}

    def test_missing_values_are_none(self, monkeypatch):
        monkeypatch.setattr(dcp, "_reg_dword", lambda path, name: None)
        assert dcp._p_power_config({}) == {"fast_startup": None, "hibernate": None}


class TestEscalations:
    def test_window_30d_reruns_three_probes_over_30_days(self, fake_evt, tmp_path, monkeypatch):
        monkeypatch.setenv("SYSTEMROOT", str(tmp_path))
        fake = fake_evt({"System": []})
        d = dcp._p_window_30d({})
        assert set(d) == {"power_timeline", "bugchecks", "whea"}
        assert d["power_timeline"]["window_days"] == 30
        assert all("timediff(@SystemTime) <= 2592000000" in x for _, x in fake.queries)

    def test_app_detail(self, fake_evt, sysroot):
        fake_evt(
            {
                "Application": [
                    app_crash("2026-10-08T10:00:00Z", "chrome.exe", "chrome.dll"),
                    app_hang("2026-10-08T09:00:00Z", "chrome.exe"),
                    app_crash("2026-10-08T08:00:00Z", "notepad.exe", "x.dll"),
                ]
            }
        )
        d = dcp._p_app_detail({"app_name": "chrome"})
        assert d["records"][0] == {
            "time": "2026-10-08T10:00:00Z",
            "kind": "crash",
            "app_version": "1.0",
            "module": "chrome.dll",
            "module_version": "2.0",
            "exception": "0xc0000005",
            "offset": "0x1234",
        }
        assert [r["kind"] for r in d["records"]] == ["crash", "hang"]

    def test_event_context_before_newest_unexpected_shutdown(self, fake_evt):
        fake_evt(
            {
                "System": [
                    evt_xml(41, "2026-10-09T12:17:51Z", KP, 1, data={}),
                    evt_xml(7, "2026-10-09T12:10:00Z", "disk", 2),
                ],
                "Application": [evt_xml(1000, "2026-10-09T12:15:00Z", APP_ERR, 2, data_list=["x.exe"])],
            }
        )
        d = dcp._p_event_context({})
        assert d["anchor"] == "2026-10-09T12:17:51Z"
        assert {(e["provider"], e["id"]) for e in d["events"]} >= {("disk", 7), (APP_ERR, 1000)}
        assert all(set(e) == {"time", "provider", "id", "level"} for e in d["events"])

    def test_event_context_without_any_unexpected_shutdown(self, fake_evt):
        fake_evt({"System": [], "Application": []})
        assert dcp._p_event_context({}) == {"anchor": None, "events": []}


class TestRegistrationB:
    @pytest.mark.parametrize(
        "key",
        [
            "crash.app_crashes",
            "crash.storage_errors",
            "crash.recent_changes",
            "crash.hw_changes",
            "crash.power_config",
            "crash.window_30d",
            "crash.app_detail",
            "crash.event_context",
        ],
    )
    def test_registered_with_crash_category_and_redaction(self, key):
        probe = dcp.REGISTERED[key]
        assert probe.category == "crash"
        assert probe.redact == CRASH_REDACT
        assert 8 <= probe.timeout_s <= 15

    def test_slot_needs(self):
        assert dcp.REGISTERED["crash.app_crashes"].needs_optional == ("app_name",)
        assert dcp.REGISTERED["crash.app_detail"].needs == ("app_name",)

    def test_thirteen_crash_probes(self):
        assert len(dcp.REGISTERED) == 13
