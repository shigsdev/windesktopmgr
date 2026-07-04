"""Tests for nas.py — QNAP NAS storage over SNMP.

The SNMP I/O (_snmp_collect) is mocked; the parsing, assembly, config loading,
and concern logic are pure and exercised directly. OID mappings were verified
live against a TS-X72 on QTS 5.2.9.
"""

import json

import nas


class TestParseTempC:
    def test_qnap_format(self):
        assert nas._parse_temp_c("37 C/98 F") == 37
        assert nas._parse_temp_c("52 C/125 F") == 52

    def test_no_c_returns_none(self):
        assert nas._parse_temp_c("N/A") is None
        assert nas._parse_temp_c("") is None
        assert nas._parse_temp_c(None) is None


class TestParseSizeGb:
    def test_units(self):
        assert nas._parse_size_gb("21.83 TB") == round(21.83 * 1024, 1)
        assert nas._parse_size_gb("931.51 GB") == 931.5
        assert nas._parse_size_gb("512 MB") == 0.5

    def test_unparseable(self):
        assert nas._parse_size_gb("") is None
        assert nas._parse_size_gb("lots") is None
        assert nas._parse_size_gb(None) is None


class TestParseVolumeName:
    def test_qnap_bracket_form(self):
        assert nas._parse_volume_name("[Volume shigs78nas2-hdd, Pool 1]") == ("shigs78nas2-hdd", "Pool 1")
        assert nas._parse_volume_name("[Volume shigs78-nvme, Pool 2]") == ("shigs78-nvme", "Pool 2")

    def test_other_shape_falls_back(self):
        name, pool = nas._parse_volume_name("DataVol1")
        assert name == "DataVol1"
        assert pool == ""


class TestLoadNasConfig:
    def test_valid(self, tmp_path):
        p = tmp_path / "nas_config.json"
        p.write_text(json.dumps({"nas": [{"name": "x", "host": "1.2.3.4"}], "poll_timeout_s": 5}), encoding="utf-8")
        cfg = nas._load_nas_config(str(p))
        assert cfg["poll_timeout_s"] == 5
        assert cfg["nas"][0]["host"] == "1.2.3.4"

    def test_missing_file(self, tmp_path):
        assert nas._load_nas_config(str(tmp_path / "nope.json")) == {"nas": []}

    def test_malformed(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{ not json", encoding="utf-8")
        assert nas._load_nas_config(str(p)) == {"nas": []}


class TestConfiguredNas:
    def test_placeholder_community_excluded(self):
        cfg = {"nas": [{"name": "a", "host": "1.1.1.1", "community": "REPLACE_WITH_YOUR_COMMUNITY", "enabled": True}]}
        assert nas._configured_nas(cfg) == []

    def test_disabled_excluded(self):
        cfg = {"nas": [{"name": "a", "host": "1.1.1.1", "community": "real", "enabled": False}]}
        assert nas._configured_nas(cfg) == []

    def test_missing_host_or_community_excluded(self):
        cfg = {
            "nas": [
                {"name": "a", "host": "", "community": "real", "enabled": True},
                {"name": "b", "host": "2.2.2.2", "community": "", "enabled": True},
            ]
        }
        assert nas._configured_nas(cfg) == []

    def test_fully_configured_included(self):
        cfg = {"nas": [{"name": "a", "host": "1.1.1.1", "community": "wdmreader", "enabled": True}]}
        assert len(nas._configured_nas(cfg)) == 1


class TestBuildNasResult:
    def _raw(self):
        return {
            "sys_info": {"sys_descr": "Linux TS-X72 5.2.9.3499", "sys_name": "nas2", "cpu": "4.8 %"},
            "disk_cols": {
                "descr": {1: "HDD1", 2: "HDD2", 3: "HDD3"},
                "model": {1: "ST24000NT002", 2: "SSD 990 EVO Plus 1TB", 3: ""},  # 3 = empty bay
                "capacity": {1: "21.83 TB", 2: "931.51 GB"},
                "temp": {1: "37 C/98 F", 2: "52 C/125 F"},
                "health": {1: "GOOD", 2: "GOOD"},
            },
            "vol_cols": {
                "descr": {1: "[Volume hdd, Pool 1]"},
                "fs": {1: "EXT4"},
                "total": {1: "108.14 TB"},
                "free": {1: "32.29 TB"},
                "status": {1: "Ready"},
            },
            "fan_cols": {"descr": {1: "System FAN 1"}, "speed": {1: "761 RPM"}},
        }

    def test_assembles_model_firmware(self):
        r = nas._build_nas_result({"name": "nas2", "host": "1.2.3.4"}, **self._raw())
        assert r["model"] == "TS-X72"
        assert r["firmware"] == "5.2.9.3499"
        assert r["reachable"] is True

    def test_empty_bay_skipped(self):
        r = nas._build_nas_result({"name": "n", "host": "h"}, **self._raw())
        # bay 3 has empty model -> excluded; 1 and 2 kept
        assert [d["bay"] for d in r["disks"]] == ["HDD1", "HDD2"]

    def test_disk_fields(self):
        r = nas._build_nas_result({"name": "n", "host": "h"}, **self._raw())
        d = r["disks"][0]
        assert d["model"] == "ST24000NT002"
        assert d["temp_c"] == 37
        assert d["health"] == "GOOD"
        assert d["healthy"] is True

    def test_volume_pct_used(self):
        r = nas._build_nas_result({"name": "n", "host": "h"}, **self._raw())
        v = r["volumes"][0]
        assert v["name"] == "hdd"
        assert v["pool"] == "Pool 1"
        assert v["status"] == "Ready"
        assert v["healthy"] is True
        # (108.14 - 32.29) / 108.14 ~ 70.1%
        assert 69 < v["pct_used"] < 71

    def test_unhealthy_disk_flag(self):
        raw = self._raw()
        raw["disk_cols"]["health"][1] = "Warning"
        r = nas._build_nas_result({"name": "n", "host": "h"}, **raw)
        assert r["disks"][0]["healthy"] is False


class TestGetNasStorage:
    def test_unreachable_when_snmp_none(self, mocker):
        mocker.patch(
            "nas._load_nas_config",
            return_value={"nas": [{"name": "n", "host": "1.1.1.1", "community": "c", "enabled": True}]},
        )
        mocker.patch("nas._snmp_collect", return_value=None)
        out = nas.get_nas_storage()
        assert out["configured"] == 1
        assert out["nas"][0]["reachable"] is False
        assert out["nas"][0]["error"]

    def test_reachable_builds_result(self, mocker):
        mocker.patch(
            "nas._load_nas_config",
            return_value={"nas": [{"name": "n", "host": "1.1.1.1", "community": "c", "enabled": True}]},
        )
        mocker.patch(
            "nas._snmp_collect",
            return_value={
                "sys_info": {"sys_descr": "Linux TS-453 5.1", "sys_name": "n", "cpu": "3 %"},
                "disk_cols": {
                    "descr": {1: "HDD1"},
                    "model": {1: "WD Red"},
                    "capacity": {1: "4 TB"},
                    "temp": {1: "35 C/95 F"},
                    "health": {1: "GOOD"},
                },
                "vol_cols": {
                    "descr": {1: "[Volume v, Pool 1]"},
                    "fs": {1: "EXT4"},
                    "total": {1: "4 TB"},
                    "free": {1: "1 TB"},
                    "status": {1: "Ready"},
                },
                "fan_cols": {"descr": {1: "FAN 1"}, "speed": {1: "700 RPM"}},
            },
        )
        out = nas.get_nas_storage()
        assert out["nas"][0]["reachable"] is True
        assert out["nas"][0]["disks"][0]["model"] == "WD Red"

    def test_no_config_configured_zero(self, mocker):
        mocker.patch("nas._load_nas_config", return_value={"nas": []})
        out = nas.get_nas_storage()
        assert out == {"nas": [], "configured": 0}


class TestNasStorageConcerns:
    def _nas(self, **over):
        d = {"name": "nas2", "host": "1.1.1.1", "reachable": True, "disks": [], "volumes": [], "fans": []}
        d.update(over)
        return d

    def test_all_healthy_no_concern(self):
        data = {
            "nas": [
                self._nas(
                    disks=[{"bay": "HDD1", "health": "GOOD", "healthy": True}],
                    volumes=[{"name": "v", "status": "Ready", "healthy": True}],
                )
            ]
        }
        assert nas.nas_storage_concerns(data) == []

    def test_unreachable_is_warning(self):
        data = {"nas": [self._nas(reachable=False, error="down")]}
        cs = nas.nas_storage_concerns(data)
        assert len(cs) == 1
        assert cs[0]["level"] == "warning"
        assert "unreachable" in cs[0]["title"].lower()

    def test_unhealthy_disk_is_critical(self):
        data = {"nas": [self._nas(disks=[{"bay": "HDD3", "health": "Warning", "healthy": False}])]}
        cs = nas.nas_storage_concerns(data)
        assert any(c["level"] == "critical" and "disk" in c["title"].lower() for c in cs)

    def test_not_ready_volume_is_critical(self):
        data = {"nas": [self._nas(volumes=[{"name": "v", "status": "Degraded", "healthy": False}])]}
        cs = nas.nas_storage_concerns(data)
        assert any(c["level"] == "critical" and "volume" in c["title"].lower() for c in cs)

    def test_empty_data_no_concern(self):
        assert nas.nas_storage_concerns({}) == []
        assert nas.nas_storage_concerns({"nas": []}) == []
