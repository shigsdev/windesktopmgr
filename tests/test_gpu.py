"""
tests/test_gpu.py — GPU metrics collector (backlog #37).

get_gpu_metrics() is Python-first per CLAUDE.md: it uses the official NVIDIA
NVML Python binding (nvidia-ml-py, import name pynvml) rather than shelling
out to nvidia-smi.exe. These tests mock the pynvml module itself via
sys.modules, so no real NVIDIA driver or GPU is required to run them.

Coverage:
  1. Happy path    — realistic NVML values parsed correctly
  2. Idle GPU      — 0 values kept (not mistaken for missing)
  3. NVML init fail — driver mismatch, no driver, etc.
  4. Zero GPUs     — count=0 returns available=False
  5. Query failure — NVMLError mid-call still triggers shutdown
  6. Power unsupported — optional field gracefully → None
  7. pynvml not installed — ImportError degrades to available=False
  8. Shutdown hygiene — every init path must shut down
  9. Legacy bytes name — pre-12.x pynvml returned bytes
 10. Zero total memory — defensive guard against div-by-zero
 11. Unit conversion — bytes → MB
 12. Unexpected exception — non-NVMLError caught defensively
"""

import windesktopmgr as wdm


class TestGetGpuMetrics:
    """Every test injects a fake pynvml module via sys.modules so the
    collector's ``import pynvml`` line picks up the mock. No subprocess
    mocking -- there is no subprocess call in the Python-first path.
    """

    def _install_fake_pynvml(
        self,
        mocker,
        *,
        init_error=None,
        count=1,
        name="NVIDIA GeForce RTX 4090",
        util_gpu=23,
        util_mem=7,
        mem_used=1024 * 1024 * 1024,
        mem_total=24576 * 1024 * 1024,
        temp=52,
        power_mw=45200,
        power_supported=True,
        query_error=None,
    ):
        """Build a mock pynvml module with controllable behaviour and register
        it in sys.modules so ``import pynvml`` in the collector finds it.
        """
        import sys
        import types

        fake = types.SimpleNamespace()

        class NVMLError(Exception):
            pass

        fake.NVMLError = NVMLError
        fake.NVML_TEMPERATURE_GPU = 0

        fake.nvmlInit = mocker.MagicMock()
        if init_error:
            fake.nvmlInit.side_effect = NVMLError(init_error)

        fake.nvmlShutdown = mocker.MagicMock()

        if query_error:
            fake.nvmlDeviceGetCount = mocker.MagicMock(side_effect=NVMLError(query_error))
        else:
            fake.nvmlDeviceGetCount = mocker.MagicMock(return_value=count)

        fake.nvmlDeviceGetHandleByIndex = mocker.MagicMock(return_value="fake-handle")
        fake.nvmlDeviceGetName = mocker.MagicMock(return_value=name)
        fake.nvmlDeviceGetUtilizationRates = mocker.MagicMock(
            return_value=types.SimpleNamespace(gpu=util_gpu, memory=util_mem)
        )
        fake.nvmlDeviceGetMemoryInfo = mocker.MagicMock(
            return_value=types.SimpleNamespace(used=mem_used, total=mem_total, free=mem_total - mem_used)
        )
        fake.nvmlDeviceGetTemperature = mocker.MagicMock(return_value=temp)
        if power_supported:
            fake.nvmlDeviceGetPowerUsage = mocker.MagicMock(return_value=power_mw)
        else:
            fake.nvmlDeviceGetPowerUsage = mocker.MagicMock(side_effect=NVMLError("not supported"))

        # Register so `import pynvml` inside the function finds our mock.
        mocker.patch.dict(sys.modules, {"pynvml": fake})
        return fake

    def test_happy_path_all_fields_populated(self, mocker):
        self._install_fake_pynvml(mocker)
        result = wdm.get_gpu_metrics()
        assert result["available"] is True
        assert result["source"] == "pynvml"
        assert result["name"] == "NVIDIA GeForce RTX 4090"
        assert result["utilization_pct"] == 23.0
        assert result["vram_memctrl_pct"] == 7.0
        assert result["vram_used_mb"] == 1024.0
        assert result["vram_total_mb"] == 24576.0
        assert result["vram_pct"] == round(100.0 * 1024 / 24576, 1)  # rounded to 1 decimal
        assert result["temp_c"] == 52.0
        assert result["power_w"] == 45.2
        assert result["error"] is None

    def test_idle_gpu_zero_values_kept(self, mocker):
        """0% utilisation on an idle card is a real reading, not a missing
        one -- must come through as 0.0 float, not None."""
        self._install_fake_pynvml(mocker, util_gpu=0, util_mem=0, power_mw=22000)
        result = wdm.get_gpu_metrics()
        assert result["utilization_pct"] == 0.0
        assert result["vram_memctrl_pct"] == 0.0

    def test_nvml_init_failure_returns_unavailable(self, mocker):
        self._install_fake_pynvml(mocker, init_error="Driver/library version mismatch")
        result = wdm.get_gpu_metrics()
        assert result["available"] is False
        assert "NVML init failed" in result["error"]
        assert "version mismatch" in result["error"]
        assert result["utilization_pct"] is None

    def test_no_gpus_returns_unavailable(self, mocker):
        self._install_fake_pynvml(mocker, count=0)
        result = wdm.get_gpu_metrics()
        assert result["available"] is False
        assert "no NVIDIA GPU" in result["error"]

    def test_query_error_after_successful_init(self, mocker):
        """NVML init OK but device query fails mid-call -- must not crash,
        must still call nvmlShutdown."""
        fake = self._install_fake_pynvml(mocker, query_error="Device lost")
        result = wdm.get_gpu_metrics()
        assert result["available"] is False
        assert "NVML query failed" in result["error"]
        assert "Device lost" in result["error"]
        fake.nvmlShutdown.assert_called_once()

    def test_power_unsupported_becomes_none_not_error(self, mocker):
        """Lower-tier cards / passthrough VMs may return NOT_SUPPORTED for
        power. The collector treats that as 'no signal', not a full failure
        -- utilisation / temp / memory still come through."""
        self._install_fake_pynvml(mocker, power_supported=False)
        result = wdm.get_gpu_metrics()
        assert result["available"] is True
        assert result["power_w"] is None
        assert result["utilization_pct"] == 23.0  # other fields fine

    def test_import_error_returns_unavailable(self, mocker):
        """pynvml not installed at all -- collector must degrade gracefully,
        never raise ImportError up the stack."""
        import sys

        # Nuke pynvml from the module cache so import raises in the collector
        saved = sys.modules.pop("pynvml", None)
        # Also block future imports by setting to None
        mocker.patch.dict(sys.modules, {"pynvml": None})
        try:
            result = wdm.get_gpu_metrics()
            assert result["available"] is False
            assert "pynvml not installed" in result["error"]
        finally:
            if saved is not None:
                sys.modules["pynvml"] = saved

    def test_shutdown_called_on_success(self, mocker):
        """NVML is reference-counted -- leaking an init without a shutdown
        is bad hygiene. Verify every successful path calls shutdown."""
        fake = self._install_fake_pynvml(mocker)
        wdm.get_gpu_metrics()
        fake.nvmlShutdown.assert_called_once()

    def test_shutdown_called_on_query_error(self, mocker):
        """NVMLError during query must still trigger shutdown via finally."""
        fake = self._install_fake_pynvml(mocker, query_error="boom")
        wdm.get_gpu_metrics()
        fake.nvmlShutdown.assert_called_once()

    def test_bytes_name_decoded(self, mocker):
        """Older pynvml versions return bytes from nvmlDeviceGetName."""
        self._install_fake_pynvml(mocker, name=b"NVIDIA GeForce RTX 4090")
        result = wdm.get_gpu_metrics()
        assert result["name"] == "NVIDIA GeForce RTX 4090"
        assert isinstance(result["name"], str)

    def test_zero_total_memory_produces_none_vram_pct(self, mocker):
        """Defensive: if total RAM comes back 0 (shouldn't happen, but
        protect against div-by-zero), vram_pct is None not a crash."""
        self._install_fake_pynvml(mocker, mem_total=0, mem_used=0)
        result = wdm.get_gpu_metrics()
        assert result["vram_pct"] is None
        assert result["vram_total_mb"] == 0.0

    def test_vram_used_converted_to_mb(self, mocker):
        """pynvml returns raw bytes; collector converts to MB (/ 1024^2)."""
        self._install_fake_pynvml(
            mocker,
            mem_used=1536 * 1024 * 1024,  # 1.5 GB exactly
            mem_total=8192 * 1024 * 1024,  # 8 GB
        )
        result = wdm.get_gpu_metrics()
        assert result["vram_used_mb"] == 1536.0
        assert result["vram_total_mb"] == 8192.0

    def test_unexpected_exception_returns_unavailable(self, mocker):
        """Catch-all defence: if pynvml throws something wild, don't
        propagate -- surface a readable error string."""
        fake = self._install_fake_pynvml(mocker)
        fake.nvmlDeviceGetUtilizationRates.side_effect = RuntimeError("wat")
        result = wdm.get_gpu_metrics()
        assert result["available"] is False
        assert "unexpected GPU collector error" in result["error"]
        assert "RuntimeError" in result["error"]
        assert "wat" in result["error"]
