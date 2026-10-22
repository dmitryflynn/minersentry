"""Tests for GPU telemetry parsers (real PDH / nvidia-smi output shapes)."""

from minersentry import gpu

# A trimmed real `typeperf "\GPU Engine(*)\Utilization Percentage" -sc 1` sample:
# two engines for pid 4321 (Compute + 3D) and one Compute engine for pid 8899.
PDH_CSV = (
    '"(PDH-CSV 4.0)",'
    '"\\\\HOST\\GPU Engine(pid_4321_luid_0x0_0x1_phys_0_eng_3_engtype_Compute)\\Utilization Percentage",'
    '"\\\\HOST\\GPU Engine(pid_4321_luid_0x0_0x1_phys_0_eng_0_engtype_3D)\\Utilization Percentage",'
    '"\\\\HOST\\GPU Engine(pid_8899_luid_0x0_0x1_phys_0_eng_5_engtype_Compute)\\Utilization Percentage"\n'
    '"10/21/2026 14:00:00.000","87.5","4.2","63.0"\n'
)


def test_parse_pdh_sums_compute_per_pid():
    out = gpu.parse_gpu_engine_counters(PDH_CSV)
    assert round(out[4321]) == 88          # only the Compute engine, not the 3D one
    assert round(out[8899]) == 63


def test_parse_pdh_ignores_non_compute():
    # a buffer with only a 3D engine -> no compute utilization recorded
    only_3d = (
        '"(PDH-CSV 4.0)",'
        '"\\\\HOST\\GPU Engine(pid_1000_luid_0x0_0x1_phys_0_eng_0_engtype_3D)\\Utilization Percentage"\n'
        '"10/21/2026 14:00:00.000","99.0"\n'
    )
    assert gpu.parse_gpu_engine_counters(only_3d) == {}


def test_parse_pdh_empty_values():
    csv_text = (
        '"(PDH-CSV 4.0)",'
        '"\\\\HOST\\GPU Engine(pid_5_luid_0x0_0x1_phys_0_eng_3_engtype_Compute)\\Utilization Percentage"\n'
        '"10/21/2026 14:00:00.000"," "\n'
    )
    assert gpu.parse_gpu_engine_counters(csv_text).get(5, 0.0) == 0.0


def test_parse_pdh_garbage_returns_empty():
    assert gpu.parse_gpu_engine_counters("not a pdh csv") == {}


def test_parse_nvidia_compute_apps():
    text = "pid, used_gpu_memory [MiB]\n15184, [N/A]\n13356, 512 MiB\n"
    pids = gpu.parse_nvidia_compute_apps(text)
    assert pids == {15184, 13356}


def test_parse_nvidia_empty():
    assert gpu.parse_nvidia_compute_apps("") == set()


def test_parse_pdh_truncated_row_ignored():
    # a data row whose width != header width (truncated output) must be skipped,
    # not misparsed into bogus pid->util pairs
    csv_text = (
        '"(PDH-CSV 4.0)",'
        '"\\\\HOST\\GPU Engine(pid_7_luid_0x0_0x1_phys_0_eng_3_engtype_Compute)\\Utilization Percentage",'
        '"\\\\HOST\\GPU Engine(pid_8_luid_0x0_0x1_phys_0_eng_3_engtype_Compute)\\Utilization Percentage"\n'
        '"10/21/2026 14:00:00.000","50.0"\n'   # only one value for two columns
    )
    assert gpu.parse_gpu_engine_counters(csv_text) == {}


def test_parse_pdh_skips_pid_zero():
    csv_text = (
        '"(PDH-CSV 4.0)",'
        '"\\\\HOST\\GPU Engine(pid_0_luid_0x0_0x1_phys_0_eng_3_engtype_Compute)\\Utilization Percentage"\n'
        '"10/21/2026 14:00:00.000","80.0"\n'
    )
    assert 0 not in gpu.parse_gpu_engine_counters(csv_text)


def test_parse_nvidia_ignores_nonnumeric_pid():
    # a crafted/garbled line must not inject a bogus PID
    text = "pid, used_gpu_memory\nnotapid, 10\n4242, 5\n"
    assert gpu.parse_nvidia_compute_apps(text) == {4242}
