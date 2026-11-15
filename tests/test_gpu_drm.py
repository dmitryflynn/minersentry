"""DRM fdinfo GPU accounting for AMD and Intel on Linux (issue #18).

Tested against the kernel's documented format. Not run against hardware.
"""

from minersentry import gpu_drm as G

AMD = """pos:\t0
flags:\t02100002
drm-driver: amdgpu
drm-client-id: 42
drm-pdev: 0000:03:00.0
drm-engine-gfx: 1000 ns
drm-engine-compute: 5000000000 ns
drm-engine-capacity-compute: 4
drm-memory-vram: 100 KiB
"""


def test_a_drm_fdinfo_is_parsed():
    driver, client, engines = G.parse_drm_fdinfo(AMD)
    assert (driver, client) == ("amdgpu", "42")
    assert engines == {"gfx": 1000, "compute": 5000000000}


def test_an_ordinary_fdinfo_is_not_drm():
    assert G.parse_drm_fdinfo("pos:\t0\nflags:\t02\nmnt_id:\t21\n") is None
    assert G.parse_drm_fdinfo("") is None


def test_utilisation_is_the_delta_over_wall_time():
    before = {(7, "42"): {"compute": 1_000_000_000}}
    after = {(7, "42"): {"compute": 1_900_000_000}}
    out = G.utilisation(before, after, elapsed_ns=1_000_000_000)
    assert round(out[7]["compute"]) == 90


def test_a_client_with_no_baseline_contributes_nothing_yet():
    """Its lifetime total says nothing about the last few seconds."""
    assert G.utilisation({}, {(7, "42"): {"compute": 9_000_000_000}}, 1e9) == {}


def test_no_elapsed_time_means_no_reading():
    r = {(7, "42"): {"compute": 5}}
    assert G.utilisation(r, r, 0) == {}


def test_a_compute_engine_always_counts_and_render_only_for_a_client():
    assert G.compute_percent({"compute": 80.0}, is_client=False) == 80.0
    assert G.compute_percent({"render": 80.0}, is_client=False) == 0.0
    assert G.compute_percent({"render": 80.0}, is_client=True) == 80.0


def test_reading_a_missing_proc_returns_nothing(tmp_path):
    assert G.read_clients(root=str(tmp_path / "nope")) == {}


def test_only_dri_files_are_read(tmp_path):
    proc = tmp_path / "123"
    (proc / "fd").mkdir(parents=True)
    (proc / "fdinfo").mkdir()
    for fd in ("3", "4"):
        (proc / "fd" / fd).write_text("")
        (proc / "fdinfo" / fd).write_text(AMD)
    links = {"3": "/dev/dri/renderD128", "4": "/home/x/file"}
    out = G.read_clients(root=str(tmp_path),
                         readlink=lambda p: links[p.replace("\\", "/").rsplit("/", 1)[-1]])
    assert out == {(123, "42"): {"gfx": 1000, "compute": 5000000000}}
