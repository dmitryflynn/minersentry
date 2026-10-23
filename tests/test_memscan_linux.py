"""Tests for the Linux /proc memory-map parsing (pure, runs on any OS)."""

from minersentry import memscan

# A trimmed real /proc/<pid>/maps: the binary (r-xp, file-backed), a ~2 GiB
# anonymous rw region (a RandomX dataset), and the stack.
MAPS = (
    "55a3c0000000-55a3c0021000 r-xp 00000000 08:01 1312470 /usr/bin/python3.11\n"
    "7f8800000000-7f8880000000 rw-p 00000000 00:00 0 \n"               # 0x80000000 = 2 GiB
    "7fff12340000-7fff12361000 rw-p 00000000 00:00 0 [stack]\n"
)
TWO_GIB = 2 * 1024 * 1024 * 1024 - (64 * 1024 * 1024)


def test_parse_maps_fields():
    regions = memscan.parse_maps(MAPS)
    assert len(regions) == 3
    start, end, perms, path = regions[0]
    assert start == 0x55a3c0000000 and end == 0x55a3c0021000
    assert perms == "r-xp"
    assert path.endswith("python3.11")
    assert regions[1][3] == ""          # anonymous region -> no path
    assert regions[2][3] == "[stack]"


def test_large_dataset_detected():
    regions = memscan.parse_maps(MAPS)
    assert memscan.maps_has_large_dataset(regions, TWO_GIB)


def test_no_large_dataset_when_regions_small():
    small = "7f8800000000-7f8800100000 rw-p 00000000 00:00 0 \n"   # 1 MiB
    assert not memscan.maps_has_large_dataset(memscan.parse_maps(small), TWO_GIB)


def test_shared_mapping_not_counted_as_dataset():
    # a 2 GiB SHARED file-backed mapping (perms 's') is not a private dataset
    shared = "7f8800000000-7f8880000000 rw-s 00000000 08:01 42 /huge.db\n"
    assert not memscan.maps_has_large_dataset(memscan.parse_maps(shared), TWO_GIB)


def test_parse_maps_ignores_garbage():
    assert memscan.parse_maps("not a maps line\n\n") == []
