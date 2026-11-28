"""`str.isdigit()` is True for superscripts and other characters `int()`
rejects, so a parser that checked isdigit() and then called int() raised on
input it had just accepted. The parsers of external text use isdecimal()."""

from minersentry import gpu_drm, tcpstats


def test_an_address_with_a_superscript_port_is_skipped_not_raised():
    assert tcpstats._split_addr("1.2.3.4:4²3") is None


def test_a_drm_engine_value_with_superscripts_is_ignored():
    text = "drm-driver: i915\ndrm-client-id: 7\ndrm-engine-render: ²³ ns\n"
    assert gpu_drm.parse_drm_fdinfo(text) == ("i915", "7", {})


def test_ordinary_values_still_parse():
    assert tcpstats._split_addr("10.0.0.5:443") == ("10.0.0.5", 443)
    text = "drm-driver: i915\ndrm-client-id: 7\ndrm-engine-render: 1234 ns\n"
    assert gpu_drm.parse_drm_fdinfo(text) == ("i915", "7", {"render": 1234})
