"""Tests for memory-fingerprint matching (no live process needed)."""

from minersentry import memscan


def scan(buf: bytes) -> memscan.MemScanResult:
    r = memscan.MemScanResult(pid=1234)
    memscan._search_chunk(buf, r, set())
    return r


def test_string_marker_detected():
    r = scan(b"...garbage...stratum+tcp://pool.example:3333...more...")
    assert any(h.where == "string" for h in r.hits)
    assert r.score > 0


def test_case_insensitive_string_match():
    r = scan(b"XMRig/6.21.0 RandomX")
    labels = [h.label for h in r.hits]
    assert any("XMRig" in label for label in labels)


def test_clean_buffer_has_no_hits():
    r = scan(b"the quick brown fox jumps over the lazy dog" * 100)
    assert not r.hits
    assert r.score == 0


def test_string_markers_outweigh_binary_constants():
    # a strong protocol/identifier string must score higher than a lone constant
    strong = scan(b'{"method":"login","params":{}}').score
    weak = scan(bytes.fromhex("0100000000000000")).score
    assert strong > weak


def test_binary_constant_only_stays_weak():
    # weak constants alone must not reach the memory "hard evidence" gate (40)
    r = scan(bytes.fromhex("0100000000000000") + bytes.fromhex("08c9bcf367e6096a"))
    assert r.score < 40


def test_dedup_same_label_counts_once():
    r = scan(b"xmrig xmrig xmrig xmrig")
    xmrig_hits = [h for h in r.hits if "XMRig" in h.label]
    assert len(xmrig_hits) == 1
