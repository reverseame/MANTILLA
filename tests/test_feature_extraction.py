"""Tests for the pure (non-radare2) logic in feature_extraction.py.

Importing the module pulls in native deps (magic, tlsh, ssdeep, r2pipe); if any
is unavailable the whole module is skipped rather than failing collection.
"""
import pytest

fe = pytest.importorskip("feature_extraction")


def test_func_offset_accepts_addr_or_offset():
    # radare2 5.x exposes 'offset', 6.x exposes 'addr'.
    assert fe.BinaryAnalyzer._func_offset({'offset': 0x1000}) == 0x1000
    assert fe.BinaryAnalyzer._func_offset({'addr': 0x2000}) == 0x2000


def test_entropy_calculator_uniform_bytes():
    # 256 distinct byte values -> 8 bits of entropy.
    data = bytes(range(256))
    assert fe.EntropyCalculator.calculate_entropy(data) == pytest.approx(8.0)
    # A single repeated byte -> 0 entropy.
    assert fe.EntropyCalculator.calculate_entropy(b"\x00" * 32) == pytest.approx(0.0)


def test_clean_function_names_strips_prefixes_and_suffixes():
    out = fe.FunctionFilter.clean_function_names([
        {'name': 'sym.imp.printf', 'offset': 1},
        {'name': 'sym.my_func', 'offset': 2},
        {'name': 'dbg.helper', 'offset': 3},
        {'name': 'foo_2', 'offset': 4},
    ])
    names = [c['name'] for c in out]
    assert names == ['printf', 'my_func', 'helper', 'foo']


def test_remove_fnc_c_plus_exact_match_no_substring_overremoval():
    clean = [{'name': n, 'offset': i} for i, n in enumerate(
        ['address_of', 'padding', 'read_config', 'add', 'main', 'real'])]
    out = [c['name'] for c in fe.FunctionFilter.remove_fnc_c_plus(clean, {'add', 'read', 'main'})]
    # 'add' removed (exact); 'main' kept; substring matches NOT removed.
    assert 'add' not in out
    assert 'main' in out
    assert {'address_of', 'padding', 'read_config', 'real'} <= set(out)


def test_remove_glibc_uses_bundled_lists():
    # Resolved against the script dir, so this works from any CWD.
    clean = [{'name': 'malloc', 'offset': 1},
             {'name': 'zzz_not_a_libc_fn_123', 'offset': 2}]
    out = [c['name'] for c in fe.FunctionFilter.remove_glibc(clean)]
    assert 'malloc' not in out                 # present in glibc_functions.txt
    assert 'zzz_not_a_libc_fn_123' in out


def test_remove_known_fnc_suffix_and_prefix_rules():
    clean = [{'name': n, 'offset': i} for i, n in enumerate(
        ['foo.cold', '_IO_helper', 'memcpy_avx2', 'my_unique_fn_xyz'])]
    out = [c['name'] for c in fe.FunctionFilter.remove_known_fnc(clean)]
    assert out == ['my_unique_fn_xyz']
