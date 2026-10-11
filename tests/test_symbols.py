from __future__ import annotations

import subprocess

import pytest

from helpers import IL2CPP_BUILD_ID
from uaal_analyzer.symbols.importer import find_candidates, import_symbols, make_build_id_reader
from uaal_analyzer.symbols.index import SymbolIndex, ensure_symbols
from uaal_analyzer.symbols.store import SymbolStore, normalize_library_name

OTHER_BUILD_ID = "bb" * 20


def _fake_reader(mapping):
    def read(path):
        return mapping.get(path.name)

    return read


def test_store_add_find_and_entries(tmp_path):
    source = tmp_path / "libil2cpp.dbg.so"
    source.write_bytes(b"x" * 10)
    store = SymbolStore(tmp_path / "store")

    stored = store.add(source, IL2CPP_BUILD_ID.upper())

    assert stored == store.find(IL2CPP_BUILD_ID)
    assert stored.read_bytes() == b"x" * 10
    entries = store.entries()
    assert [e.build_id for e in entries] == [IL2CPP_BUILD_ID]
    assert entries[0].source == str(source)
    assert store.find(OTHER_BUILD_ID) is None


def test_store_keeps_first_copy_when_same_build_id_added_again(tmp_path):
    first = tmp_path / "a" / "libil2cpp.dbg.so"
    second = tmp_path / "b" / "libil2cpp.dbg.so"
    for path, data in ((first, b"1"), (second, b"2")):
        path.parent.mkdir()
        path.write_bytes(data)
    store = SymbolStore(tmp_path / "store")

    store.add(first, IL2CPP_BUILD_ID)
    stored = store.add(second, IL2CPP_BUILD_ID)

    assert stored.read_bytes() == b"1"


def test_find_candidates_recurses_directories_for_dbg_so(tmp_path):
    nested = tmp_path / "artifacts" / "objcopy_4di1"
    nested.mkdir(parents=True)
    (nested / "libil2cpp.dbg.so").write_bytes(b"d")
    (nested / "libil2cpp.sym.so").write_bytes(b"s")
    explicit = tmp_path / "custom.so"
    explicit.write_bytes(b"c")

    found = find_candidates([tmp_path / "artifacts", explicit])

    assert [p.name for p in found] == ["libil2cpp.dbg.so", "custom.so"]


def test_import_symbols_reports_unreadable_build_id(tmp_path):
    good = tmp_path / "good.dbg.so"
    bad = tmp_path / "bad.dbg.so"
    good.write_bytes(b"g")
    bad.write_bytes(b"b")
    store = SymbolStore(tmp_path / "store")

    results = import_symbols(store, _fake_reader({"good.dbg.so": IL2CPP_BUILD_ID}), [tmp_path])

    by_name = {r.source.name: r for r in results}
    assert by_name["good.dbg.so"].stored is not None
    assert by_name["bad.dbg.so"].build_id is None
    assert by_name["bad.dbg.so"].stored is None


def test_ensure_symbols_imports_only_matching_build_id(tmp_path):
    search = tmp_path / "build"
    search.mkdir()
    (search / "match.dbg.so").write_bytes(b"m")
    (search / "other.dbg.so").write_bytes(b"o")
    store = SymbolStore(tmp_path / "store")
    reader = _fake_reader({"match.dbg.so": IL2CPP_BUILD_ID, "other.dbg.so": OTHER_BUILD_ID})
    index = SymbolIndex(tmp_path / "index.json", reader)
    index.scan([search], ["*.so"])

    found = ensure_symbols(store, index, {IL2CPP_BUILD_ID.upper(), "cc" * 20})

    assert found == {IL2CPP_BUILD_ID}
    assert store.find(OTHER_BUILD_ID) is None


def test_index_prefers_symbol_files_then_larger_size(tmp_path):
    root = tmp_path / "b"
    (root / "symbols").mkdir(parents=True)
    (root / "intermediates").mkdir()
    files = {
        root / "intermediates" / "libunity.so": b"x" * 50,
        root / "symbols" / "libunity.so": b"x" * 10,
        root / "libunity.sym.so": b"x" * 5,
        root / "libunity.dbg.so": b"x" * 1,
    }
    for path, data in files.items():
        path.write_bytes(data)
    index = SymbolIndex(tmp_path / "index.json", lambda p: IL2CPP_BUILD_ID)
    index.scan([root], ["*.so"])

    ranked = [p.relative_to(root).as_posix() for p in index.candidates(IL2CPP_BUILD_ID)]

    assert ranked == ["libunity.dbg.so", "libunity.sym.so", "symbols/libunity.so", "intermediates/libunity.so"]
    assert index.library_name(IL2CPP_BUILD_ID) == "libunity.so"


def test_index_caches_build_ids_by_size_and_mtime(tmp_path):
    root = tmp_path / "b"
    root.mkdir()
    lib = root / "libil2cpp.so"
    lib.write_bytes(b"1234")
    calls = []

    def reader(path):
        calls.append(path.name)
        return IL2CPP_BUILD_ID

    cache = tmp_path / "index.json"
    SymbolIndex(cache, reader).scan([root], ["*.so"])
    SymbolIndex(cache, reader).scan([root], ["*.so"])
    assert calls == ["libil2cpp.so"]

    lib.write_bytes(b"12345678")
    SymbolIndex(cache, reader).scan([root], ["*.so"])
    assert calls == ["libil2cpp.so", "libil2cpp.so"]


def test_index_skips_missing_roots_and_ignores_deleted_files(tmp_path):
    root = tmp_path / "b"
    root.mkdir()
    lib = root / "libx.so"
    lib.write_bytes(b"1")
    index = SymbolIndex(tmp_path / "index.json", lambda p: IL2CPP_BUILD_ID)
    index.scan([tmp_path / "missing", root], ["*.so"])

    lib.unlink()

    assert index.candidates(IL2CPP_BUILD_ID) == []
    assert index.library_name(IL2CPP_BUILD_ID) is None


def test_index_ignores_cache_with_unknown_version(tmp_path):
    cache = tmp_path / "index.json"
    cache.write_text('{"version": 99, "entries": {"x": {}}}', encoding="utf-8")

    index = SymbolIndex(cache, lambda p: None)

    assert index.candidates(IL2CPP_BUILD_ID) == []


@pytest.mark.parametrize(
    "name,expected",
    [("libil2cpp.dbg.so", "libil2cpp.so"), ("libunity.sym.so", "libunity.so"), ("libmain.so", "libmain.so")],
)
def test_normalize_library_name(name, expected):
    assert normalize_library_name(name) == expected


def test_store_library_name_uses_stored_file(tmp_path):
    source = tmp_path / "libil2cpp.dbg.so"
    source.write_bytes(b"x")
    store = SymbolStore(tmp_path / "store")
    store.add(source, IL2CPP_BUILD_ID)

    assert store.library_name(IL2CPP_BUILD_ID) == "libil2cpp.so"
    assert store.library_name(OTHER_BUILD_ID) is None


def test_build_id_reader_parses_readelf_output(tmp_path):
    output = b"Displaying notes found in: .note.gnu.build-id\n  Owner  Data size\n  GNU    0x00000014\n    Build ID: AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12\n"

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")

    reader = make_build_id_reader(tmp_path / "llvm-readelf", runner)

    assert reader(tmp_path / "x.so") == IL2CPP_BUILD_ID
