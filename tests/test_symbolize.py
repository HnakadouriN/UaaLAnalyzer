from __future__ import annotations

import subprocess

import pytest

from helpers import (
    IL2CPP_BUILD_ID,
    PC_NAMES,
    FakeResolver,
    anr_section,
    make_session,
    make_store,
    stuck_trace,
    thread_block,
)
from uaal_analyzer.errors import SymbolError
from uaal_analyzer.symbolize.resolver import Addr2LineResolver, ResolvedSymbol, parse_addr2line_output
from uaal_analyzer.symbolize.symbolizer import needed_build_ids, symbolize_session

MODULES = ["libil2cpp.so"]
INLINE_TEST_FILE = "C:/b/il2cppOutput/Unity.ResourceManager.cpp"


def test_parse_addr2line_output_skips_unknown_functions():
    text = (
        "0x0000000000001000\nResourceManager_Update\nC:/b/il2cppOutput/foo.cpp:10\n"
        "0x0000000000002000\n??\n??:0\n"
        "0x0000000000003000\nModeProvider_get_Modes\n??:0\n"
        "0x0000000000004000\nfn\nbar.cpp:7 (discriminator 3)\n"
    )
    assert parse_addr2line_output(text) == {
        0x1000: ResolvedSymbol("ResourceManager_Update", "C:/b/il2cppOutput/foo.cpp"),
        0x3000: ResolvedSymbol("ModeProvider_get_Modes", None),
        0x4000: ResolvedSymbol("fn", "bar.cpp"),
    }


def test_parse_addr2line_output_uses_outermost_function_and_keeps_inlined_helpers():
    # DWARF 付き libil2cpp の `llvm-addr2line -a -C -f -i` の出力形式。内側 -> 外側の順に並ぶ。
    gen = "C:/b/il2cppOutput/Contoso.App.Presentation__1.cpp"
    text = (
        "0x4dc43c8\n"
        "InterfaceFuncInvoker0<List_1_tBD0*>::Invoke(unsigned short, Il2CppClass*, Il2CppObject*)\n"
        f"{gen}:112\n"
        "SettingsManager_OnModeChanged_m0123456789ABCDEF0123456789ABCDEF01234567\n"
        f"{gen}:14278\n"
        "0x4dcd028\n"
        "U3CStartU3Ed__9_MoveNext_m1111111111111111111111111111111111111111\n"
        f"{gen}:21546\n"
        "0x4dccc08\n"
        "AsyncUniTaskMethodBuilder_Start_X_gshared_inline(A*, B*, MethodInfo const*)\n"
        f"{gen}:29288\n"
        "AsyncUniTaskMethodBuilder_Start_X_inline(A*, B*, MethodInfo const*)\n"
        f"{gen}:8465\n"
        "BasePanel_TryLoadAsync_m2222222222222222222222222222222222222222\n"
        f"{gen}:21309\n"
    )

    result = parse_addr2line_output(text)

    assert result[0x4DC43C8] == ResolvedSymbol(
        "SettingsManager_OnModeChanged_m0123456789ABCDEF0123456789ABCDEF01234567",
        gen,
        ("InterfaceFuncInvoker0<List_1_tBD0*>::Invoke(unsigned short, Il2CppClass*, Il2CppObject*)",),
    )
    assert result[0x4DCD028].inlined == ()
    assert result[0x4DCCC08].name.startswith("BasePanel_TryLoadAsync")
    assert [n.split("(")[0] for n in result[0x4DCCC08].inlined] == [
        "AsyncUniTaskMethodBuilder_Start_X_gshared_inline",
        "AsyncUniTaskMethodBuilder_Start_X_inline",
    ]


def test_parse_addr2line_output_with_inline_chain_does_not_swallow_the_next_address():
    text = "0x10\nouter\nf.cpp:1\n0x20\n??\n??:0\n0x30\ninner\ng.cpp:2\nouter2\ng.cpp:9\n"

    assert parse_addr2line_output(text) == {
        0x10: ResolvedSymbol("outer", "f.cpp"),
        0x30: ResolvedSymbol("outer2", "g.cpp", ("inner",)),
    }


def test_symbolize_stores_inlined_helpers_on_the_frame(tmp_path):
    class InlineResolver:
        def resolve(self, symbol_file, addresses):
            return {a: ResolvedSymbol("OuterMethod", INLINE_TEST_FILE, ("Helper<int>::Invoke(int)",)) for a in addresses}

    result = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), InlineResolver(), MODULES)

    frame = result.samples[0].threads[1].frames[1]
    assert frame.resolved == "OuterMethod"
    assert frame.inlined == ["Helper<int>::Invoke(int)"]


def test_addr2line_resolver_passes_addresses_via_stdin(tmp_path):
    captured = {}

    def runner(command, **kwargs):
        captured["command"] = command
        captured["input"] = kwargs["input"]
        return subprocess.CompletedProcess(command, 0, stdout=b"0x0000000000001000\nfn\nx:1\n", stderr=b"")

    resolver = Addr2LineResolver(tmp_path / "llvm-addr2line", runner)
    result = resolver.resolve(tmp_path / "libil2cpp.dbg.so", [0x1000])

    assert result == {0x1000: ResolvedSymbol("fn", "x")}
    assert captured["input"] == b"0x1000\n"
    assert "-a" in captured["command"] and "-C" in captured["command"] and "-f" in captured["command"]
    assert "-i" in captured["command"]  # インライン展開された補助関数ではなく、実際に呼ばれた関数を得る


def test_addr2line_resolver_raises_on_failure(tmp_path):
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=b"boom")

    with pytest.raises(SymbolError):
        Addr2LineResolver(tmp_path / "t", runner).resolve(tmp_path / "f", [1])


def test_symbolize_resolves_matching_build_id_and_leaves_other_modules(tmp_path):
    session = make_session(stuck_trace(3))
    resolver = FakeResolver()

    result = symbolize_session(session, make_store(tmp_path), resolver, MODULES)

    frames = result.samples[0].threads[1].frames
    assert frames[1].resolved == "ResourceManager_Update"
    assert frames[1].resolution == "resolved"
    assert frames[1].source_file.endswith("Unity.ResourceManager.cpp")
    assert frames[0].resolution == "none"  # libc は対象モジュール外
    assert frames[0].resolved is None
    assert result.symbol_report[IL2CPP_BUILD_ID]["status"] == "resolved"
    assert len(resolver.calls) == 1
    assert resolver.calls[0][1] == sorted(set(resolver.calls[0][1]))  # アドレスは重複なし
    assert session.samples[0].threads[1].frames[1].resolved is None  # 入力は変更しない


def test_symbolize_does_not_guess_when_build_id_differs(tmp_path):
    session = make_session(stuck_trace(3))
    resolver = FakeResolver()
    store = make_store(tmp_path, build_id="dd" * 20)

    result = symbolize_session(session, store, resolver, MODULES)

    frames = result.samples[0].threads[1].frames
    assert frames[1].resolved is None
    assert frames[1].resolution == "no_symbols"
    assert resolver.calls == []
    assert any(IL2CPP_BUILD_ID in w and "dd" * 20 in w for w in result.warnings)
    assert result.symbol_report[IL2CPP_BUILD_ID]["status"] == "no_symbols"


def test_symbolize_marks_frames_without_build_id_as_unverified(tmp_path):
    text = stuck_trace(3).replace(f" (BuildId: {IL2CPP_BUILD_ID})", "")
    session = make_session(text)
    resolver = FakeResolver()

    result = symbolize_session(session, make_store(tmp_path), resolver, MODULES)

    assert result.samples[0].threads[1].frames[1].resolution == "unverified"
    assert resolver.calls == []
    assert any("BuildId が無い" in w for w in result.warnings)


def test_symbolize_reports_resolver_failure_without_resolving(tmp_path):
    class Failing:
        def resolve(self, symbol_file, addresses):
            raise SymbolError("boom")

    result = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), Failing(), MODULES)

    assert result.samples[0].threads[1].frames[1].resolution == "unresolved"
    assert any("boom" in w for w in result.warnings)


def test_needed_build_ids_lists_only_target_modules():
    assert needed_build_ids(make_session(stuck_trace(3)), MODULES) == {IL2CPP_BUILD_ID}


def test_library_names_are_attached_by_build_id_even_without_symbols(tmp_path):
    session = _apk_session("f6" * 20)

    result = symbolize_session(
        session, make_store(tmp_path, IL2CPP_BUILD_ID), FakeResolver(), MODULES, {"F6" * 20: "libil2cpp.so"}
    )

    frames = result.samples[0].threads[0].frames
    assert {f.library for f in frames} == {"libil2cpp.so"}
    assert all(f.module_label == "libil2cpp.so" for f in frames)
    assert all(f.resolution == "no_symbols" for f in frames)
    assert any("libil2cpp.so: BuildId" in w for w in result.warnings)


def test_pc_names_cover_all_il2cpp_frames():
    assert 0x1000 in PC_NAMES


def _apk_session(build_id: str):
    apk = "/data/app/~~x==/com.example.app-y==/base.apk"
    lines = [
        f"  native: #00 pc 0000000000001000  {apk} (offset f2b0000) (???) (BuildId: {build_id})",
        f"  native: #01 pc 0000000000002000  {apk} (offset f2b0000) (???) (BuildId: {build_id})",
    ]
    threads = thread_block("UnityMain", 22, 14031, "Native", "R", 1, 1, lines)
    text = anr_section(8589, "2026-10-08 15:28:53.0+0900", "com.example.app", threads)
    return make_session(text + text.replace("15:28:53", "15:28:55"))


def test_unnamed_apk_libraries_are_symbolized_by_build_id(tmp_path):
    device_id = "f6" * 20
    session = _apk_session(device_id)
    resolver = FakeResolver()

    result = symbolize_session(session, make_store(tmp_path, device_id), resolver, MODULES)

    frames = result.samples[0].threads[0].frames
    assert [f.resolved for f in frames] == ["ResourceManager_Update", "AsyncOperationBase_WaitForCompletion"]
    assert result.symbol_report[device_id]["module"] == "base.apk@f2b0000"
    assert needed_build_ids(session, MODULES) == {device_id}


def test_apk_library_with_other_build_id_is_not_guessed(tmp_path):
    session = _apk_session("f6" * 20)
    resolver = FakeResolver()

    result = symbolize_session(session, make_store(tmp_path, IL2CPP_BUILD_ID), resolver, MODULES)

    assert all(f.resolved is None and f.resolution == "no_symbols" for f in result.samples[0].threads[0].frames)
    assert resolver.calls == []
    assert any("base.apk@f2b0000" in w and IL2CPP_BUILD_ID in w for w in result.warnings)
