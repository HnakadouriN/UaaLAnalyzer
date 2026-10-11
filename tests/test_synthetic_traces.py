from __future__ import annotations

from helpers import (
    PC_FILES,
    PC_NAMES,
    FakeResolver,
    anr_section,
    make_session,
    make_store,
    PACKAGE,
    PID,
    stuck_trace,
    thread_block,
    unity_main_frames,
)
from uaal_analyzer.analyze.engine import analyze_session
from uaal_analyzer.config import Config
from uaal_analyzer.symbolize.resolver import ResolvedSymbol
from uaal_analyzer.symbolize.symbolizer import symbolize_session

CFG = Config(app_assemblies=["Contoso.*"])
MODULES = ["libil2cpp.so"]


class InlineResolver:
    """DWARF 付きシンボルの結果を模す: 外側の関数名にハッシュが付き、インライン展開された補助関数を持つ。"""

    def resolve(self, symbol_file, addresses):
        result = {}
        for address in addresses:
            if address not in PC_NAMES:
                continue
            if address == 0x4000:
                result[address] = ResolvedSymbol(
                    PC_NAMES[address] + "_m" + "AB" * 20,
                    PC_FILES[address],
                    ("InterfaceFuncInvoker0<List_1_tBD0*>::Invoke(unsigned short, Il2CppClass*)",),
                )
            else:
                result[address] = ResolvedSymbol(PC_NAMES[address], PC_FILES[address])
        return result


def test_spinning_main_thread_reports_the_app_method_and_the_wait_rule(tmp_path):
    session = symbolize_session(make_session(stuck_trace(5)), make_store(tmp_path), FakeResolver(), MODULES)

    result = analyze_session(session, CFG)
    main = result.main_threads[0]

    assert result.sample_count == 5
    assert main.os_states == ["R"] * 5
    assert main.classification == "spinning"
    assert result.origin["function"] == "SettingsManager_OnModeChanged"
    assert result.origin["assembly"] == "Contoso.App.Presentation"
    assert result.main_observation == {"total": 5, "with_stack": 5, "il2cpp": 5, "app": 5, "unidentified_library": 0}
    assert [f.rule_id for f in result.findings] == ["wait-for-completion"]


def test_waiting_main_thread_is_not_reported_as_spinning():
    def section(k: int) -> str:
        threads = thread_block("UnityMain", 12, 8620, "Native", "S", 100, 10, unity_main_frames(0)[1:])
        return anr_section(PID, f"2026-09-24 20:30:{35 + 2 * k:02d}.0+0900", PACKAGE, threads)

    session = make_session("".join(section(k) for k in range(3)))

    result = analyze_session(session, CFG)
    main = result.main_threads[0]

    assert main.os_states == ["S"] * 3
    assert main.classification == "waiting"
    assert main.cpu_ratio < 0.05
    assert result.origin is None
    assert result.findings == []


def test_unset_app_assemblies_is_reported_as_the_reason_for_no_origin(tmp_path):
    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), FakeResolver(), MODULES)

    result = analyze_session(session, Config())

    assert result.origin is None
    assert "app_assemblies が未設定" in result.origin_note


def test_inlined_helpers_do_not_replace_the_outermost_function(tmp_path):
    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), InlineResolver(), MODULES)

    result = analyze_session(session, CFG)
    frames = {f.display_name().split("_m")[0]: f for f in result.main_threads[0].frames}

    assert result.origin["function"] == "SettingsManager_OnModeChanged"
    assert result.origin["raw"].startswith("SettingsManager_OnModeChanged_m")
    assert frames["SettingsManager_OnModeChanged"].inlined[0].startswith("InterfaceFuncInvoker0<")
    assert not any(name.startswith("InterfaceFuncInvoker") for name in result.reached)
