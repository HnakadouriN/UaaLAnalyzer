from __future__ import annotations

import pytest

from helpers import (
    FakeResolver,
    IL2CPP_BUILD_ID,
    anr_section,
    make_session,
    make_store,
    native,
    stuck_section,
    stuck_trace,
    thread_block,
    unity_main_frames,
    IL2CPP_PATH,
    LIBC_PATH,
    LIBC_BUILD_ID,
)
from uaal_analyzer.analyze.engine import analyze_session
from uaal_analyzer.analyze.stuck import analyze_threads
from uaal_analyzer.config import Config
from uaal_analyzer.model import ProcSnapshot, ProcThread
from uaal_analyzer.symbolize.symbolizer import symbolize_session

CFG = Config(app_assemblies=["Contoso.*"])


def _by_name(results, name):
    return next(t for t in results if t.name == name)


def test_unity_main_is_stuck_with_common_outer_frames_and_spinning():
    results = analyze_threads(make_session(stuck_trace(3)), CFG)

    main = _by_name(results, "UnityMain")
    assert main.is_main
    assert main.stuck
    # 外側 10 フレーム (#11..#02) は不変。#01 と #00 は pc / 関数が変化する。
    assert main.common_len == 10
    assert main.common_ratio == pytest.approx(10 / 12)
    assert main.classification == "spinning"
    assert main.os_states == ["R", "R", "R"]
    assert main.cpu_ticks_delta == (100 + 200 * 2 + 10 + 10 * 2) - (100 + 10)
    assert main.window_sec == 4.0


def test_idle_threads_are_not_reported_busy():
    results = analyze_threads(make_session(stuck_trace(3)), CFG)

    worker = _by_name(results, "Worker")
    assert worker.classification == "waiting"
    assert _by_name(results, "main").classification == "waiting"


def test_not_stuck_when_outer_frames_change():
    changing = "".join(
        anr_section(
            8589,
            f"2026-09-24 20:30:{35 + 2 * k:02d}.0+0900",
            "com.example.app",
            thread_block(
                "UnityMain",
                12,
                8620,
                "Runnable",
                "R",
                10 * k,
                0,
                [native(0, 0x10, LIBC_PATH, "syscall+1", LIBC_BUILD_ID), native(1, 0x100 * (k + 1), IL2CPP_PATH, None, IL2CPP_BUILD_ID)]
                + [native(2, 0x7000 + 0x10 * k, IL2CPP_PATH, None, IL2CPP_BUILD_ID)],
            ),
        )
        for k in range(3)
    )

    main = _by_name(analyze_threads(make_session(changing), CFG), "UnityMain")

    assert not main.stuck
    assert main.common_len == 0


def test_thread_missing_in_some_samples_is_not_judged_stuck():
    text = stuck_section(0) + stuck_section(1).replace('"Worker"', '"Other"').replace("tid=15", "tid=16").replace("sysTid=8630", "sysTid=8631")
    results = analyze_threads(make_session(text), CFG)

    assert not _by_name(results, "Worker").stuck
    assert not _by_name(results, "Other").stuck


def test_single_sample_still_reports_origin_but_cannot_judge_stuck(tmp_path):
    session = symbolize_session(make_session(stuck_trace(1)), make_store(tmp_path), FakeResolver(), ["libil2cpp.so"])

    result = analyze_session(session, CFG)

    assert not result.main_threads[0].stuck
    assert result.origin["function"] == "SettingsManager_OnModeChanged"
    assert "変化しています" in result.observation


def test_cpu_falls_back_to_proc_snapshots_when_trace_has_no_ticks():
    text = stuck_trace(3).replace("utm=", "xtm=")
    session = make_session(text)
    session.proc_snapshots = [
        ProcSnapshot(0, "2026-09-24T20:30:34+0900", [ProcThread(8620, "UnityMain", "R", 100, 10)]),
        ProcSnapshot(1, "2026-09-24T20:30:40+0900", [ProcThread(8620, "UnityMain", "R", 500, 50)]),
    ]

    main = _by_name(analyze_threads(session, CFG), "UnityMain")

    assert main.cpu_ticks_delta == 440
    assert main.window_sec == 6.0
    assert main.classification == "spinning"


def test_acceptance_chain_is_summarized_after_symbolization(tmp_path):
    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), FakeResolver(), ["libil2cpp.so"])

    result = analyze_session(session, CFG)

    main = result.main_threads
    outer_to_inner = [f.display_name() for f in reversed(main[0].frames)]
    chain = [
        "BasePanel_TryLoadAsync",
        "SettingsManager_OnModeChanged",
        "ModeProvider_get_Modes",
        "AsyncOperationBase_WaitForCompletion",
        "ResourceManager_Update",
    ]
    positions = [outer_to_inner.index(name) for name in chain]
    assert positions == sorted(positions)
    assert "空回り" in result.verdict
    assert [f.rule_id for f in result.findings] == ["wait-for-completion"]
    assert "WaitForCompletion" in result.findings[0].evidence[0]


def test_unsymbolized_session_has_no_rule_hits_and_no_origin():
    result = analyze_session(make_session(stuck_trace(3)), CFG)

    assert result.main_threads[0].stuck
    assert result.findings == []
    assert result.origin is None
    assert result.reached == []


def test_origin_is_the_innermost_app_frame_of_the_latest_path(tmp_path):
    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), FakeResolver(), ["libil2cpp.so"])

    result = analyze_session(session, CFG)

    assert result.origin is not None
    assert result.origin["function"] == "SettingsManager_OnModeChanged"
    assert result.origin["assembly"] == "Contoso.App.Presentation"
    assert result.origin["library"] == "libil2cpp.so"


def test_origin_is_absent_without_matching_app_assembly(tmp_path):
    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), FakeResolver(), ["libil2cpp.so"])

    result = analyze_session(session, Config(app_assemblies=["Other.*"]))

    assert result.origin is None


def test_short_common_path_relative_to_depth_is_not_stuck():
    def section(k, extra):
        frames = [native(i, 0x7000 + 0x10 * k + i, IL2CPP_PATH, None, IL2CPP_BUILD_ID) for i in range(extra)]
        frames += [native(extra + i, 0x100 * i, LIBC_PATH, f"outer{i}", LIBC_BUILD_ID) for i in range(6)]
        return anr_section(
            8589,
            f"2026-09-24 20:30:{35 + 2 * k:02d}.0+0900",
            "com.example.app",
            thread_block("UnityMain", 12, 8620, "Runnable", "R", 100 * k, 0, frames),
        )

    # 外側 6 フレームは共通だが、内側の 14 フレームが毎回変わる (共通の割合 30%)。
    main = _by_name(analyze_threads(make_session("".join(section(k, 14) for k in range(3))), CFG), "UnityMain")

    assert main.common_len == 6
    assert main.common_ratio == pytest.approx(0.3)
    assert not main.stuck


def test_other_busy_stuck_threads_are_listed():
    def busy_worker(k):
        return thread_block("Worker", 15, 8630, "Runnable", "R", 300 * k, 0, unity_main_frames(0)[1:])

    text = "".join(
        anr_section(8589, f"2026-09-24 20:30:{35 + 2 * k:02d}.0+0900", "com.example.app", busy_worker(k)) for k in range(3)
    )

    result = analyze_session(make_session(text), CFG)

    assert [t.name for t in result.busy_threads] == ["Worker"]
    assert any("主スレッド" in w for w in result.warnings)


def test_unknown_rule_name_is_rejected():
    import pytest
    from uaal_analyzer.errors import ConfigError

    cfg = Config(rules=["no-such-rule"])
    with pytest.raises(ConfigError):
        analyze_session(make_session(stuck_trace(3)), cfg)
