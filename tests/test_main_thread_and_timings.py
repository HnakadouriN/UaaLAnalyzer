from __future__ import annotations

import json

import pytest

from helpers import (
    APK_UNNAMED_LINE,
    IL2CPP_BUILD_ID,
    IL2CPP_PATH,
    LIBC_BUILD_ID,
    LIBC_PATH,
    PACKAGE,
    PID,
    FakeResolver,
    anr_section,
    make_session,
    make_store,
    native,
    stuck_trace,
    thread_block,
)
from test_capture import FakeAdb, _options
from uaal_analyzer.analyze.engine import analyze_session, describe_main_observation
from uaal_analyzer.collect.capture import rebuild_session, run_capture
from uaal_analyzer.config import Config
from uaal_analyzer.model import ProcSnapshot, Session
from uaal_analyzer.report.html import render_html
from uaal_analyzer.report.markdown import render_report
from uaal_analyzer.symbolize.resolver import ResolvedSymbol
from uaal_analyzer.symbolize.symbolizer import symbolize_session

CFG = Config(app_assemblies=["Contoso.*"])
JAVA_PLAYER = "  at com.unity3d.player.UnityPlayerForActivityOrService.nativeRender(Native method)"


def _il2cpp_frame(pc: int = 0x100) -> list[str]:
    return [native(0, pc, IL2CPP_PATH, None, IL2CPP_BUILD_ID)]


def _detached(name: str, sys_tid: int, utm: int = 0) -> str:
    return (
        f'"{name}" prio=5 (not attached)\n'
        f"  | sysTid={sys_tid} nice=0 cgrp=top-app\n"
        f"  | state=S schedstat=( 1 2 3 ) utm={utm} stm=0 core=6 HZ=100\n"
        f"{native(0, 0x9A1B4, LIBC_PATH, 'syscall+28', LIBC_BUILD_ID)}\n"
    )


def _session(per_sample_threads: list[str]):
    text = "".join(
        anr_section(PID, f"2026-10-08 19:09:{4 + 8 * k:02d}.0+0900", PACKAGE, threads)
        for k, threads in enumerate(per_sample_threads)
    )
    return make_session(text)


def _main(utm: int = 10, frames: list[str] | None = None, sys_tid: int = 28742) -> str:
    return thread_block("UnityMain", 22, sys_tid, "Native", "S", utm, 0, (frames or _il2cpp_frame()) + [JAVA_PLAYER])


# ---- 工程 9: 主スレッドの選び方 ----


def test_main_thread_prefers_the_attached_thread_seen_in_every_sample():
    samples = [
        _main(10) + "\n" + _detached("UnityMain", 30548, 0),
        _main(40) + "\n" + _detached("UnityMain", 30548, 0),
        _main(90),
    ]

    result = analyze_session(_session(samples), CFG)

    assert [t.sys_tid for t in result.main_threads] == [28742, 30548]
    assert result.main_threads[0].sys_tid == 28742
    assert [c["selected"] for c in result.main_candidates] == [True, False]
    assert result.main_candidates[1]["attached"] is False
    assert not result.main_ambiguous
    assert "28742" in result.main_note


def test_main_thread_candidate_present_only_in_the_last_sample_does_not_win():
    samples = [_main(10), _main(40), _main(90) + "\n" + _detached("UnityMain", 30548, 500)]

    result = analyze_session(_session(samples), CFG)

    assert result.main_threads[0].sys_tid == 28742


def test_main_thread_is_ambiguous_when_candidates_tie_and_cpu_decides():
    block = lambda sys_tid, utm: thread_block("UnityMain", 22, sys_tid, "Native", "S", utm, 0, _il2cpp_frame())  # noqa: E731
    samples = [block(1, 1) + block(2, 1), block(1, 5) + block(2, 90), block(1, 6) + block(2, 200)]

    result = analyze_session(_session(samples), CFG)

    assert result.main_threads[0].sys_tid == 2  # CPU が多い方
    assert result.main_ambiguous
    assert "曖昧" in result.main_note
    assert any("曖昧" in w for w in result.warnings)


def test_html_shows_the_ambiguity_note_and_the_candidate_table():
    block = lambda sys_tid, utm: thread_block("UnityMain", 22, sys_tid, "Native", "S", utm, 0, _il2cpp_frame())  # noqa: E731
    session = _session([block(1, 1) + block(2, 1), block(1, 5) + block(2, 90), block(1, 6) + block(2, 200)])

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert "(曖昧)" in html
    assert "<th>出現サンプル</th>" in html
    assert "UnityMain (tid 2, 採用)" in html and "UnityMain (tid 1, 候補 (不採用))" in html


def test_origin_is_not_taken_from_a_thread_missing_in_the_latest_sample():
    samples = [_main(10), _main(40), thread_block("Other", 5, 77, "Native", "S", 1, 1, _il2cpp_frame())]

    result = analyze_session(_session(samples), CFG)

    assert result.origin is None
    assert "最新のサンプルに主スレッドが存在しない" in result.origin_note
    assert result.reached == []


def test_single_main_thread_has_no_selection_note():
    result = analyze_session(_session([_main(1), _main(2), _main(3)]), CFG)

    assert result.main_note == ""
    assert not result.main_ambiguous


def test_html_shows_main_candidates_and_marks_unattached_threads():
    samples = [_main(10) + "\n" + _detached("UnityMain", 30548), _main(40) + "\n" + _detached("UnityMain", 30548), _main(90)]
    session = _session(samples)

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert "未登録" in html
    assert "採用" in html
    assert "ART未登録" in html


# ---- 工程 11: IL2CPP を観測したサンプル数 ----


def test_main_observation_counts_il2cpp_and_app_samples(tmp_path):
    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), FakeResolver(), ["libil2cpp.so"])

    result = analyze_session(session, CFG)

    assert result.main_observation == {"total": 3, "with_stack": 3, "il2cpp": 3, "app": 3, "unidentified_library": 0}
    text = describe_main_observation(result.main_observation)
    assert "3/3" in text and "稼働率や停止確率ではありません" in text


def test_main_observation_does_not_count_unidentified_libraries_as_il2cpp_absence():
    session = _session([_main(1, [APK_UNNAMED_LINE]), _main(2, [APK_UNNAMED_LINE]), _main(3, [APK_UNNAMED_LINE])])

    result = analyze_session(session, CFG)

    assert result.main_observation["il2cpp"] == 0
    assert result.main_observation["unidentified_library"] == 3
    assert "判定できません" in describe_main_observation(result.main_observation)


def test_main_observation_is_zero_for_a_thread_without_il2cpp():
    frames = [native(0, 0x9A1B4, LIBC_PATH, "syscall+28", LIBC_BUILD_ID)]

    result = analyze_session(_session([_main(1, frames), _main(2, frames), _main(3, frames)]), CFG)

    assert result.main_observation == {"total": 3, "with_stack": 3, "il2cpp": 0, "app": 0, "unidentified_library": 0}


def test_observation_line_appears_in_html_and_markdown(tmp_path):
    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), FakeResolver(), ["libil2cpp.so"])
    result = analyze_session(session, CFG)

    assert "主スレッドで IL2CPP を観測したサンプル: 3/3" in render_html(session, result, CFG.app_assemblies)
    assert "主スレッドで IL2CPP を観測したサンプル: 3/3" in render_report(session, result)


# ---- 工程 8a: インライン展開の表示 ----


def test_html_shows_inlined_helpers_as_a_supplement_and_escapes_them(tmp_path):
    class InlineResolver:
        def resolve(self, symbol_file, addresses):
            gen = "C:/b/il2cppOutput/Contoso.App.Presentation__1.cpp"
            return {a: ResolvedSymbol("SettingsManager_OnModeChanged_m" + "AB" * 20, gen, ("Helper<int>::Invoke(int)",)) for a in addresses}

    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), InlineResolver(), ["libil2cpp.so"])

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert "インライン展開: Helper&lt;int&gt;::Invoke" in html
    assert "Helper<int>" not in html
    assert analyze_session(session, CFG).origin["function"] == "SettingsManager_OnModeChanged"


# ---- 工程 12: 所要時間 ----


def test_capture_records_per_step_timings_with_a_monotonic_clock(tmp_path):
    ticks = iter(i * 0.5 for i in range(10_000))

    session = run_capture(
        FakeAdb(stuck_trace(3)), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None, clock=lambda: next(ticks)
    )

    for snapshot in session.proc_snapshots:
        assert set(snapshot.timings) == {"top", "stat", "wchan", "meminfo", "sigquit", "sample_total"}
        assert snapshot.timings["top"] == 0.5
        assert snapshot.timings["sample_total"] > snapshot.timings["sigquit"]
    assert session.to_dict()["schema_version"] == 4


def test_capture_keeps_the_snapshot_and_timings_when_stat_is_empty(tmp_path):
    class NoStatAdb(FakeAdb):
        def shell(self, command, timeout=60, check=True):
            if command.endswith("/stat'"):
                self.commands.append(command)
                return ""
            return super().shell(command, timeout, check)

    session = run_capture(NoStatAdb(stuck_trace(3)), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)

    assert len(session.proc_snapshots) == 3
    assert all(s.threads == [] and "stat" in s.timings for s in session.proc_snapshots)
    assert any("thread stat を取得できませんでした" in w for w in session.warnings)


def test_html_shows_not_measured_for_snapshots_without_timings():
    session = make_session(stuck_trace(3))
    session.proc_snapshots = [
        ProcSnapshot(0, "2026-09-24T20:30:34+09:00", [], {}, {}, {"top": 0.5, "stat": 1.25, "sample_total": 9.0}),
        ProcSnapshot(1, "2026-09-24T20:30:36+09:00", [], {}, {}),
    ]

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert "取得の所要時間" in html
    assert "1.25" in html
    assert html.count("未計測") >= 4  # 取得回 2 の全項目と、取得回 1 の欠けた項目


def test_capture_records_phase_seconds_and_rebuild_keeps_them(tmp_path):
    ticks = iter(i * 0.5 for i in range(10_000))

    session = run_capture(
        FakeAdb(stuck_trace(3)), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None, clock=lambda: next(ticks)
    )

    phases = session.capture["phase_sec"]
    assert list(phases) == ["prepare", "device_info", "sampling", "bugreport", "parse"]
    assert all(value > 0 for value in phases.values())
    assert phases["sampling"] > phases["prepare"]  # 3 サンプル分の時計の読み取りが入る
    saved = json.loads((tmp_path / "s" / "session.json").read_text(encoding="utf-8"))
    assert saved["capture"]["phase_sec"] == phases
    assert rebuild_session(tmp_path / "s", 30).capture["phase_sec"] == phases


# ---- 工程 12: スキーマ互換 ----


@pytest.mark.parametrize("version", [1, 2, 3])
def test_older_schema_versions_still_load_without_timings_and_inlined(tmp_path, version):
    session = symbolize_session(make_session(stuck_trace(2)), make_store(tmp_path), FakeResolver(), ["libil2cpp.so"])
    session.proc_snapshots = [ProcSnapshot(0, "2026-09-24T20:30:34+09:00", [], {}, {}, {"top": 1.0})]
    data = json.loads(json.dumps(session.to_dict()))
    data["schema_version"] = version
    for snapshot in data["proc_snapshots"]:
        del snapshot["timings"]
    for sample in data["samples"]:
        for thread in sample["threads"]:
            for frame in thread["frames"]:
                del frame["inlined"]

    loaded = Session.from_dict(data)

    assert loaded.proc_snapshots[0].timings == {}
    assert loaded.samples[0].threads[1].frames[1].inlined == []
    assert loaded.samples[0].threads[1].frames[1].resolved == "ResourceManager_Update"


def test_unsupported_schema_version_is_rejected():
    with pytest.raises(ValueError):
        Session.from_dict({"schema_version": 99})


# ---- 工程 8: 読めない見出しの警告 ----


def test_capture_warns_when_a_thread_header_cannot_be_read(tmp_path):
    trace = stuck_trace(3).replace('"Worker" prio=5 tid=15 Waiting', '"Worker" prio=5 weird-new-format')

    session = run_capture(FakeAdb(trace), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)

    warnings = [w for w in session.warnings if "読めないスレッド見出し" in w]
    assert len(warnings) == 3
    assert "weird-new-format" in warnings[0]
    assert all(t.name != "Worker" for t in session.samples[0].threads)


def test_rebuild_also_warns_about_unreadable_thread_headers(tmp_path):
    trace = stuck_trace(3).replace('"Worker" prio=5 tid=15 Waiting', '"Worker" prio=5 weird-new-format')
    run_capture(FakeAdb(trace), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)

    rebuilt = rebuild_session(tmp_path / "s", 30)

    assert sum("読めないスレッド見出し" in w for w in rebuilt.warnings) == 3


# ---- レビュー修正: 候補の扱いと取得時間の表 ----


def test_rules_run_only_on_the_selected_main_thread():
    waiting = [native(i, 0x100 + i, LIBC_PATH, "pthread_cond_wait+10", LIBC_BUILD_ID) for i in range(6)]

    def quiet(utm: int, pc: int) -> str:
        return thread_block("UnityMain", 22, 1, "Native", "S", utm, 0, _il2cpp_frame(pc))

    def waiter(utm: int) -> str:
        return thread_block("UnityMain", 23, 2, "Native", "S", utm, 0, waiting)

    samples = [quiet(1, 0x100) + waiter(1), quiet(50, 0x110) + waiter(2), quiet(99, 0x120) + waiter(3)]

    result = analyze_session(_session(samples), CFG)

    assert result.main_threads[0].sys_tid == 1 and result.main_ambiguous
    assert result.main_threads[1].stuck  # 不採用の候補は待機で固まって見えるが、所見には混ぜない
    assert result.findings == []


def test_path_tab_labels_selected_and_unselected_candidates_and_flags_stale_ones():
    samples = [_main(10) + "\n" + _detached("UnityMain", 30548), _main(40) + "\n" + _detached("UnityMain", 30548), _main(90)]
    session = _session(samples)

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert "UnityMain (tid 28742, 採用)" in html
    assert "UnityMain (tid 30548, 候補 (不採用))" in html
    assert "最新のサンプルに存在しません" in html


def test_timing_tables_are_separate_so_unmatched_counts_do_not_misalign():
    session = make_session(stuck_trace(3))  # ART トレースは 3 件
    session.proc_snapshots = [
        ProcSnapshot(i, f"2026-09-24T20:30:3{i}+09:00", [], {}, {}, {"top": 0.5, "sample_total": 8.0}) for i in range(5)
    ]

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert "取得の所要時間 (送信順)" in html and "ART トレースの時刻と間隔" in html
    assert all(f"2026-09-24T20:30:3{i}+09:00" in html for i in range(5))  # 送信 5 回分すべてが残る
    assert "待ち時間を含む" in html


def test_wait_note_does_not_claim_the_innermost_frame():
    frames = [
        native(0, 0x1, LIBC_PATH, "syscall+28", LIBC_BUILD_ID),
        native(1, 0x2, LIBC_PATH, "pthread_cond_wait+10", LIBC_BUILD_ID),
    ]

    note = analyze_session(_session([_main(1, frames), _main(2, frames), _main(3, frames)]), CFG).origin_note

    assert "スタック内に待機呼び出し (pthread_cond_wait)" in note
    assert "最も内側" not in note
