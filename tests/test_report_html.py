from __future__ import annotations

import re

import pytest

from helpers import FakeResolver, make_session, make_store, stuck_trace
from uaal_analyzer.analyze.engine import analyze_session
from uaal_analyzer.config import Config
from uaal_analyzer.model import ProcSnapshot
from uaal_analyzer.report.html import render_html
from uaal_analyzer.report.markdown import render_report
from uaal_analyzer.symbolize.symbolizer import symbolize_session

CFG = Config(app_assemblies=["Contoso.*"])


def _symbolized(tmp_path):
    return symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), FakeResolver(), ["libil2cpp.so"])


def _with_extras(session):
    session.logs = {
        "logs": [
            {"time": "10-08 16:46:50.200", "pid": 1, "tid": 1, "level": "E", "tag": "T<ag>", "message": "<script>alert(1)</script> & x"},
        ],
        "log_total": 1,
        "log_range": {"first": "a", "last": "b"},
        "unity_log_count": 0,
        "kernel_lines": ["lowmemorykiller <x>"],
        "system_meminfo": {"MemTotal": 1},
    }
    session.device = {
        "props": {"ro.product.model": "<M>"},
        "package": {"versionName": "1.0"},
        "window": {"mCurrentFocus": "Window{a}"},
        "power": {"mWakefulness": "Asleep", "displayState": "OFF"},
        "layers": ["pkg/.Main#1"],
        "process": {"curAdj": "0"},
    }
    session.proc_snapshots = [
        ProcSnapshot(0, "2026-09-24T20:30:34+09:00", [], {"1": "futex_wait", "2": ""}, {"total_pss": 100, "java_heap_pss": 5}),
        ProcSnapshot(1, "2026-09-24T20:30:36+09:00", [], {"1": "futex_wait"}, {"total_pss": 120}),
    ]
    return session


def test_origin_uses_latest_path_and_does_not_depend_on_stuck(tmp_path):
    session = _symbolized(tmp_path)
    session.samples = session.samples[:1]  # 1 件だけでも到達点は分かる

    result = analyze_session(session, CFG)

    assert not result.main_threads[0].stuck
    assert result.origin["function"] == "SettingsManager_OnModeChanged"
    assert result.reached == ["BasePanel_TryLoadAsync", "SettingsManager_OnModeChanged"]
    assert result.origin_note == ""


def test_origin_note_explains_missing_symbols(tmp_path):
    result = analyze_session(make_session(stuck_trace(3)), CFG)

    assert result.origin is None
    assert "IL2CPP のフレームはあるが生成元ファイルを解決できていません" in result.origin_note
    assert result.reached == []


def _main_thread_session(frame_lines, device=None):
    from helpers import PACKAGE, PID, anr_section, thread_block

    text = "".join(
        anr_section(PID, f"2026-09-24 20:30:{35 + 2 * k:02d}.0+0900", PACKAGE, thread_block("UnityMain", 12, 8620, "Native", "S", 5, 5, frame_lines))
        for k in range(3)
    )
    session = make_session(text)
    session.device = device or {}
    return session


def test_origin_note_says_app_code_is_not_running_when_stack_has_no_il2cpp():
    from helpers import LIBC_BUILD_ID, LIBC_PATH, UNITY_BUILD_ID, UNITY_PATH, native

    frames = [
        native(0, 0x9A1B4, LIBC_PATH, "syscall+28", LIBC_BUILD_ID),
        native(1, 0x100, LIBC_PATH, "pthread_cond_wait+10", LIBC_BUILD_ID),
        native(2, 0x100, UNITY_PATH, None, UNITY_BUILD_ID),
    ]

    result = analyze_session(_main_thread_session(frames), CFG)

    assert result.origin is None
    assert "IL2CPP のフレームは見つかりませんでした" in result.origin_note
    assert "正常に動いていても起こり得ます" in result.origin_note
    assert "待機呼び出し (pthread_cond_wait)" in result.origin_note  # 根拠があるときだけ待機に言及
    assert "シンボル" not in result.origin_note
    assert "画面の状態" not in result.origin_note  # 未取得のときは触れない


def test_origin_note_does_not_claim_waiting_without_a_wait_call():
    from helpers import LIBC_BUILD_ID, LIBC_PATH, native

    frames = [native(0, 0x9A1B4, LIBC_PATH, "syscall+28", LIBC_BUILD_ID)]

    note = analyze_session(_main_thread_session(frames), CFG).origin_note

    assert "IL2CPP のフレームは見つかりませんでした" in note
    assert "待機呼び出し" not in note


@pytest.mark.parametrize(
    "wakefulness,expected",
    [("Asleep", "スリープ中"), ("Dozing", "スリープ中"), ("Awake", "画面の状態: Awake。")],
)
def test_origin_note_appends_screen_state_when_known(wakefulness, expected):
    from helpers import LIBC_BUILD_ID, LIBC_PATH, native

    frames = [native(0, 0x9A1B4, LIBC_PATH, "syscall+28", LIBC_BUILD_ID)]
    device = {"power": {"mWakefulness": wakefulness}}

    note = analyze_session(_main_thread_session(frames, device), CFG).origin_note

    assert expected in note
    assert ("可能性" in note) == (wakefulness != "Awake")


def test_origin_note_is_not_conclusive_when_an_unnamed_library_is_on_the_path():
    from helpers import APK_UNNAMED_LINE

    result = analyze_session(_main_thread_session([APK_UNNAMED_LINE], {"power": {"mWakefulness": "Asleep"}}), CFG)

    assert result.origin is None
    assert "断定できません" in result.origin_note
    assert "スリープ中" in result.origin_note


def test_origin_note_explains_missing_app_frames(tmp_path):
    result = analyze_session(_symbolized(tmp_path), Config(app_assemblies=["Other.*"]))

    assert result.origin is None
    assert "自社アセンブリ" in result.origin_note


def test_observation_is_reference_not_a_verdict(tmp_path):
    result = analyze_session(_symbolized(tmp_path), CFG)

    assert "同じ経路" in result.observation
    assert result.verdict == result.observation
    assert "停止し" not in result.observation


def test_thread_table_lists_main_first_then_by_cpu(tmp_path):
    result = analyze_session(_symbolized(tmp_path), CFG)

    names = [row["name"] for row in result.thread_table]
    assert names[0] == "UnityMain"
    assert result.thread_table[0]["is_main"] is True
    assert result.thread_table[0]["innermost"]


def test_memory_series_comes_from_snapshots(tmp_path):
    session = _with_extras(_symbolized(tmp_path))

    result = analyze_session(session, CFG)

    assert [m["total_pss"] for m in result.memory] == [100, 120]


def test_html_has_seven_tabs_and_is_self_contained(tmp_path):
    session = _with_extras(_symbolized(tmp_path))

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert len(re.findall(r"<button data-tab=", html)) == 7
    assert len(re.findall(r'<section class="tab', html)) == 7
    assert "http://" not in html and "https://" not in html
    assert "<link" not in html and "src=" not in html
    assert "SettingsManager_OnModeChanged" in html
    assert "f app" in html  # 自社メソッドの強調


def test_html_escapes_untrusted_text_from_logs_and_device(tmp_path):
    session = _with_extras(_symbolized(tmp_path))

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt; &amp; x" in html
    assert "T&lt;ag&gt;" in html
    assert "&lt;M&gt;" in html
    assert "lowmemorykiller &lt;x&gt;" in html
    assert html.count("<script>") == 1  # タブ切り替えの正規のスクリプトだけ


def test_html_escapes_frame_names_and_warnings(tmp_path):
    session = _symbolized(tmp_path)
    session.warnings.append("<img src=x onerror=alert(1)>")

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_html_shows_notice_when_logs_and_device_are_missing(tmp_path):
    session = make_session(stuck_trace(3))  # シンボル解決も端末情報もログも無い

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert "ログは取得されていません" in html
    assert "端末・ビルドの情報は取得されていません" in html
    assert "プロセス・画面の情報は取得されていません" in html


def test_html_shows_origin_unknown_reason(tmp_path):
    session = make_session(stuck_trace(3))

    html = render_html(session, analyze_session(session, CFG), CFG.app_assemblies)

    assert "自社メソッドを判定できません" in html
    assert "生成元ファイルを解決できていません" in html


def test_markdown_is_a_short_summary_with_logs_and_pointer_to_html(tmp_path):
    session = _with_extras(_symbolized(tmp_path))

    text = render_report(session, analyze_session(session, CFG))

    assert "## 最後に到達した自社メソッド" in text
    assert "SettingsManager_OnModeChanged (Contoso.App.Presentation" in text
    assert "## 参考: 観測結果" in text
    assert "## 直近のログ" in text
    assert "report.html" in text
    assert "停止判定" not in text
    assert text.count("\n") < 60
