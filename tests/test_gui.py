from __future__ import annotations

import queue
import sys
from datetime import datetime
from pathlib import Path

import pytest

from uaal_analyzer import gui
from uaal_analyzer.gui import (
    PHASES_INIT,
    PHASES_RUN,
    CommandRunner,
    ProgressTracker,
    build_init_command,
    build_run_command,
    cli_python,
    default_session_name,
    format_duration,
    format_progress_summary,
    format_row,
    is_existing_config_error,
    load_phase_weights,
    parse_devices,
    parse_progress_line,
    parse_summary,
    validate_session_name,
)

RUN_OUTPUT = [
    "対象のアプリを自動で検出します",
    "対象: com.example.app pid=4111 (検出方法: foreground)",
    "対象: com.example.app pid=4111",
    "SIGQUIT 送信 1/5",
    "bugreport を取得中 (数分かかることがあります)",
    "最後に到達した自社メソッド: SettingsManager_OnModeChanged (Contoso.App.Presentation)",
    "観測結果 (参考): 全 5 サンプルで同じ経路 (共通フレーム 63 件) にあり、CPU を消費し続けています (空回りの可能性)。",
    "[wait-for-completion] 主スレッドで Addressables の WaitForCompletion が停止経路に残っている",
    "警告: base.apk@420c000: BuildId ab12cd34 に一致するシンボルが保管庫にありません",
    "レポート: C:\\tool\\data\\sessions\\x\\report.html",
    "所要時間: 準備 1.2秒 / サンプル取得 39.3秒 / 合計 138.0秒",
]

INIT_OUTPUT = [
    "設定ファイルを作りました: C:\\tool\\configs\\com.game.app.toml",
    "自社アセンブリ (3 件):",
    "  - Game.Core",
    "  - Game.Debug",
    "  - Assembly-CSharp",
    "シンボルの場所 (1 件):",
    "  - C:/proj/androidBuild/unityLibrary/symbols",
    "NDK: C:/ndk/bin",
    "注意: Unity 6000.3.10f1 の Variations フォルダが標準の場所に見つかりません",
]


def test_default_session_name_is_a_timestamp():
    assert default_session_name(datetime(2026, 10, 9, 15, 30, 5)) == "20261009-153005"


@pytest.mark.parametrize("name", ["", "  ", "a/b", "a\\b", "..", "."])
def test_session_names_with_path_parts_or_blank_are_rejected(name):
    assert validate_session_name(name)


def test_plain_session_names_are_accepted():
    assert validate_session_name("timing-check-20261009") is None


def test_cli_python_replaces_pythonw_with_the_console_python(tmp_path):
    (tmp_path / "python.exe").write_bytes(b"")
    (tmp_path / "pythonw.exe").write_bytes(b"")

    assert cli_python(str(tmp_path / "pythonw.exe")) == str(tmp_path / "python.exe")
    assert cli_python(str(tmp_path / "python.exe")) == str(tmp_path / "python.exe")
    lonely = tmp_path / "sub" / "pythonw.exe"
    assert cli_python(str(lonely)) == str(lonely)  # python.exe が無ければそのまま


def test_run_command_passes_only_the_options_that_were_filled_in():
    assert build_run_command("py", "s1") == ["py", "-m", "uaal_analyzer", "run", "--session-name", "s1"]
    assert build_run_command("py", "s1", "com.a.b", "ABC") == [
        "py", "-m", "uaal_analyzer", "run", "--session-name", "s1", "--package", "com.a.b", "--serial", "ABC",
    ]


def test_init_command_adds_force_only_when_asked():
    assert build_init_command("py", "C:/proj") == ["py", "-m", "uaal_analyzer", "init", "--project", "C:/proj"]
    assert build_init_command("py", "C:/proj", "com.a.b", force=True)[-3:] == ["--package", "com.a.b", "--force"]
    assert "--force" in build_init_command("py", "C:/proj", force=True)


def test_parse_devices_keeps_only_connected_devices():
    text = (
        "* daemon not running; starting now at tcp:5037\n"
        "* daemon started successfully\n"
        "List of devices attached\n"
        "1bc92747\tdevice\n"
        "emulator-5554\toffline\n"
        "ZZZ\tunauthorized\n"
        "\n"
    )

    assert parse_devices(text) == ["1bc92747"]
    assert parse_devices("List of devices attached\n") == []


def test_existing_config_error_is_recognised():
    assert is_existing_config_error(["エラー: 設定ファイルが既にあります: C:\\x.toml (上書きするには --force を付けてください)"])
    assert not is_existing_config_error(["エラー: セッションが見つかりません: s"])


def test_parse_summary_extracts_the_points_of_a_run():
    summary = parse_summary(RUN_OUTPUT)

    assert summary.target == "com.example.app pid=4111 (検出方法: foreground)"  # 最初の「対象:」だけ
    assert summary.origin.startswith("最後に到達した自社メソッド: SettingsManager_OnModeChanged")
    assert "共通フレーム 63 件" in summary.observation
    assert summary.findings == ["[wait-for-completion] 主スレッドで Addressables の WaitForCompletion が停止経路に残っている"]
    assert summary.warnings == ["base.apk@420c000: BuildId ab12cd34 に一致するシンボルが保管庫にありません"]
    assert summary.timing.startswith("準備 1.2秒")
    assert summary.report == "C:\\tool\\data\\sessions\\x\\report.html"  # ドライブの ':' を壊さない


def test_parse_summary_keeps_the_reason_when_the_origin_is_unknown():
    summary = parse_summary(["自社メソッドを判定できません: 最新サンプルの主スレッドのスタックに、IL2CPP のフレームは見つかりませんでした。"])

    assert summary.origin.startswith("自社メソッドを判定できません")


def test_parse_summary_of_an_init_run_lists_assemblies_and_notes():
    summary = parse_summary(INIT_OUTPUT)

    assert summary.config_path == "C:\\tool\\configs\\com.game.app.toml"
    assert summary.assemblies == ["Game.Core", "Game.Debug", "Assembly-CSharp"]  # シンボルの場所は含めない
    assert summary.warnings == ["Unity 6000.3.10f1 の Variations フォルダが標準の場所に見つかりません"]


def test_parse_summary_of_unrelated_output_is_empty():
    summary = parse_summary(["SIGQUIT 送信 1/5", "エラー: セッションが見つかりません"])

    assert (summary.target, summary.origin, summary.report, summary.findings) == ("", "", "", [])


def _drain(events: queue.Queue, timeout: float = 20.0) -> list[tuple[str, object]]:
    items = []
    while True:
        item = events.get(timeout=timeout)
        items.append(item)
        if item[0] == "done":
            return items


def test_command_runner_streams_utf8_lines_then_reports_the_exit_code():
    events: queue.Queue = queue.Queue()
    code = "import sys; print('日本語 1', flush=True); print('line 2', file=sys.stderr, flush=True); sys.exit(3)"

    CommandRunner([sys.executable, "-c", code], events).start()

    items = _drain(events)
    assert items[-1] == ("done", 3)
    assert [p for k, p in items if k == "line"] == ["日本語 1", "line 2"]  # 標準エラーも同じ流れに入る


def test_command_runner_reports_a_command_that_cannot_start():
    events: queue.Queue = queue.Queue()

    CommandRunner(["definitely-not-a-command-xyz"], events).start()

    items = _drain(events)
    assert items[-1] == ("done", -1)
    assert items[0][1].startswith("エラー: コマンドを起動できません")


def test_command_runner_stop_ends_a_long_running_command():
    events: queue.Queue = queue.Queue()
    runner = CommandRunner([sys.executable, "-c", "import time; print('started', flush=True); time.sleep(60)"], events)
    runner.start()
    assert events.get(timeout=20) == ("line", "started")

    runner.stop()

    items = _drain(events)
    assert items[-1][0] == "done" and items[-1][1] != 0
    assert ("line", "エラー: 中断しました") in items


def test_command_runner_delivers_a_line_without_waiting_for_the_child_to_flush_or_exit():
    events: queue.Queue = queue.Queue()
    code = "import time; print('first'); time.sleep(20); print('second')"  # flush しない子プロセス
    runner = CommandRunner([sys.executable, "-c", code], events)

    runner.start()

    assert events.get(timeout=10) == ("line", "first")  # 終了 (20 秒後) より前に届く
    runner.stop()
    _drain(events)


# ---- 画面の部品 (画面を作れない環境では読み飛ばす) ----


class _FlakyTk:
    class TclError(Exception):
        pass

    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.calls = 0

    def Tk(self):  # noqa: N802
        self.calls += 1
        if self.calls <= self.failures:
            raise self.TclError("Can't find a usable tk.tcl")
        return "root"


def test_create_root_retries_a_sporadic_tk_failure():
    waits: list[float] = []
    fake = _FlakyTk(failures=2)

    assert gui.create_root(fake, attempts=5, wait=0.3, sleep=waits.append) == "root"
    assert fake.calls == 3 and waits == [0.3, 0.3]


def test_create_root_gives_up_after_the_last_attempt():
    fake = _FlakyTk(failures=99)

    with pytest.raises(_FlakyTk.TclError):
        gui.create_root(fake, attempts=3, wait=0, sleep=lambda s: None)
    assert fake.calls == 3


class _FakeRunner:
    started: list[list[str]] = []

    def __init__(self, command, events):
        self.command = list(command)
        _FakeRunner.started.append(self.command)

    def start(self):
        pass

    running = False


class _FakeBox:
    def __init__(self, answer=True):
        self.answer = answer
        self.errors: list[tuple[str, str]] = []

    def askyesno(self, title, message):
        return self.answer

    def showerror(self, title, message):
        self.errors.append((title, message))


@pytest.fixture
def app(monkeypatch):
    import tkinter

    try:
        root = gui.create_root(tkinter, attempts=10, wait=0.2)
    except tkinter.TclError as exc:
        pytest.skip(f"画面を作れません: {exc}")
    root.withdraw()
    monkeypatch.setattr(gui, "read_devices", lambda adb="adb": (["ABC"], ""))
    monkeypatch.setattr(gui, "load_phase_weights", lambda sessions_dir: {})
    monkeypatch.setattr(gui, "CommandRunner", _FakeRunner)
    _FakeRunner.started = []
    instance = gui.GuiApp(root)
    # 起動直後の端末確認・目安時間の読み込みの結果を先に受け取り、テストで流すイベントと順序が入れ替わらないようにする。
    seen = {}
    while len(seen) < 2:
        kind, payload = instance._events.get(timeout=10)
        seen[kind] = payload
    assert set(seen) == {"devices", "weights"}
    instance._show_devices(*seen["devices"])
    instance._messagebox = _FakeBox()
    yield instance
    root.destroy()


def _feed(app, *events):
    for event in events:
        app._events.put(event)
    app._poll()


def test_gui_shows_connected_devices_and_passes_a_serial_only_for_several(app):
    _feed(app, ("devices", (["ABC"], "")))
    assert app._device_note.get() == "接続中" and app._serial() == ""

    _feed(app, ("devices", (["ABC", "DEF"], "")))
    app._device_var.set("DEF")
    assert "2 台" in app._device_note.get() and app._serial() == "DEF"

    _feed(app, ("devices", ([], "")))
    assert "未接続" in app._device_note.get() and app._serial() == ""


def test_gui_rejects_a_bad_session_name_without_starting_anything(app):
    app._session_var.set("a/b")

    app.start_run()

    assert app._messagebox.errors and _FakeRunner.started == []


def test_gui_run_shows_the_summary_and_opens_the_report(app, tmp_path, monkeypatch):
    report = tmp_path / "report.html"
    report.write_text("<html></html>", encoding="utf-8")
    opened: list[str] = []
    monkeypatch.setattr(gui.webbrowser, "open", lambda url: opened.append(url))
    app._session_var.set("s1")
    app._package_var.set("com.a.b")

    app.start_run()
    command = _FakeRunner.started[0]
    assert command[-4:] == ["--session-name", "s1", "--package", "com.a.b"]  # 端末が1台のときは --serial を付けない
    assert app._status_var.get() == "実行中..."
    lines = [l for l in RUN_OUTPUT if not l.startswith("レポート:")] + [f"レポート: {report}"]
    _feed(app, *[("line", l) for l in lines], ("done", 0))

    summary = app._summary_text.get("1.0", "end")
    assert "到達点: 最後に到達した自社メソッド: SettingsManager_OnModeChanged" in summary
    assert "危険パターン: [wait-for-completion]" in summary and "所要時間: 準備 1.2秒" in summary
    assert app._status_var.get() == "完了"
    assert opened == [report.as_uri()]
    assert str(app._open_button.cget("state")) == "normal"


def test_gui_run_failure_is_shown_in_red_and_does_not_open_the_report(app, monkeypatch):
    opened: list[str] = []
    monkeypatch.setattr(gui.webbrowser, "open", lambda url: opened.append(url))
    app.start_run()

    _feed(app, ("line", "エラー: Unity のアプリを見つけられませんでした"), ("done", 1))

    assert app._status_var.get() == "失敗しました (終了コード 1)"
    assert opened == []
    assert app._progress.tag_ranges("error")


def test_gui_init_asks_before_overwriting_and_reruns_with_force(app):
    app._project_var.set("C:/proj")
    app._package_var.set("com.a.b")
    app.start_init()
    assert "--force" not in _FakeRunner.started[0]

    _feed(app, ("line", "エラー: 設定ファイルが既にあります: x (上書きするには --force を付けてください)"), ("done", 1))

    assert "--force" in _FakeRunner.started[1] and "--package" in _FakeRunner.started[1]
    assert app._status_var.get() == "実行中..."


def test_gui_init_declined_overwrite_reports_the_failure(app):
    app._project_var.set("C:/proj")
    app.start_init()
    app._messagebox.answer = False

    _feed(app, ("line", "エラー: 設定ファイルが既にあります: x"), ("done", 1))

    assert len(_FakeRunner.started) == 1
    assert app._status_var.get().startswith("失敗しました")


def test_gui_init_success_lists_the_assemblies(app):
    app._project_var.set("C:/proj")
    app.start_init()

    _feed(app, *[("line", l) for l in INIT_OUTPUT], ("done", 0))

    summary = app._summary_text.get("1.0", "end")
    assert "Game.Core, Game.Debug, Assembly-CSharp" in summary and "注意:" in summary
    assert app._status_var.get() == "完了"


def test_gui_init_requires_a_project_folder(app):
    app.start_init()

    assert app._messagebox.errors and _FakeRunner.started == []


def test_gui_progress_panel_follows_progress_lines_and_completes(app):
    app.start_run()
    assert app._phase_labels[0].cget("text").startswith("▶ 準備")

    _feed(app, ("line", "進捗: 準備"), ("line", "進捗: 端末情報"), ("line", "進捗: サンプル取得 3/5"))

    assert app._phase_labels[0].cget("text").startswith("✔ 準備")
    assert "▶ サンプル取得" in app._phase_labels[2].cget("text") and "3/5" in app._phase_labels[2].cget("text")
    assert 0 < float(app._bar["value"]) < 100
    assert "残り" in app._progress_var.get()

    _feed(app, ("done", 0))

    assert all(label.cget("text").startswith("✔") for label in app._phase_labels)
    assert float(app._bar["value"]) == 100 and app._progress_var.get().startswith("100%")


def test_gui_progress_panel_marks_the_failed_phase_and_shows_only_init_phases_for_init(app):
    app.start_run()
    _feed(app, ("line", "進捗: 準備"), ("line", "進捗: bugreport 40%"), ("done", 1))

    assert app._phase_labels[3].cget("text").startswith("✖ bugreport")
    assert float(app._bar["value"]) < 100

    app._project_var.set("C:/proj")
    app.start_init()

    texts = [label.cget("text") for label in app._phase_labels]
    assert texts[0].startswith("▶ 準備") and texts[1].endswith("") and "設定ファイル作成" in texts[1]
    assert texts[2:] == [""] * 5


def test_gui_uses_weights_loaded_in_the_background(app):
    _feed(app, ("weights", {"bugreport": 10.0}))

    assert app._weights == {"bugreport": 10.0}


# ---- 進捗 (画面に依存しない部分) ----

WEIGHTS = {"prepare": 1, "device_info": 2, "sampling": 40, "bugreport": 94, "parse": 1, "symbolize": 2, "report": 1}


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _tracker(phases=PHASES_RUN):
    clock = _Clock()
    return ProgressTracker(phases, WEIGHTS, clock), clock


@pytest.mark.parametrize(
    "line, expected",
    [
        ("進捗: 準備", ("prepare", None, None, None, None)),
        ("進捗: サンプル取得 3/5", ("sampling", 3, 5, None, None)),
        ("進捗: bugreport 45%", ("bugreport", None, None, 45, None)),
        ("進捗: bugreport 経過 30秒", ("bugreport", None, None, None, 30)),
        ("進捗: 設定ファイル作成", ("setup", None, None, None, None)),
    ],
)
def test_parse_progress_line(line, expected):
    event = parse_progress_line(line)

    assert (event.phase, event.done, event.total, event.percent, event.elapsed) == expected


@pytest.mark.parametrize("line", ["SIGQUIT 送信 1/5", "進捗: 知らない工程 1/2", "進捗:", "", "警告: 進捗: 準備"])
def test_parse_progress_line_ignores_other_lines(line):
    assert parse_progress_line(line) is None


def test_tracker_starts_with_the_first_phase_running():
    tracker, _ = _tracker()

    view = tracker.view()

    assert [row.state for row in view.rows] == ["running"] + ["pending"] * 6
    assert view.percent == 0 and view.remaining == 141 and not view.finished


def test_tracker_uses_the_sample_count_for_percent_and_remaining_time():
    tracker, clock = _tracker()
    clock.now = 0
    tracker.feed("進捗: 準備")
    clock.now = 1
    tracker.feed("進捗: 端末情報")
    clock.now = 3
    tracker.feed("進捗: サンプル取得 0/5")
    clock.now = 20
    assert tracker.feed("進捗: サンプル取得 3/5")

    view = tracker.view()

    assert [row.state for row in view.rows[:4]] == ["done", "done", "running", "pending"]
    assert view.rows[0].seconds == 1 and view.rows[1].seconds == 2
    assert "3/5" in view.rows[2].detail and "経過 17秒 / 目安 40秒" in view.rows[2].detail
    assert view.percent == 19  # (1 + 2 + 40 * 0.6) / 141
    assert view.remaining == pytest.approx(141 - 27)
    assert view.elapsed == 20


def test_tracker_uses_the_bugreport_percent_and_skipped_phases_count_as_done():
    tracker, clock = _tracker()
    clock.now = 60
    tracker.feed("進捗: bugreport 50%")

    view = tracker.view()

    assert [row.state for row in view.rows[:4]] == ["done", "done", "done", "running"]
    assert view.percent == int(100 * (43 + 47) / 141)
    assert "50%" in view.rows[3].detail


def test_tracker_estimates_by_elapsed_time_when_no_detail_and_caps_before_the_end():
    tracker, clock = _tracker()
    tracker.feed("進捗: bugreport")
    clock.now = 10_000

    view = tracker.view()

    assert view.percent < 100 and view.remaining is not None and view.remaining > 0
    assert view.percent == int(100 * (43 + 94 * 0.95) / 141)


def test_tracker_ignores_going_back_and_unknown_phases():
    tracker, _ = _tracker()
    tracker.feed("進捗: bugreport 10%")

    assert tracker.feed("進捗: 準備") is False
    assert tracker.feed("進捗: 設定ファイル作成") is False
    assert tracker.feed("SIGQUIT 送信 1/5") is False
    assert tracker.view().rows[3].state == "running"


def test_tracker_keeps_the_percent_when_a_repeated_line_has_no_detail():
    tracker, _ = _tracker()
    tracker.feed("進捗: bugreport 40%")
    tracker.feed("進捗: bugreport")

    assert "40%" in tracker.view().rows[3].detail


def test_tracker_finish_success_marks_everything_done_at_100_percent():
    tracker, clock = _tracker()
    tracker.feed("進捗: レポート作成")
    clock.now = 130
    tracker.finish(True)
    clock.now = 999  # 終了後は時間が進んでも変わらない

    view = tracker.view()

    assert all(row.state == "done" for row in view.rows)
    assert view.percent == 100 and view.remaining == 0 and view.elapsed == 130 and view.finished


def test_tracker_finish_failure_marks_the_current_phase_and_never_reaches_100():
    tracker, clock = _tracker()
    tracker.feed("進捗: bugreport 40%")
    clock.now = 50
    tracker.finish(False)

    view = tracker.view()

    assert [row.state for row in view.rows] == ["done", "done", "done", "failed", "pending", "pending", "pending"]
    assert view.percent < 100 and view.remaining is None


def test_tracker_for_init_has_two_phases():
    tracker, _ = _tracker(PHASES_INIT)
    tracker.feed("進捗: 設定ファイル作成")
    tracker.finish(True)

    assert [row.label for row in tracker.view().rows] == ["準備", "設定ファイル作成"]


def test_format_helpers():
    assert format_duration(45.9) == "45秒" and format_duration(65) == "1分05秒"
    tracker, clock = _tracker()
    clock.now = 70
    tracker.feed("進捗: bugreport 10%")
    view = tracker.view()
    assert format_progress_summary(view).startswith(f"{view.percent}%  経過 1分10秒  残り 約")
    assert format_row(view.rows[0]) == "✔ 準備  70.0秒" and format_row(view.rows[1]) == "✔ 端末情報"  # 飛ばした工程は所要時間を出さない
    assert format_row(view.rows[6]) == "  レポート作成"
    assert format_row(view.rows[3]).startswith("▶ bugreport  10%")
    tracker.finish(True)
    assert "残り" not in format_progress_summary(tracker.view())


def test_load_phase_weights_reads_the_newest_session_and_ignores_unknown_or_bad_values(tmp_path):
    import json
    import os

    old = tmp_path / "old" / "session.json"
    new = tmp_path / "new" / "session.json"
    broken = tmp_path / "broken" / "session.json"
    for path in (old, new, broken):
        path.parent.mkdir()
    old.write_text(json.dumps({"capture": {"phase_sec": {"bugreport": 1.0}}}), encoding="utf-8")
    new.write_text(
        json.dumps({"capture": {"phase_sec": {"bugreport": 80.5, "sampling": 0, "x": 5, "parse": "a"}}}),
        encoding="utf-8",
    )
    broken.write_text("{not json", encoding="utf-8")
    os.utime(old, (1000, 1000))
    os.utime(new, (3000, 3000))
    os.utime(broken, (2000, 2000))

    assert load_phase_weights(tmp_path) == {"bugreport": 80.5}
    assert load_phase_weights(tmp_path / "missing") == {}
