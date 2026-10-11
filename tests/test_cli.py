from __future__ import annotations

import json

import pytest

from helpers import make_session, stuck_trace
from uaal_analyzer.cli import main
from uaal_analyzer.model import save_session


def _write_session(data_dir, name="20260924-203000"):
    session_dir = data_dir / "sessions" / name
    save_session(session_dir / "session.json", make_session(stuck_trace(3)))
    return session_dir


def test_help_lists_all_commands(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])

    assert exc.value.code == 0
    out = capsys.readouterr().out
    for command in ("capture", "symbols", "symbolize", "analyze", "run"):
        assert command in out


def test_analyze_latest_writes_report_and_analysis_json(tmp_path, capsys):
    session_dir = _write_session(tmp_path)

    code = main(["--data-dir", str(tmp_path), "analyze", "latest"])

    assert code == 0
    out = capsys.readouterr().out
    assert "自社メソッドを判定できません" in out  # シンボル未解決のセッション
    assert "観測結果 (参考)" in out
    assert (session_dir / "report.md").exists()
    assert (session_dir / "report.html").read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    analysis = json.loads((session_dir / "analysis.json").read_text(encoding="utf-8"))
    assert analysis["main_threads"][0]["stuck"] is True
    assert analysis["observation"]
    assert analysis["thread_table"][0]["name"] == "UnityMain"


def test_analyze_accepts_session_path_and_name(tmp_path):
    session_dir = _write_session(tmp_path, "named")

    assert main(["--data-dir", str(tmp_path), "analyze", str(session_dir)]) == 0
    assert main(["--data-dir", str(tmp_path), "analyze", "named"]) == 0


def test_unknown_session_returns_error_code(tmp_path, capsys):
    code = main(["--data-dir", str(tmp_path), "analyze", "nope"])

    assert code == 1
    assert "セッションが見つかりません" in capsys.readouterr().err


def test_symbolize_without_native_frames_needs_no_ndk(tmp_path, capsys):
    from uaal_analyzer.collect.anr_trace import parse_trace_text
    from uaal_analyzer.model import Sample, Session

    section = parse_trace_text(stuck_trace(1).replace("libil2cpp.so", "libother.so"))[0]
    session = Session(
        "s", "pkg", "", 8589, "2026-09-24T20:31:00+09:00",
        samples=[Sample(0, section.time.isoformat(), 8589, "pkg", "t", section.threads)],
    )
    session_dir = tmp_path / "sessions" / "s"
    save_session(session_dir / "session.json", session)

    code = main(["--data-dir", str(tmp_path), "symbolize", "s"])

    assert code == 0
    assert (session_dir / "symbolized.json").exists()


def _patch_target(monkeypatch, package="com.game.app", pid=123, calls=None):
    from uaal_analyzer.collect.target import Target

    def resolve(adb, **kwargs):
        if calls is not None:
            calls.append(kwargs)
        return Target(package, pid, "foreground", [{"package": package, "pids": [pid]}])

    monkeypatch.setattr("uaal_analyzer.cli.resolve_target", resolve)


def _fake_capture(phase_sec, seen=None):
    def run_capture(adb, options, session_dir, session_id, **kwargs):
        if seen is not None:
            seen.append(options)
        session = make_session(stuck_trace(3))
        session.capture = {"samples": 3, "interval_sec": 2.0, "phase_sec": phase_sec}
        save_session(session_dir / "session.json", session)
        return session

    return run_capture


def test_run_prints_phase_timings_including_symbolize_and_report(tmp_path, capsys, monkeypatch):
    phases = {"prepare": 1.25, "device_info": 1.8, "sampling": 39.3, "bugreport": 94.0, "parse": 0.5}
    _patch_target(monkeypatch)
    monkeypatch.setattr("uaal_analyzer.cli.run_capture", _fake_capture(phases))
    monkeypatch.setattr("uaal_analyzer.cli._symbolize", lambda cfg, session_dir: None)

    code = main(["--data-dir", str(tmp_path), "run", "--session-name", "s1"])

    assert code == 0
    line = next(l for l in capsys.readouterr().out.splitlines() if l.startswith("所要時間:"))
    for label in ("準備 1.2", "端末情報 1.8", "サンプル取得 39.3", "bugreport 94.0", "トレース解析 0.5", "シンボル解決", "解析 ", "合計"):
        assert label in line


def test_capture_prints_recorded_phase_timings(tmp_path, capsys, monkeypatch):
    _patch_target(monkeypatch)
    monkeypatch.setattr("uaal_analyzer.cli.run_capture", _fake_capture({"prepare": 2.0, "bugreport": 90.0}))

    code = main(["--data-dir", str(tmp_path), "capture", "--session-name", "s2"])

    assert code == 0
    out = capsys.readouterr().out
    assert "所要時間: 準備 2.0秒 / bugreport 90.0秒 / 合計 92.0秒" in out


def test_capture_without_recorded_phases_prints_no_timing_line(tmp_path, capsys, monkeypatch):
    _patch_target(monkeypatch)
    monkeypatch.setattr("uaal_analyzer.cli.run_capture", _fake_capture({}))

    main(["--data-dir", str(tmp_path), "capture", "--session-name", "s3"])

    assert "所要時間" not in capsys.readouterr().out


def _isolated_configs(tmp_path, monkeypatch, default_text=None):
    """設定ファイルの置き場を tmp に差し替える (リポジトリの configs/ を汚さない)。"""
    configs = tmp_path / "configs"
    configs.mkdir()
    default = configs / "default.toml"
    if default_text is not None:
        default.write_text(default_text, encoding="utf-8")
    monkeypatch.setattr("uaal_analyzer.config.DEFAULT_CONFIG_PATH", default)
    monkeypatch.setattr("uaal_analyzer.project_setup.DEFAULT_CONFIG_PATH", default)
    return configs


def test_run_without_config_uses_the_config_named_after_the_detected_package(tmp_path, capsys, monkeypatch):
    configs = _isolated_configs(tmp_path, monkeypatch, '[device]\npackage = "com.example.app"\n')
    (configs / "com.game.app.toml").write_text(
        '[device]\npackage = "com.game.app"\n[capture]\nsamples = 4\ninterval_sec = 1.5\n', encoding="utf-8"
    )
    seen, calls = [], []
    _patch_target(monkeypatch, calls=calls)
    monkeypatch.setattr("uaal_analyzer.cli.run_capture", _fake_capture({}, seen))
    monkeypatch.setattr("uaal_analyzer.cli._symbolize", lambda cfg, session_dir: None)

    main(["--data-dir", str(tmp_path), "run", "--session-name", "a1"])

    out = capsys.readouterr().out
    assert "com.game.app.toml" in out and "検出方法: foreground" in out
    assert (seen[0].samples, seen[0].interval_sec) == (4, 1.5)  # 見つけたパッケージ用の設定を使う
    assert calls[0]["config_package"] == ""  # --config を指定しないときは既定のパッケージ名を対象にしない
    assert seen[0].target["method"] == "foreground"


def test_run_warns_to_run_init_when_no_config_matches_the_detected_package(tmp_path, capsys, monkeypatch):
    _isolated_configs(tmp_path, monkeypatch, '[device]\npackage = "com.example.app"\n')
    seen = []
    _patch_target(monkeypatch)
    monkeypatch.setattr("uaal_analyzer.cli.run_capture", _fake_capture({}, seen))
    monkeypatch.setattr("uaal_analyzer.cli._symbolize", lambda cfg, session_dir: None)

    main(["--data-dir", str(tmp_path), "run", "--session-name", "a2"])

    out = capsys.readouterr().out
    assert "警告:" in out and "uaal init" in out
    assert any("uaal init" in n for n in seen[0].notes)


def test_run_does_not_warn_when_the_default_config_is_for_the_detected_package(tmp_path, capsys, monkeypatch):
    _isolated_configs(tmp_path, monkeypatch, '[device]\npackage = "com.game.app"\n')
    _patch_target(monkeypatch)
    monkeypatch.setattr("uaal_analyzer.cli.run_capture", _fake_capture({}))
    monkeypatch.setattr("uaal_analyzer.cli._symbolize", lambda cfg, session_dir: None)

    main(["--data-dir", str(tmp_path), "run", "--session-name", "a3"])

    assert "uaal init" not in capsys.readouterr().out


def test_explicit_config_package_and_package_option_are_passed_to_the_detector(tmp_path, monkeypatch):
    explicit = tmp_path / "mine.toml"
    explicit.write_text('[device]\npackage = "com.mine.app"\n', encoding="utf-8")
    calls = []
    _patch_target(monkeypatch, package="com.mine.app", calls=calls)
    monkeypatch.setattr("uaal_analyzer.cli.run_capture", _fake_capture({}))

    main(["--config", str(explicit), "--data-dir", str(tmp_path), "capture", "--session-name", "a4"])
    main(["--data-dir", str(tmp_path), "capture", "--session-name", "a5", "--package", "com.x.y", "--pid", "77"])

    assert calls[0]["config_package"] == "com.mine.app"
    assert (calls[1]["package"], calls[1]["pid"]) == ("com.x.y", 77)


def test_target_errors_are_reported_without_a_traceback(tmp_path, capsys, monkeypatch):
    from uaal_analyzer.errors import TargetError

    def fail(adb, **kwargs):
        raise TargetError("Unity のアプリを見つけられませんでした")

    monkeypatch.setattr("uaal_analyzer.cli.resolve_target", fail)

    code = main(["--data-dir", str(tmp_path), "capture", "--session-name", "a6"])

    assert code == 1
    assert "見つけられませんでした" in capsys.readouterr().err
    assert not (tmp_path / "sessions" / "a6").exists()


def test_init_creates_a_config_from_the_project_and_refuses_to_overwrite(tmp_path, capsys, monkeypatch):
    configs = _isolated_configs(tmp_path, monkeypatch)
    project = tmp_path / "proj"
    (project / "Assets" / "Core").mkdir(parents=True)
    (project / "Assets" / "Core" / "Core.asmdef").write_text('{"name": "Game.Core"}', encoding="utf-8")

    code = main(["init", "--project", str(project), "--package", "com.game.app"])

    out = capsys.readouterr().out
    assert code == 0 and (configs / "com.game.app.toml").exists()
    assert "Game.Core" in out and "Assembly-CSharp" in out
    assert main(["init", "--project", str(project), "--package", "com.game.app"]) == 1
    assert "--force" in capsys.readouterr().err
    assert main(["init", "--project", str(project), "--package", "com.game.app", "--force"]) == 0


def test_init_without_package_detects_it_from_the_device(tmp_path, capsys, monkeypatch):
    configs = _isolated_configs(tmp_path, monkeypatch)
    project = tmp_path / "proj"
    (project / "Assets").mkdir(parents=True)
    _patch_target(monkeypatch, package="com.detected.app")

    code = main(["init", "--project", str(project)])

    assert code == 0 and (configs / "com.detected.app.toml").exists()
    assert "com.detected.app" in capsys.readouterr().out


def test_symbols_list_when_empty(tmp_path, capsys):
    assert main(["--data-dir", str(tmp_path), "symbols", "list"]) == 0
    assert "ありません" in capsys.readouterr().out


@pytest.mark.parametrize("name", ["../escape", "a/b", ".."])
def test_capture_rejects_session_names_with_path_parts(tmp_path, capsys, name):
    code = main(["--data-dir", str(tmp_path), "capture", "--session-name", name])

    assert code == 1
    assert "パス区切り" in capsys.readouterr().err
    assert not (tmp_path / "sessions").exists()


def _progress_lines(out: str) -> list[str]:
    return [line for line in out.splitlines() if line.startswith("進捗:")]


def test_run_prints_progress_lines_in_order(tmp_path, capsys, monkeypatch):
    _patch_target(monkeypatch)
    monkeypatch.setattr("uaal_analyzer.cli.run_capture", _fake_capture({"prepare": 1.0}))
    monkeypatch.setattr("uaal_analyzer.cli._symbolize", lambda cfg, session_dir: None)

    assert main(["--data-dir", str(tmp_path), "run", "--session-name", "p1"]) == 0

    assert _progress_lines(capsys.readouterr().out) == ["進捗: 準備", "進捗: シンボル解決", "進捗: レポート作成"]


def test_init_prints_progress_lines(tmp_path, capsys, monkeypatch):
    _isolated_configs(tmp_path, monkeypatch)
    project = tmp_path / "proj"
    (project / "Assets").mkdir(parents=True)

    assert main(["init", "--project", str(project), "--package", "com.game.app"]) == 0

    assert _progress_lines(capsys.readouterr().out) == ["進捗: 準備", "進捗: 設定ファイル作成"]
