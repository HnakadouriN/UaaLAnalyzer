from __future__ import annotations

import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from helpers import PACKAGE, PID, stuck_section, stuck_trace
from uaal_analyzer.adb import Adb
from uaal_analyzer.collect.capture import CaptureOptions, run_capture
from uaal_analyzer.errors import AdbError, CaptureError

JST = timezone(timedelta(hours=9))
STAT = (
    "8620 (UnityMain) R 1 1 1 0 -1 4194560 100 0 5 0 120 30 0 0 20 0\n"
    "8630 (Worker) S 1 1 1 0 -1 4194560 100 0 5 0 7 1 0 0 20 0\n"
)


class FakeAdb:
    """Adb の差し替え。端末時刻は 1 回の問い合わせごとに 3 秒進む。"""

    def __init__(
        self, trace_text: str, pids: str = str(PID), run_as_ok: bool = True, failing: tuple[str, ...] = ()
    ) -> None:
        self.trace_text = trace_text
        self.pids = pids
        self.run_as_ok = run_as_ok
        self.failing = failing
        self.commands: list[str] = []
        self.now = datetime(2026, 9, 24, 20, 30, 30, tzinfo=JST)

    def shell(self, command: str, timeout: float = 60, check: bool = True) -> str:
        self.commands.append(command)
        for key in self.failing:
            if key in command:
                raise AdbError(f"failed: {key}")
        if command.endswith(" id"):
            if not self.run_as_ok:
                raise AdbError("run-as: package not debuggable")
            return "uid=10258(u0_a258)\n"
        if command.startswith("pidof"):
            return self.pids + "\n"
        if command.startswith("date"):
            current = self.now
            self.now += timedelta(seconds=3)
            return current.strftime("%Y-%m-%dT%H:%M:%S%z") + "\n"
        if command.startswith("top"):
            return "top output\n"
        if "wchan" in command:
            return "8620 UnityMain futex_wait_queue\n8630 Worker 0\n"
        if "cat /proc" in command:
            return STAT
        if "kill -3" in command:
            return ""
        if command == "getprop":
            return "[ro.product.model]: [M]\n"
        if command.startswith("dumpsys package"):
            return "versionName=1.0\npkgFlags=[ DEBUGGABLE ]\n"
        if command == "dumpsys power":
            return "  mWakefulness=Asleep\n"
        if command.startswith("dumpsys meminfo"):
            return " Native Heap    57780    1    1    1    1\n        TOTAL PSS:   578162            TOTAL RSS:   669316       TOTAL SWAP PSS:   1\n"
        if command.startswith("dumpsys"):
            return ""
        raise AssertionError(f"想定外のコマンド: {command}")

    def bugreport(self, destination, timeout: float, progress=None) -> None:
        if progress is not None:
            progress(40, 4.0)
            progress(None, 12.0)
        destination.parent.mkdir(parents=True, exist_ok=True)
        report = (
            "------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------\n"
            f"09-24 20:30:36.000 10258 {PID} {PID} I Unity   : hello from unity\n"
            "------ KERNEL LOG (dmesg) ------\n[ 1.0] lowmemorykiller: Kill\n"
        )
        with zipfile.ZipFile(destination, "w") as archive:
            archive.writestr("FS/data/anr/trace_00", stuck_section(0, second=0).replace("20:30:00", "19:00:00"))
            archive.writestr("FS/data/anr/trace_01", self.trace_text)
            archive.writestr("bugreport-test.txt", report)


def _options(**overrides) -> CaptureOptions:
    values = dict(package=PACKAGE, samples=3, interval_sec=0.0)
    values.update(overrides)
    return CaptureOptions(**values)


def test_capture_collects_samples_snapshots_and_ignores_stale_traces(tmp_path):
    adb = FakeAdb(stuck_trace(3))

    session = run_capture(adb, _options(), tmp_path / "s1", "s1", log=lambda m: None, sleep=lambda s: None)

    assert session.pid == PID
    assert [s.time[11:19] for s in session.samples] == ["20:30:35", "20:30:37", "20:30:39"]
    assert len(session.proc_snapshots) == 3
    assert session.proc_snapshots[0].threads[0].comm == "UnityMain"
    assert sum("kill -3" in c for c in adb.commands) == 3
    assert (tmp_path / "s1" / "session.json").exists()
    assert (tmp_path / "s1" / "raw" / "top_00.txt").read_text(encoding="utf-8") == "top output\n"
    assert (tmp_path / "s1" / "raw" / "stat_02.txt").exists()
    assert (tmp_path / "s1" / "raw" / "bugreport.zip").exists()
    assert any("取得窓の外" in w for w in session.warnings)


def test_capture_warns_when_trace_count_differs_from_sent_signals(tmp_path):
    session = run_capture(FakeAdb(stuck_trace(2)), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)

    assert len(session.samples) == 2
    assert any("送信 3 回" in w and "2 件" in w for w in session.warnings)


def test_capture_records_device_info_wchan_meminfo_and_logs(tmp_path):
    adb = FakeAdb(stuck_trace(3))

    session = run_capture(adb, _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)

    assert session.device["props"] == {"ro.product.model": "M"}
    assert session.device["package"]["debuggable"] is True
    assert session.device["power"] == {"mWakefulness": "Asleep"}
    assert [s.wchan for s in session.proc_snapshots] == [{"8620": "futex_wait_queue", "8630": ""}] * 3
    assert all(s.meminfo["total_pss"] == 578162 for s in session.proc_snapshots)
    assert [e["message"] for e in session.logs["logs"]] == ["hello from unity"]
    assert len(session.logs["kernel_lines"]) == 1
    assert (tmp_path / "s" / "raw" / "getprop.txt").exists()
    assert (tmp_path / "s" / "raw" / "dumpsys_package.txt").exists()


def test_capture_reads_device_info_once_before_sampling(tmp_path):
    adb = FakeAdb(stuck_trace(3))

    run_capture(adb, _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)

    assert adb.commands.count("getprop") == 1
    first_kill = next(i for i, c in enumerate(adb.commands) if "kill -3" in c)
    assert adb.commands.index("getprop") < first_kill
    assert sum(c.startswith("dumpsys meminfo") for c in adb.commands) == 3


def test_capture_continues_when_optional_reads_fail(tmp_path):
    adb = FakeAdb(stuck_trace(3), failing=("dumpsys window", "wchan", "dumpsys meminfo"))

    session = run_capture(adb, _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)

    assert len(session.samples) == 3
    assert "window" not in session.device
    assert all(s.wchan == {} and s.meminfo == {} for s in session.proc_snapshots)
    assert any("dumpsys_window" in w for w in session.warnings)
    assert sum("wchan" in w for w in session.warnings) == 3
    assert sum("dumpsys meminfo" in w for w in session.warnings) == 3


def test_capture_warns_when_bugreport_has_no_dumpstate_text(tmp_path):
    class NoDumpstate(FakeAdb):
        def bugreport(self, destination, timeout, progress=None):
            super().bugreport(destination, timeout, progress)
            original = destination.with_suffix(".orig")
            destination.rename(original)
            with zipfile.ZipFile(original) as src, zipfile.ZipFile(destination, "w") as dst:
                for name in src.namelist():
                    if not name.startswith("bugreport"):
                        dst.writestr(name, src.read(name))
            original.unlink()

    session = run_capture(NoDumpstate(stuck_trace(3)), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)

    assert session.logs == {}
    assert any("dumpstate" in w for w in session.warnings)


def test_capture_fails_clearly_when_run_as_is_unavailable(tmp_path):
    with pytest.raises(CaptureError, match="run-as"):
        run_capture(FakeAdb("", run_as_ok=False), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)


def test_capture_requires_explicit_pid_when_multiple_processes(tmp_path):
    with pytest.raises(CaptureError, match="--pid"):
        run_capture(FakeAdb("", pids="100 200"), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)


def test_capture_rejects_package_name_with_shell_metacharacters(tmp_path):
    adb = FakeAdb(stuck_trace(3))

    with pytest.raises(CaptureError, match="使えない文字"):
        run_capture(adb, _options(package="com.x; rm -rf /"), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)

    assert adb.commands == []


def test_capture_uses_given_pid_without_pidof(tmp_path):
    adb = FakeAdb(stuck_trace(3), pids="")

    run_capture(adb, _options(pid=PID), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)

    assert not any(c.startswith("pidof") for c in adb.commands)


def test_capture_fails_when_bugreport_has_no_matching_trace(tmp_path):
    with pytest.raises(CaptureError, match="見つかりません"):
        run_capture(FakeAdb(stuck_section(0, pid=999)), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)


def test_capture_reports_process_exit_during_sampling(tmp_path):
    class Dying(FakeAdb):
        def shell(self, command, timeout=60, check=True):
            if "kill -3" in command:
                raise AdbError("no such process")
            return super().shell(command, timeout, check)

    with pytest.raises(CaptureError, match="終了した可能性"):
        run_capture(Dying(stuck_trace(3)), _options(), tmp_path / "s", "s", log=lambda m: None, sleep=lambda s: None)


def test_adb_wrapper_builds_command_and_wraps_failures():
    import subprocess

    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        code = 1 if "fail" in command else 0
        return subprocess.CompletedProcess(command, code, stdout=b"a\r\nb\r\n", stderr=b"denied")

    adb = Adb("SER", "adb", runner)

    assert adb.shell("echo hi") == "a\nb\n"
    assert calls[0] == ["adb", "-s", "SER", "shell", "echo hi"]
    with pytest.raises(AdbError, match="denied"):
        adb.run(["fail"])
    assert adb.run(["fail"], check=False) == "a\nb\n"


def test_adb_wrapper_reports_missing_executable():
    def runner(command, **kwargs):
        raise FileNotFoundError

    with pytest.raises(AdbError, match="見つかりません"):
        Adb("", "no-adb", runner).run(["devices"])


def test_rebuild_reparses_saved_bugreport_and_clears_symbol_report(tmp_path):
    from uaal_analyzer.collect.capture import rebuild_session
    from uaal_analyzer.model import load_session, save_session

    session_dir = tmp_path / "s"
    session = run_capture(
        FakeAdb(stuck_trace(3)), _options(), session_dir, "s", log=lambda m: None, sleep=lambda s: None
    )
    session.symbol_report = {"x": {"status": "resolved"}}
    session.samples = session.samples[:1]
    save_session(session_dir / "session.json", session)

    rebuilt = rebuild_session(session_dir, time_margin_sec=30)

    assert len(rebuilt.samples) == 3
    assert rebuilt.symbol_report == {}
    assert load_session(session_dir / "session.json") == rebuilt
    assert len(rebuilt.proc_snapshots) == 3


def test_rebuild_requires_saved_bugreport(tmp_path):
    from uaal_analyzer.collect.capture import rebuild_session
    from uaal_analyzer.model import save_session

    from helpers import make_session

    save_session(tmp_path / "s" / "session.json", make_session(stuck_trace(1)))

    with pytest.raises(CaptureError, match="生データがありません"):
        rebuild_session(tmp_path / "s", time_margin_sec=30)
