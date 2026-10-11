from __future__ import annotations

import subprocess
import threading
from pathlib import Path

import pytest

from helpers import stuck_trace
from test_capture import FakeAdb, _options
from uaal_analyzer.adb import Adb
from uaal_analyzer.collect.capture import _bugreport_reporter, run_capture
from uaal_analyzer.errors import AdbError


class _Stream:
    """read1 で決めた塊を順に返す。終わりを許すまでは読み取りが止まる (adb の標準出力の代わり)。"""

    def __init__(self, chunks: list[bytes], hold: threading.Event | None = None) -> None:
        self._chunks = list(chunks)
        self._hold = hold

    def read1(self, size: int) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        if self._hold is not None:
            self._hold.wait(timeout=10)
        return b""


class _Process:
    def __init__(self, stream: _Stream, code: int = 0, hold: threading.Event | None = None) -> None:
        self.stdout = stream
        self._code = code
        self._hold = hold
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        return self._code

    def kill(self) -> None:
        self.killed = True
        if self._hold is not None:
            self._hold.set()


class _ReadOnlyStream:
    """read1 を持たず read だけを持つ標準出力。"""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def read(self, size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


class _HangingProcess(_Process):
    """出力は閉じたが、プロセスが終わらない adb。"""

    def wait(self, timeout: float | None = None) -> int:
        if timeout is not None and not self.killed:
            raise subprocess.TimeoutExpired("adb", timeout)
        return -9


def _popen_factory(process: _Process, create_file: bool = True):
    seen: list[list[str]] = []

    def popen(command, **kwargs):
        seen.append(command)
        if create_file:
            Path(command[-1]).write_bytes(b"zip")
        return process

    popen.seen = seen  # type: ignore[attr-defined]
    return popen


def test_bugreport_progress_reports_each_new_percent_even_with_carriage_return_separators(tmp_path):
    chunks = [b"[  5%] generating bugreport\r", b"[ 5%] x\r[ 40%] y\r", b"[100%] done"]
    popen = _popen_factory(_Process(_Stream(chunks)))
    events: list[tuple[int | None, float]] = []

    Adb("S1", popen=popen).bugreport(tmp_path / "out" / "b.zip", 600, progress=lambda p, e: events.append((p, e)), clock=lambda: 0.0)

    assert [p for p, _ in events] == [5, 40, 100]
    assert popen.seen[0][:3] == ["adb", "-s", "S1"] and popen.seen[0][3] == "bugreport"


def test_bugreport_progress_reports_every_percent_inside_one_chunk(tmp_path):
    popen = _popen_factory(_Process(_Stream([b"[ 5%] a\r[ 40%] b\r[ 41%] c\n"])))
    events: list[int | None] = []

    Adb(popen=popen).bugreport(tmp_path / "b.zip", 600, progress=lambda p, e: events.append(p), clock=lambda: 0.0)

    assert events == [5, 40, 41]  # 1 回の読み取りに並んだ途中の割合も落とさない


def test_bugreport_progress_joins_a_percent_split_across_reads(tmp_path):
    popen = _popen_factory(_Process(_Stream([b"[ 4", b"5%] gen", b"erating\r[ 50%] x\r"])))
    events: list[int | None] = []

    Adb(popen=popen).bugreport(tmp_path / "b.zip", 600, progress=lambda p, e: events.append(p), clock=lambda: 0.0)

    assert events == [45, 50]


def test_bugreport_progress_works_with_a_stream_that_only_has_read(tmp_path):
    popen = _popen_factory(_Process(_ReadOnlyStream([b"[ 10%] x\r[100%] done"])))
    events: list[int | None] = []

    Adb(popen=popen).bugreport(tmp_path / "b.zip", 600, progress=lambda p, e: events.append(p), clock=lambda: 0.0)

    assert events == [10, 100]


def test_bugreport_progress_gives_up_when_adb_does_not_exit_after_the_output_closed(tmp_path):
    process = _HangingProcess(_Stream([b"[100%] done"]))

    with pytest.raises(AdbError, match="タイムアウト"):
        Adb(popen=_popen_factory(process, create_file=False)).bugreport(
            tmp_path / "b.zip", 600, progress=lambda p, e: None, clock=lambda: 0.0
        )

    assert process.killed


def test_bugreport_progress_ticks_with_none_when_no_percent_is_printed(tmp_path):
    hold = threading.Event()
    calls = {"n": 0}

    def clock() -> float:
        calls["n"] += 1
        if calls["n"] >= 4:
            hold.set()
        return calls["n"] * 5.0

    popen = _popen_factory(_Process(_Stream([b"pulling..."], hold)))
    events: list[tuple[int | None, float]] = []

    Adb(popen=popen).bugreport(tmp_path / "b.zip", 10_000, progress=lambda p, e: events.append((p, e)), clock=clock, tick_sec=10.0)

    assert events and all(p is None for p, _ in events)
    assert [e for _, e in events] == sorted(e for _, e in events)


def test_bugreport_progress_timeout_kills_the_process(tmp_path):
    hold = threading.Event()
    process = _Process(_Stream([], hold), hold=hold)
    ticks = iter(range(0, 10_000, 100))

    with pytest.raises(AdbError, match="タイムアウト"):
        Adb(popen=_popen_factory(process, create_file=False)).bugreport(
            tmp_path / "b.zip", 150, progress=lambda p, e: None, clock=lambda: float(next(ticks))
        )

    assert process.killed


def test_bugreport_progress_nonzero_exit_is_an_error_with_the_output_tail(tmp_path):
    process = _Process(_Stream([b"adb: error: device offline\n"]), code=1)

    with pytest.raises(AdbError, match="code 1.*device offline"):
        Adb(popen=_popen_factory(process, create_file=False)).bugreport(
            tmp_path / "b.zip", 600, progress=lambda p, e: None, clock=lambda: 0.0
        )


def test_bugreport_progress_does_not_wait_for_the_timeout_when_the_reader_fails(tmp_path):
    class BrokenStream:
        def read1(self, size: int) -> bytes:
            raise OSError("pipe closed")

    process = _Process(BrokenStream(), code=1)  # type: ignore[arg-type]
    ticks = iter(range(0, 10_000, 100))  # 合図が来ないと、タイムアウトのエラーになる

    with pytest.raises(AdbError, match="code 1"):
        Adb(popen=_popen_factory(process, create_file=False)).bugreport(
            tmp_path / "b.zip", 600, progress=lambda p, e: None, clock=lambda: float(next(ticks))
        )


def test_bugreport_progress_kills_adb_when_the_progress_callback_raises(tmp_path):
    process = _Process(_Stream([b"[ 10%] x\r"]))

    def failing(percent, elapsed):
        raise RuntimeError("callback failed")

    with pytest.raises(RuntimeError, match="callback failed"):
        Adb(popen=_popen_factory(process, create_file=False)).bugreport(
            tmp_path / "b.zip", 600, progress=failing, clock=lambda: 0.0
        )

    assert process.killed


def test_bugreport_progress_keeps_a_multibyte_character_split_across_reads(tmp_path):
    encoded = "デバイス".encode("utf-8")
    process = _Process(_Stream([encoded[:4], encoded[4:]]), code=1)

    with pytest.raises(AdbError, match="デバイス"):
        Adb(popen=_popen_factory(process, create_file=False)).bugreport(
            tmp_path / "b.zip", 600, progress=lambda p, e: None, clock=lambda: 0.0
        )


def test_bugreport_progress_without_output_file_is_an_error(tmp_path):
    process = _Process(_Stream([b"[100%] done"]))

    with pytest.raises(AdbError, match="出力が見つかりません"):
        Adb(popen=_popen_factory(process, create_file=False)).bugreport(
            tmp_path / "b.zip", 600, progress=lambda p, e: None, clock=lambda: 0.0
        )


def test_bugreport_progress_missing_adb_is_an_error(tmp_path):
    def popen(command, **kwargs):
        raise FileNotFoundError("adb")

    with pytest.raises(AdbError, match="adb が見つかりません"):
        Adb(popen=popen).bugreport(tmp_path / "b.zip", 600, progress=lambda p, e: None)


def test_bugreport_without_progress_keeps_using_the_blocking_runner(tmp_path):
    seen: list[list[str]] = []

    def runner(command, **kwargs):
        seen.append(command)
        Path(command[-1]).write_bytes(b"zip")
        return subprocess.CompletedProcess(command, 0, b"", b"")

    def popen(command, **kwargs):
        raise AssertionError("progress が無いときは Popen を使わない")

    Adb(runner=runner, popen=popen).bugreport(tmp_path / "b.zip", 600)

    assert seen[0][-2] == "bugreport"


def test_bugreport_reporter_does_not_repeat_the_same_percent_and_reports_elapsed_when_unknown():
    lines: list[str] = []
    report = _bugreport_reporter(lines.append)

    report(10, 1.0)
    report(10, 11.0)
    report(20, 21.0)
    report(None, 31.9)

    assert lines == ["進捗: bugreport 10%", "進捗: bugreport 20%", "進捗: bugreport 経過 31秒"]


def test_capture_logs_progress_lines_in_order(tmp_path):
    lines: list[str] = []

    run_capture(FakeAdb(stuck_trace(3)), _options(samples=3), tmp_path / "s", "s", log=lines.append, sleep=lambda s: None)

    assert [l for l in lines if l.startswith("進捗:")] == [
        "進捗: 準備",
        "進捗: 端末情報",
        "進捗: サンプル取得 0/3",
        "進捗: サンプル取得 1/3",
        "進捗: サンプル取得 2/3",
        "進捗: サンプル取得 3/3",
        "進捗: bugreport",
        "進捗: bugreport 40%",
        "進捗: bugreport 経過 12秒",
        "進捗: トレース解析",
    ]


def test_capture_progress_lines_are_understood_by_the_gui_tracker(tmp_path):
    from uaal_analyzer.gui import PHASES_RUN, ProgressTracker, parse_progress_line

    lines: list[str] = []
    run_capture(FakeAdb(stuck_trace(3)), _options(samples=3), tmp_path / "s", "s", log=lines.append, sleep=lambda s: None)

    tracker = ProgressTracker(PHASES_RUN)
    fed = [tracker.feed(line) for line in lines if line.startswith("進捗:")]

    assert all(fed) and all(parse_progress_line(l) for l in lines if l.startswith("進捗:"))
    view = tracker.view()
    assert view.rows[4].state == "running" and view.rows[3].state == "done"
