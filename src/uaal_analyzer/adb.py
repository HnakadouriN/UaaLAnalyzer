from __future__ import annotations

import codecs
import queue
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

from .errors import AdbError

# 端末が出す `[ 45%] generating bugreport-....zip` の割合。
_PERCENT_RE = re.compile(r"\[\s*(\d+)%\]")
_LINE_SPLIT_RE = re.compile(r"[\r\n]+")
_STOP_WAIT_SEC = 5.0
BugreportProgress = Callable[[int | None, float], None]


class Adb:
    """ADB 呼び出しの唯一の入口。runner を差し替えればテストできる。"""

    def __init__(
        self,
        serial: str = "",
        adb_path: str = "adb",
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
    ) -> None:
        self._serial = serial
        self._adb_path = adb_path
        self._runner = runner
        self._popen = popen

    def _command(self, args: list[str]) -> list[str]:
        command = [self._adb_path]
        if self._serial:
            command += ["-s", self._serial]
        return command + args

    def run(self, args: list[str], timeout: float = 60, check: bool = True) -> str:
        command = self._command(args)
        try:
            proc = self._runner(command, capture_output=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise AdbError(f"adb が見つかりません: {self._adb_path}") from exc
        except subprocess.TimeoutExpired as exc:
            raise AdbError(f"adb がタイムアウトしました ({timeout}s): {' '.join(args)}") from exc
        out = proc.stdout.decode("utf-8", errors="replace").replace("\r\n", "\n")
        if check and proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace").replace("\r\n", "\n").strip()
            detail = err or out.strip()
            raise AdbError(f"adb {' '.join(args)} が失敗しました (code {proc.returncode}): {detail}")
        return out

    def shell(self, command: str, timeout: float = 60, check: bool = True) -> str:
        return self.run(["shell", command], timeout=timeout, check=check)

    def bugreport(
        self,
        destination: Path,
        timeout: float,
        progress: BugreportProgress | None = None,
        clock: Callable[[], float] = time.monotonic,
        tick_sec: float = 10.0,
    ) -> None:
        """bugreport を取得する。progress を渡すと、出力から読んだ割合 (読めなければ None) と経過秒を知らせる。"""
        destination.parent.mkdir(parents=True, exist_ok=True)
        if progress is None:
            self.run(["bugreport", str(destination)], timeout=timeout)
        else:
            self._bugreport_with_progress(destination, timeout, progress, clock, tick_sec)
        if not destination.exists():
            raise AdbError(f"bugreport の出力が見つかりません: {destination}")

    def _bugreport_with_progress(
        self,
        destination: Path,
        timeout: float,
        progress: BugreportProgress,
        clock: Callable[[], float],
        tick_sec: float,
    ) -> None:
        args = ["bugreport", str(destination)]
        try:
            process = self._popen(self._command(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except FileNotFoundError as exc:
            raise AdbError(f"adb が見つかりません: {self._adb_path}") from exc
        chunks: queue.Queue = queue.Queue()

        def read() -> None:
            try:
                stream = process.stdout
                reader = getattr(stream, "read1", None) or stream.read
                while True:
                    data = reader(1024)
                    if not data:
                        break
                    chunks.put(data)
            finally:
                chunks.put(None)  # 読み取りが例外で終わっても、本体を待たせ続けない

        reader_thread = threading.Thread(target=read, daemon=True)
        reader_thread.start()
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")  # 多バイト文字が塊の境をまたぐため
        started = clock()
        last_tick = started
        percent: int | None = None
        buffer = ""
        output = ""
        stopped = False

        def notify(line: str, now: float) -> None:
            nonlocal percent, last_tick
            for match in _PERCENT_RE.finditer(line):
                value = int(match.group(1))
                if value != percent:
                    percent = value
                    progress(percent, now - started)
                    last_tick = now

        def stop() -> None:
            nonlocal stopped
            if stopped:
                return
            stopped = True
            process.kill()
            try:
                process.wait(timeout=_STOP_WAIT_SEC)
            except subprocess.TimeoutExpired:
                pass
            reader_thread.join(timeout=_STOP_WAIT_SEC)

        def timed_out() -> AdbError:
            stop()
            return AdbError(f"adb がタイムアウトしました ({timeout}s): {' '.join(args)}")

        try:
            while True:
                now = clock()
                if now - started > timeout:
                    raise timed_out()
                try:
                    data = chunks.get(timeout=0.5)
                except queue.Empty:
                    data = b""
                if data is None:
                    break
                if data:
                    text = decoder.decode(data)
                    output = (output + text)[-2000:]
                    # \r だけで区切られる更新もあるため、行の終わりは \r と \n の両方で見る。未完の末尾は次の読み取りへ回す。
                    *lines, buffer = _LINE_SPLIT_RE.split(buffer + text)
                    for line in lines:
                        notify(line, now)
                if now - last_tick >= tick_sec:
                    progress(percent, now - started)
                    last_tick = now
            if buffer:
                notify(buffer, clock())
            try:
                code = process.wait(timeout=max(timeout - (clock() - started), 1.0))
            except subprocess.TimeoutExpired:
                raise timed_out() from None
        except BaseException:
            stop()  # progress の例外などで抜けても、adb を残さない
            raise
        if code != 0:
            detail = re.sub(r"\s+", " ", output).strip()
            raise AdbError(f"adb {' '.join(args)} が失敗しました (code {code}): {detail}")
