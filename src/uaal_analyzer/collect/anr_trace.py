from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from ..model import Frame, ThreadInfo
from ..timeutil import parse_device_time

_HEADER_RE = re.compile(r"^----- pid (\d+) at (.+?) -----\s*$")
_END_RE = re.compile(r"^----- end (\d+) -----\s*$")
_CMD_RE = re.compile(r"^Cmd line: (.*?)\s*$")
_THREAD_RE = re.compile(
    r'^"(?P<name>.*)"(?P<daemon> daemon)? prio=(?P<prio>\d+) tid=(?P<tid>\d+) (?P<state>.+?)\s*$'
)
_NATIVE_THREAD_RE = re.compile(r'^"(?P<name>.*)" sysTid=(?P<systid>\d+)\s*$')
# ART に登録されていないスレッド。tid が無く、sysTid は直後の `| sysTid=` 行にある。
_DETACHED_THREAD_RE = re.compile(r'^"(?P<name>.*)"(?P<daemon> daemon)? prio=(?P<prio>\d+) \(not attached\)\s*$')
_NATIVE_FRAME_RE = re.compile(r"^\s+native: #(\d+) pc ([0-9a-fA-F]+)\s+(.*?)\s*$")
_JAVA_FRAME_RE = re.compile(r"^\s+at (.+?)\s*$")
_BUILD_ID_RE = re.compile(r"\s*\(BuildId: ([0-9a-fA-F]+)\)\s*$")
_MAP_OFFSET_RE = re.compile(r"\s+\(offset (?:0x)?([0-9a-fA-F]+)\)")
_DELETED_RE = re.compile(r"\s+\(deleted\)")
_UNKNOWN_SYMBOL = "???"


@dataclass
class TraceSection:
    pid: int
    time_text: str
    time: datetime
    cmdline: str | None
    source: str
    threads: list[ThreadInfo] = field(default_factory=list)
    # スレッド見出しに見えるが書式を認識できなかった行。直後のスタックは別のスレッドへ混ぜずに捨てる。
    unknown_headers: list[str] = field(default_factory=list)


def parse_trace_text(text: str, source: str = "") -> list[TraceSection]:
    """ART の SIGQUIT トレース (bugreport 内 /data/anr/trace_*) を pid 区間ごとに解析する。"""
    sections: list[TraceSection] = []
    section: TraceSection | None = None
    thread: ThreadInfo | None = None

    for line in text.splitlines():
        header = _HEADER_RE.match(line)
        if header:
            if section is not None:
                sections.append(section)
            time_text = header.group(2)
            try:
                parsed_time = parse_device_time(time_text)
            except ValueError:
                section = None
                thread = None
                continue
            section = TraceSection(int(header.group(1)), time_text, parsed_time, None, source)
            thread = None
            continue
        if section is None:
            continue
        if _END_RE.match(line):
            sections.append(section)
            section = None
            thread = None
            continue
        if line.startswith("----- "):
            thread = None
            continue
        cmd = _CMD_RE.match(line)
        if cmd and section.cmdline is None:
            section.cmdline = cmd.group(1)
            continue

        started = _parse_thread_header(line)
        if started is not None:
            thread = started
            section.threads.append(thread)
            continue
        if line.startswith('"'):
            section.unknown_headers.append(line.strip())
            thread = None
            continue
        if thread is None:
            continue

        stripped = line.strip()
        if stripped.startswith("|"):
            _apply_state_line(thread, stripped)
            continue
        frame = _parse_frame(line, thread)
        if frame is not None:
            thread.frames.append(frame)

    if section is not None:
        sections.append(section)
    return sections


def _parse_thread_header(line: str) -> ThreadInfo | None:
    match = _THREAD_RE.match(line)
    if match:
        return ThreadInfo(
            name=match.group("name"),
            tid=int(match.group("tid")),
            art_state=match.group("state"),
            daemon=bool(match.group("daemon")),
        )
    native = _NATIVE_THREAD_RE.match(line)
    if native:
        return ThreadInfo(name=native.group("name"), sys_tid=int(native.group("systid")))
    detached = _DETACHED_THREAD_RE.match(line)
    if detached:
        return ThreadInfo(name=detached.group("name"), daemon=bool(detached.group("daemon")))
    return None


def _parse_frame(line: str, thread: ThreadInfo) -> Frame | None:
    native = _NATIVE_FRAME_RE.match(line)
    if native:
        return _native_frame(native)
    java = _JAVA_FRAME_RE.match(line)
    if java:
        java_index = sum(1 for f in thread.frames if f.kind == "java")
        return Frame(index=java_index, kind="java", module="java", symbol=java.group(1))
    return None


def _apply_state_line(thread: ThreadInfo, line: str) -> None:
    systid = re.search(r"sysTid=(\d+)", line)
    if systid:
        thread.sys_tid = int(systid.group(1))
    state = re.search(r"\bstate=(\w)\b", line)
    if state:
        thread.os_state = state.group(1)
    utm = re.search(r"\butm=(\d+)", line)
    stm = re.search(r"\bstm=(\d+)", line)
    if utm and stm:
        thread.utime = int(utm.group(1))
        thread.stime = int(stm.group(1))
    hz = re.search(r"\bHZ=(\d+)", line)
    if hz:
        thread.hz = int(hz.group(1))


def _native_frame(match: re.Match[str]) -> Frame:
    rest = match.group(3)
    build_id = None
    build = _BUILD_ID_RE.search(rest)
    if build:
        build_id = build.group(1).lower()
        rest = rest[: build.start()]
    rest = rest.strip()
    map_offset: int | None = None
    offset_match = _MAP_OFFSET_RE.search(rest)
    if offset_match:
        map_offset = int(offset_match.group(1), 16)
        rest = (rest[: offset_match.start()] + rest[offset_match.end() :]).strip()
    rest = _DELETED_RE.sub("", rest, count=1)
    module = rest
    symbol: str | None = None
    offset: int | None = None
    split = rest.find(" (")
    if split >= 0:
        module = rest[:split]
        inner = rest[split + 2 :]
        if inner.endswith(")"):
            inner = inner[:-1]
        symbol = inner
        head, sep, tail = inner.rpartition("+")
        if sep and tail.isdigit():
            symbol = head
            offset = int(tail)
    return Frame(
        index=int(match.group(1)),
        kind="native",
        pc=int(match.group(2), 16),
        module=module,
        symbol=None if symbol == _UNKNOWN_SYMBOL else (symbol or None),
        offset=offset,
        build_id=build_id,
        map_offset=map_offset,
    )
