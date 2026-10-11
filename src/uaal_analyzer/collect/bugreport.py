from __future__ import annotations

import zipfile
from datetime import datetime, timedelta
from pathlib import Path

from .anr_trace import TraceSection, parse_trace_text

_ANR_PREFIX = "fs/data/anr/"


def read_anr_traces(bugreport_zip: Path) -> list[tuple[str, str]]:
    """bugreport ZIP から /data/anr 配下のトレース本文を返す。"""
    traces: list[tuple[str, str]] = []
    with zipfile.ZipFile(bugreport_zip) as archive:
        for name in archive.namelist():
            if name.lower().startswith(_ANR_PREFIX) and not name.endswith("/"):
                traces.append((name, archive.read(name).decode("utf-8", errors="replace")))
    return traces


def parse_all_sections(traces: list[tuple[str, str]]) -> list[TraceSection]:
    sections: list[TraceSection] = []
    for name, text in traces:
        sections.extend(parse_trace_text(text, name))
    return sections


def select_sections(
    sections: list[TraceSection],
    pid: int,
    package: str,
    window_start: datetime,
    window_end: datetime,
    margin_sec: float,
) -> tuple[list[TraceSection], list[str]]:
    """PID・コマンドライン・時刻窓が全て一致する区間だけを時刻順に返す。除外理由も返す。"""
    margin = timedelta(seconds=margin_sec)
    selected: list[TraceSection] = []
    notes: list[str] = []
    seen: set[tuple[str, int]] = set()
    for section in sections:
        if section.pid != pid:
            continue
        if section.cmdline is not None and not section.cmdline.startswith(package):
            notes.append(f"{section.source}: Cmd line が一致しないため除外 ({section.cmdline})")
            continue
        if section.time < window_start - margin or section.time > window_end + margin:
            notes.append(f"{section.source}: 時刻 {section.time_text} が取得窓の外のため除外")
            continue
        key = (section.time_text, section.pid)
        if key in seen:
            continue
        seen.add(key)
        if section.cmdline is None:
            notes.append(f"{section.source}: Cmd line が無いため PID と時刻のみで採用")
        selected.append(section)
    selected.sort(key=lambda s: s.time)
    return selected, notes
