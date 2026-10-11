from __future__ import annotations

import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from helpers import PACKAGE, PID, anr_section, stuck_section, stuck_trace, thread_block
from uaal_analyzer.collect.bugreport import parse_all_sections, read_anr_traces, select_sections

JST = timezone(timedelta(hours=9))
WINDOW_START = datetime(2026, 9, 24, 20, 30, 30, tzinfo=JST)
WINDOW_END = datetime(2026, 9, 24, 20, 30, 42, tzinfo=JST)


def _zip(tmp_path, files: dict[str, str]):
    path = tmp_path / "bugreport.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return path


def test_read_anr_traces_only_returns_anr_files(tmp_path):
    path = _zip(
        tmp_path,
        {"FS/data/anr/trace_00": "a", "FS/data/anr/trace_01": "b", "dumpstate.txt": "c", "FS/data/anr/": ""},
    )
    names = sorted(name for name, _ in read_anr_traces(path))
    assert names == ["FS/data/anr/trace_00", "FS/data/anr/trace_01"]


def test_select_excludes_stale_other_pid_and_other_cmdline(tmp_path):
    stale = stuck_section(0, second=0).replace("20:30:00", "19:00:00")
    other_pid = stuck_section(0, pid=1234, cmdline="system_server")
    reused_pid = anr_section(
        PID, "2026-09-24 20:30:36.0+0900", "com.other.app", thread_block("main", 1, PID, "Native", "S", 1, 1, [])
    )
    path = _zip(
        tmp_path,
        {"FS/data/anr/trace_00": stale + other_pid + reused_pid, "FS/data/anr/trace_01": stuck_trace(3)},
    )

    sections = parse_all_sections(read_anr_traces(path))
    selected, notes = select_sections(sections, PID, PACKAGE, WINDOW_START, WINDOW_END, margin_sec=5)

    assert [s.time.second for s in selected] == [35, 37, 39]
    assert any("com.other.app" in n for n in notes)
    assert any("取得窓の外" in n for n in notes)


def test_select_keeps_sections_without_cmdline_and_notes_it():
    text = anr_section(PID, "2026-09-24 20:30:35.0+0900", None, thread_block("main", 1, PID, "Native", "S", 1, 1, []))
    from uaal_analyzer.collect.anr_trace import parse_trace_text

    selected, notes = select_sections(parse_trace_text(text), PID, PACKAGE, WINDOW_START, WINDOW_END, 5)

    assert len(selected) == 1
    assert any("Cmd line が無い" in n for n in notes)


def test_select_deduplicates_same_section_in_multiple_files():
    from uaal_analyzer.collect.anr_trace import parse_trace_text

    one = parse_trace_text(stuck_section(0), "trace_00")
    two = parse_trace_text(stuck_section(0), "trace_01")

    selected, _ = select_sections(one + two, PID, PACKAGE, WINDOW_START, WINDOW_END, 5)

    assert len(selected) == 1


@pytest.mark.parametrize("margin,expected", [(0, 0), (30, 1)])
def test_margin_controls_time_window(margin, expected):
    from uaal_analyzer.collect.anr_trace import parse_trace_text

    sections = parse_trace_text(stuck_section(0, second=50))  # 20:30:50 は窓の終端 (42) より 8 秒後
    selected, _ = select_sections(sections, PID, PACKAGE, WINDOW_START, WINDOW_END, margin)
    assert len(selected) == expected
