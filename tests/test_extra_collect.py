from __future__ import annotations

import subprocess
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from uaal_analyzer.adb import Adb
from uaal_analyzer.collect.bugreport_sections import (
    MAX_LOG_LINES,
    extract_from_report,
    parse_logcat_line,
    read_main_report,
    split_sections,
)
from uaal_analyzer.collect.extra import (
    collect_device_info,
    collect_meminfo,
    collect_wchan,
    parse_meminfo,
    parse_package_dump,
    parse_power_state,
    parse_process_record,
    parse_props,
    parse_surface_layers,
    parse_wchan_listing,
    parse_window_focus,
)
from uaal_analyzer.errors import AdbError

JST = timezone(timedelta(hours=9))
START = datetime(2026, 10, 8, 16, 46, 48, tzinfo=JST)
END = datetime(2026, 10, 8, 16, 46, 59, tzinfo=JST)
PKG = "com.example.app"

MEMINFO = """Applications Memory Usage (in Kilobytes):
** MEMINFO in pid 13290 [com.example.app] **
                   Pss  Private  Private  SwapPss      Rss
 Native Heap    57780    57600        0     1200    58736
 Dalvik Heap     5337     5200        0      100    11228
        Stack      740      740        0        0      760
     Graphics    38932    38932        0        0    38936
         Code   113468    40000        0        0   202856
        TOTAL PSS:   578162            TOTAL RSS:   669316       TOTAL SWAP PSS:   230654
"""

REPORT = f"""========================================================
== dumpstate: 2026-10-08 16:47:01
========================================================
------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------
--------- beginning of main
10-08 16:40:00.000  1000  1672  1711 I ActivityManager: Start proc 13290:{PKG}/u0a273
10-08 16:46:40.100 10273 13290 13290 I Unity   : early log
10-08 16:46:50.200 10273 13290 21869 W Unity   : Localization init <pending>
10-08 16:46:55.300 10273 13290 21869 E AndroidRuntime: boom & <crash>
10-08 16:46:56.000 10099  5555  5555 I Other   : not our pid
10-08 17:30:00.000 10273 13290 13290 I Unity   : far in the future
------ EVENT LOG (logcat -b events -v threadtime -v printable -v uid -d *:v) ------
10-08 16:46:50.000  1000  1000  1000 I am_proc_start: [0]
------ KERNEL LOG (dmesg) ------
[ 100.000] lowmemorykiller: Kill 'x' to free
[ 101.000] some other line
[ 102.000] Out of memory: Killed process 99
------ MEMORY INFO (/proc/meminfo) ------
MemTotal:        3888000 kB
MemFree:           54000 kB
MemAvailable:    1195000 kB
------ DUMPSYS MEMINFO (dumpsys meminfo -a) ------
{MEMINFO}
"""


def test_parse_logcat_line_handles_threadtime_with_uid():
    entry = parse_logcat_line("10-08 16:46:50.200 10273 13290 21869 W Unity   : Localization init <pending>")

    assert entry is not None
    assert (entry.time, entry.pid, entry.tid, entry.level, entry.tag) == ("10-08 16:46:50.200", 13290, 21869, "W", "Unity")
    assert entry.message == "Localization init <pending>"
    assert parse_logcat_line("--------- beginning of main") is None


def test_split_sections_keeps_duplicate_names():
    sections = split_sections("------ A (cmd) ------\n1\n------ A (cmd) ------\n2\n------ B ------\n3\n")

    assert list(sections) == ["A", "A#2", "B"]
    assert sections["A#2"] == ["2"]


def test_extract_hides_sigquit_self_responses_so_app_logs_stay_visible():
    signal_lines = "".join(
        f"10-08 16:46:{sec:02d}.100 10273 13290 14009 I com.example.app: {message}\n"
        for sec, message in (
            (51, 'Thread[3,tid=14009,WaitingInMainSignalCatcherLoop,"Signal Catcher"]: reacting to signal 3'),
            (51, ""),
            (51, "sched_getscheduler(14077): No such process"),
            (51, "sched_getparam(14077, &sp): No such process"),
            (52, "Wrote stack traces to tombstoned"),
        )
    )
    report = (
        "------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------\n"
        "10-08 16:46:50.000 10273 13290 21869 W Unity   : app log before the signal\n"
        f"{signal_lines}"
    )

    extract = extract_from_report(report, 13290, END)

    assert [e.message for e in extract.logs] == ["app log before the signal"]
    assert extract.self_signal_count == 5
    assert extract.log_total == 6


def test_extract_keeps_real_app_logs_that_only_resemble_signal_text():
    report = (
        "------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------\n"
        "10-08 16:46:50.000 10273 13290 21869 E Unity   : sched_getscheduler failed in game code\n"
        "10-08 16:46:51.000 10273 13290 21869 I Unity   : Wrote save data\n"
    )

    extract = extract_from_report(report, 13290, END)

    assert [e.message for e in extract.logs] == ["sched_getscheduler failed in game code", "Wrote save data"]
    assert extract.self_signal_count == 0


def test_extract_keeps_target_pid_logs_before_the_capture_window_and_drops_the_future():
    # 人が停止と判断してから起動するため、止まる直前のログは取得窓より前にある。
    extract = extract_from_report(REPORT, 13290, END, margin_sec=60)

    assert [e.message for e in extract.logs] == ["early log", "Localization init <pending>", "boom & <crash>"]
    assert extract.log_total == 4
    assert extract.unity_log_count == 3
    assert extract.log_range == {"first": "10-08 16:40:00.000", "last": "10-08 17:30:00.000"}


def test_extract_keeps_only_the_newest_log_lines_up_to_the_limit():
    lines = "".join(
        f"10-08 16:00:{i % 60:02d}.{i:03d} 10273 13290 1 I Unity   : line {i}\n" for i in range(MAX_LOG_LINES + 30)
    )
    report = "------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------\n" + lines

    extract = extract_from_report(report, 13290, END)

    assert len(extract.logs) == MAX_LOG_LINES
    assert extract.logs[-1].message == f"line {MAX_LOG_LINES + 29}"
    assert extract.logs[0].message == "line 30"


def test_extract_collects_kernel_memory_and_meminfo_block():
    extract = extract_from_report(REPORT, 13290, END)

    assert len(extract.kernel_lines) == 2
    assert extract.system_meminfo == {"MemTotal": 3888000, "MemFree": 54000, "MemAvailable": 1195000}
    assert extract.meminfo_block[0].startswith("** MEMINFO in pid 13290")
    assert extract.warnings == []


def test_extract_finds_meminfo_block_under_a_section_without_meminfo_in_its_heading():
    # 実機の bugreport では `** MEMINFO in pid N [pkg] **` が DUMPSYS HIGH という見出しの下にあった。
    report = (
        "------ DUMPSYS HIGH (dumpsys -t 60 meminfo) ------\n"
        "Applications Memory Usage (in Kilobytes):\n"
        "** MEMINFO in pid 99 [other.app] **\n"
        " Native Heap     1    1    1    1    1\n"
        f"{MEMINFO}"
        "** MEMINFO in pid 5 [another.app] **\n"
        " Native Heap     9    9    9    9    9\n"
    )

    extract = extract_from_report(report, 13290, END)

    assert extract.meminfo_block[0].startswith("** MEMINFO in pid 13290")
    assert all("pid 99" not in line and "pid 5 " not in line for line in extract.meminfo_block)
    assert not any("MEMINFO" in w for w in extract.warnings)


def test_extract_warns_when_sections_are_missing():
    extract = extract_from_report("nothing here\n", 13290, END)

    assert extract.logs == []
    assert any("SYSTEM LOG" in w for w in extract.warnings)
    assert any("KERNEL LOG" in w for w in extract.warnings)
    assert any("MEMINFO" in w for w in extract.warnings)


def test_extract_warns_when_pid_has_no_log():
    extract = extract_from_report(REPORT, 77777, END)

    assert extract.logs == []
    assert any("pid=77777 のログがありません" in w for w in extract.warnings)


def test_read_main_report_picks_largest_root_text(tmp_path):
    path = tmp_path / "b.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("bugreport-x.txt", "BIG" * 100)
        archive.writestr("dumpstate_log.txt", "small")
        archive.writestr("FS/data/anr/trace_00", "x" * 5000)

    assert read_main_report(path) == "BIG" * 100


def test_read_main_report_returns_none_without_dumpstate(tmp_path):
    path = tmp_path / "b.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("other.bin", "x")

    assert read_main_report(path) is None


def test_parse_meminfo_reads_rows_and_totals():
    assert parse_meminfo(MEMINFO) == {
        "native_heap_pss": 57780,
        "java_heap_pss": 5337,
        "stack_pss": 740,
        "graphics_pss": 38932,
        "code_pss": 113468,
        "total_pss": 578162,
        "total_rss": 669316,
        "total_swap_pss": 230654,
    }
    assert parse_meminfo("garbage") == {}


def test_parse_props_package_window_and_layers():
    assert parse_props("[ro.product.model]: [23073RPBFG]\n[ro.debuggable]: [0]\nnoise\n") == {
        "ro.product.model": "23073RPBFG",
        "ro.debuggable": "0",
    }
    package = parse_package_dump(
        "    versionCode=1 minSdk=25\n    versionName=1.0\n    pkgFlags=[ DEBUGGABLE HAS_CODE ]\n"
        "    firstInstallTime=2026-10-08 15:22:06\n    lastUpdateTime=2026-10-08 16:16:02\n"
    )
    assert package["versionName"] == "1.0"
    assert package["debuggable"] is True
    assert package["lastUpdateTime"] == "2026-10-08 16:16:02"
    assert parse_package_dump("pkgFlags=[ HAS_CODE ]")["debuggable"] is False

    window = "  mCurrentFocus=Window{fc9 u0 NotificationShade}\n  mFocusedApp=ActivityRecord{x}\n"
    assert parse_window_focus(window) == {
        "mCurrentFocus": "Window{fc9 u0 NotificationShade}",
        "mFocusedApp": "ActivityRecord{x}",
    }
    layers = parse_surface_layers(f"{PKG}/.MainActivity#1\nStatusBar#2\n{PKG}/.Other#3\n", PKG)
    assert layers == [f"{PKG}/.MainActivity#1", f"{PKG}/.Other#3"]


def test_parse_process_record_extracts_adj():
    text = f"  ProcessRecord{{5fd003 13290:{PKG}/u0a273}}\n    state=TPSL curAdj=0 setAdj=0 lastPss=561MB\n"
    record = parse_process_record(text, PKG)

    assert record["curAdj"] == "0"
    assert record["state"] == "TPSL"
    assert parse_process_record("nothing", PKG) == {}


def test_parse_wchan_listing_blanks_unreadable_entries():
    text = "21869 UnityMain futex_wait_queue\n21864 RenderThread 0\n21870 Vsync cat: Permission denied\nbroken\n"

    assert parse_wchan_listing(text) == {"21869": "futex_wait_queue", "21864": "", "21870": ""}


class FakeShellAdb:
    def __init__(self, fail: set[str] | None = None) -> None:
        self.fail = fail or set()
        self.commands: list[str] = []

    def shell(self, command: str, timeout: float = 60, check: bool = True) -> str:
        self.commands.append(command)
        for key in self.fail:
            if key in command:
                raise AdbError(f"failed: {key}")
        if command == "getprop":
            return "[ro.product.model]: [M]\n[ro.build.fingerprint]: [fp]\n[ro.secret]: [x]\n"
        if command.startswith("dumpsys package"):
            return "versionName=1.0\npkgFlags=[ DEBUGGABLE ]\n"
        if command == "dumpsys window":
            return "mCurrentFocus=Window{a}\n"
        if command == "dumpsys power":
            return "Power Manager State:\n  mWakefulness=Asleep\n  Display Power: state=OFF\n"
        if command.startswith("dumpsys SurfaceFlinger"):
            return f"{PKG}/.Main#1\nOther#2\n"
        if command.startswith("dumpsys activity processes"):
            return f"ProcessRecord{{a 1:{PKG}/u0}}\n state=TOP curAdj=0\n"
        if command.startswith("dumpsys meminfo"):
            return MEMINFO
        if "wchan" in command:
            return "1 UnityMain futex\n"
        raise AssertionError(command)


def test_collect_device_info_reads_fixed_items_and_saves_raw(tmp_path):
    warnings: list[str] = []

    info = collect_device_info(FakeShellAdb(), PKG, tmp_path, warnings.append)

    assert info["props"] == {"ro.product.model": "M", "ro.build.fingerprint": "fp"}
    assert info["package"]["debuggable"] is True
    assert info["window"] == {"mCurrentFocus": "Window{a}"}
    assert info["power"] == {"mWakefulness": "Asleep", "displayState": "OFF"}
    assert info["layers"] == [f"{PKG}/.Main#1"]
    assert info["process"]["curAdj"] == "0"
    assert warnings == []
    assert (tmp_path / "getprop.txt").exists()
    assert (tmp_path / "dumpsys_package.txt").exists()
    assert (tmp_path / "dumpsys_power.txt").exists()


def test_parse_power_state_reads_wakefulness_and_display():
    text = "Power Manager State:\n  mWakefulness=Awake\n  mWakefulnessChanging=false\n  Display Power: state=ON\n"

    assert parse_power_state(text) == {"mWakefulness": "Awake", "displayState": "ON"}
    assert parse_power_state("mWakefulness=Dozing") == {"mWakefulness": "Dozing"}
    assert parse_power_state("nothing") == {}


def test_collect_device_info_continues_when_one_item_fails(tmp_path):
    warnings: list[str] = []

    info = collect_device_info(FakeShellAdb(fail={"dumpsys window"}), PKG, tmp_path, warnings.append)

    assert "window" not in info
    assert info["props"]["ro.product.model"] == "M"
    assert info["layers"] == [f"{PKG}/.Main#1"]
    assert len(warnings) == 1 and "dumpsys_window" in warnings[0]


def test_collect_wchan_and_meminfo_use_package_and_pid():
    adb = FakeShellAdb()

    assert collect_wchan(adb, PKG, 13290) == {"1": "futex"}
    assert collect_meminfo(adb, PKG)["total_pss"] == 578162
    assert f"run-as {PKG} sh -c 'for t in /proc/13290/task/*" in adb.commands[0]
    assert adb.commands[1] == f"dumpsys meminfo {PKG}"


def test_adb_failure_type_is_adb_error_for_real_wrapper():
    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=b"denied")

    with pytest.raises(AdbError):
        Adb("", "adb", runner).shell("dumpsys window")
