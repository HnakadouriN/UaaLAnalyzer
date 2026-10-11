from __future__ import annotations

from datetime import datetime, timedelta, timezone

from helpers import IL2CPP_BUILD_ID, IL2CPP_PATH, LIBC_PATH, PACKAGE, PID, anr_section, native, stuck_trace, thread_block
from uaal_analyzer.collect.anr_trace import parse_trace_text
from uaal_analyzer.collect.proc import parse_proc_stat
from uaal_analyzer.timeutil import parse_device_time


def test_parse_time_with_nanoseconds_and_offset():
    parsed = parse_device_time("2026-09-24 20:30:35.123456789+0900")
    assert parsed == datetime(2026, 9, 24, 20, 30, 35, 123456, tzinfo=timezone(timedelta(hours=9)))


def test_parse_time_from_date_command():
    parsed = parse_device_time("2026-09-24T20:30:30+0900")
    assert parsed.utcoffset() == timedelta(hours=9)


def test_parse_sections_threads_and_frames():
    sections = parse_trace_text(stuck_trace(3), "trace_00")

    assert len(sections) == 3
    section = sections[0]
    assert section.pid == PID
    assert section.cmdline == PACKAGE
    names = [t.name for t in section.threads]
    assert names == ["main", "UnityMain", "Worker", "Binder:8589_1"]

    unity_main = section.threads[1]
    assert unity_main.tid == 12
    assert unity_main.sys_tid == 8620
    assert unity_main.art_state == "Runnable"
    assert unity_main.os_state == "R"
    assert (unity_main.utime, unity_main.stime, unity_main.hz) == (100, 10, 100)
    assert len(unity_main.frames) == 12
    assert unity_main.frames[0].symbol == "syscall"
    assert unity_main.frames[0].offset == 28
    assert unity_main.frames[1].module == IL2CPP_PATH
    assert unity_main.frames[1].build_id == IL2CPP_BUILD_ID
    assert unity_main.frames[1].symbol is None
    assert unity_main.frames[1].pc == 0x1000


def test_parse_native_only_thread_uses_header_sys_tid():
    section = parse_trace_text(stuck_trace(1))[0]
    binder = section.threads[3]
    assert binder.sys_tid == 8640
    assert binder.tid is None
    assert binder.frames[0].symbol == "__ioctl"


def _detached_thread(name: str, sys_tid: int, frame_pc: int) -> str:
    # 実機 (Android 13) の書式: tid を持たず "(not attached)" で終わる見出し。
    return (
        f'"{name}" prio=5 (not attached)\n'
        f"  | sysTid={sys_tid} nice=0 cgrp=top-app\n"
        "  | state=S schedstat=( 1 2 3 ) utm=7 stm=3 core=6 HZ=100\n"
        f"{native(0, frame_pc, LIBC_PATH, 'syscall+28', 'c' * 32)}\n"
    )


def test_parse_not_attached_threads_keep_their_own_frames_and_sys_tid():
    threads = (
        thread_block("UnityMain", 22, 28742, "Native", "S", 10, 5, [native(0, 0x100, IL2CPP_PATH, None, IL2CPP_BUILD_ID)])
        + "\n"
        + _detached_thread("UnityMain", 30548, 0x200)
        + "\n"
        + _detached_thread("GC Finalizer", 28761, 0x300)
    )
    section = parse_trace_text(anr_section(PID, "2026-10-08 19:09:04.0+0900", PACKAGE, threads))[0]

    assert [(t.name, t.tid, t.sys_tid) for t in section.threads] == [
        ("UnityMain", 22, 28742),
        ("UnityMain", None, 30548),
        ("GC Finalizer", None, 28761),
    ]
    assert [len(t.frames) for t in section.threads] == [1, 1, 1]
    assert section.threads[0].frames[0].pc == 0x100  # 未登録スレッドのフレームが直前のスレッドに混ざらない
    assert section.threads[1].frames[0].pc == 0x200
    assert (section.threads[1].utime, section.threads[1].stime) == (7, 3)
    assert section.unknown_headers == []


def test_parse_unknown_thread_header_is_not_merged_into_the_previous_thread():
    threads = (
        thread_block("UnityMain", 22, 28742, "Native", "S", 10, 5, [native(0, 0x100, IL2CPP_PATH, None, IL2CPP_BUILD_ID)])
        + '"Weird" prio=5 something-new\n'
        + "  | sysTid=999 nice=0 cgrp=top-app\n"
        + "  | state=R schedstat=( 1 2 3 ) utm=1 stm=1 core=1 HZ=100\n"
        + f"{native(0, 0x999, LIBC_PATH, 'syscall+28', 'c' * 32)}\n"
    )
    section = parse_trace_text(anr_section(PID, "2026-10-08 19:09:04.0+0900", PACKAGE, threads))[0]

    main = section.threads[0]
    assert [f.pc for f in main.frames] == [0x100]
    assert (main.sys_tid, main.os_state) == (28742, "S")
    assert section.unknown_headers == ['"Weird" prio=5 something-new']


def test_parse_symbol_with_parentheses_and_java_frames():
    threads = thread_block(
        "RenderThread",
        20,
        9000,
        "Native",
        "S",
        1,
        1,
        [
            native(0, 0x10, "/apex/com.android.art/lib64/libart.so", "art::Thread::Run(int, char*)+8"),
            "  at android.os.Looper.loop(Looper.java:299)",
            "  at java.lang.Thread.run(Thread.java:1012)",
        ],
    )
    section = parse_trace_text(anr_section(PID, "2026-09-24 20:30:35.0+0900", PACKAGE, threads))[0]

    frames = section.threads[0].frames
    assert frames[0].symbol == "art::Thread::Run(int, char*)"
    assert frames[0].offset == 8
    assert frames[1].kind == "java"
    assert frames[1].symbol == "android.os.Looper.loop(Looper.java:299)"
    assert frames[2].index == 1


def test_parse_ignores_text_outside_sections_and_other_headers():
    text = "garbage\n----- Waiting Channels: pid 1 at 2026-09-24 20:30:35+0900 -----\n" + stuck_trace(1)
    sections = parse_trace_text(text)
    assert len(sections) == 1


def test_parse_proc_stat_handles_spaces_and_parentheses_in_comm():
    text = (
        "8620 (Unity Main) (x)) R 1 1 1 0 -1 4194560 100 0 5 0 120 30 0 0 20 0\n"
        "8630 (Worker) S 1 1 1 0 -1 4194560 100 0 5 0 7 1 0 0 20 0\n"
        "broken line\n"
    )
    threads = parse_proc_stat(text)

    assert [t.tid for t in threads] == [8620, 8630]
    assert threads[0].comm == "Unity Main) (x)"
    assert (threads[0].state, threads[0].utime, threads[0].stime) == ("R", 120, 30)
    assert (threads[1].utime, threads[1].stime) == (7, 1)


def test_libc_path_constant_is_used_for_other_modules():
    section = parse_trace_text(stuck_trace(1))[0]
    assert section.threads[0].frames[0].module == LIBC_PATH


def test_parse_deleted_jit_cache_mapping_keeps_module_and_method_name():
    line = "  native: #20 pc 0000000000a7aa10  /memfd:jit-cache (deleted) (offset 2000000) (android.os.Looper.loopOnce+364)"
    threads = thread_block("UnityMain", 22, 14031, "Native", "R", 1, 1, [line])

    frame = parse_trace_text(anr_section(PID, "2026-10-08 16:36:02.0+0900", PACKAGE, threads))[0].threads[0].frames[0]

    assert frame.module == "/memfd:jit-cache"
    assert frame.map_offset == 0x2000000
    assert frame.symbol == "android.os.Looper.loopOnce"
    assert frame.offset == 364
    assert frame.build_id is None


APK = "/data/app/~~AAAAAAAAAAAAAAAAAAAAAA==/com.example.app-BBBBBBBBBBBBBBBBBBBBBB==/base.apk"
DEVICE_BUILD_ID = "cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34"


def test_parse_shared_library_stored_in_apk_with_unknown_symbol():
    line = f"  native: #00 pc 0000000005a10054  {APK} (offset f2b0000) (???) (BuildId: {DEVICE_BUILD_ID.upper()})"
    threads = thread_block("UnityMain", 22, 14031, "Native", "R", 1, 1, [line])

    frame = parse_trace_text(anr_section(PID, "2026-10-08 15:28:53.0+0900", PACKAGE, threads))[0].threads[0].frames[0]

    assert frame.module == APK
    assert frame.map_offset == 0xF2B0000
    assert frame.symbol is None
    assert frame.build_id == DEVICE_BUILD_ID
    assert frame.pc == 0x5A10054
    assert frame.display_name() == "base.apk@f2b0000+0x5a10054"


def test_parse_vdex_frame_keeps_method_name_and_offset():
    line = "  native: #42 pc 00000000011d905c  /data/app/~~x==/com.example.app-y==/oat/arm64/base.vdex (com.unity3d.player.U.handleMessage+224)"
    threads = thread_block("UnityMain", 22, 14031, "Native", "R", 1, 1, [line])

    frame = parse_trace_text(anr_section(PID, "2026-10-08 15:28:53.0+0900", PACKAGE, threads))[0].threads[0].frames[0]

    assert frame.map_offset is None
    assert frame.build_id is None
    assert frame.symbol == "com.unity3d.player.U.handleMessage"
    assert frame.offset == 224


def test_same_pc_in_different_apk_libraries_is_distinguished():
    lines = [
        f"  native: #00 pc 0000000000a0a4dc  {APK} (offset 6178000) (???) (BuildId: {'b6' * 20})",
        f"  native: #01 pc 0000000000a0a4dc  {APK} (offset f2b0000) (???) (BuildId: {DEVICE_BUILD_ID})",
    ]
    threads = thread_block("UnityMain", 22, 14031, "Native", "R", 1, 1, lines)

    first, second = parse_trace_text(anr_section(PID, "2026-10-08 15:28:53.0+0900", PACKAGE, threads))[0].threads[0].frames

    from uaal_analyzer.analyze.stuck import frame_identity

    assert frame_identity(first) != frame_identity(second)

