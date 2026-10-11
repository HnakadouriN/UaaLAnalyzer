from __future__ import annotations

from pathlib import Path

from uaal_analyzer.collect.anr_trace import parse_trace_text
from uaal_analyzer.model import Sample, Session
from uaal_analyzer.symbolize.resolver import ResolvedSymbol
from uaal_analyzer.symbols.store import SymbolStore

PACKAGE = "com.example.app"
PID = 8589
IL2CPP_BUILD_ID = "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"
LIBC_BUILD_ID = "0123456789abcdef0123456789abcdef01234567"
UNITY_BUILD_ID = "aa" * 20
IL2CPP_PATH = "/data/app/~~abc==/com.example.app-xyz==/lib/arm64/libil2cpp.so"
LIBC_PATH = "/apex/com.android.runtime/lib64/bionic/libc.so"
UNITY_PATH = "/data/app/~~abc==/com.example.app-xyz==/lib/arm64/libunity.so"
APK_PATH = "/data/app/~~abc==/com.example.app-xyz==/base.apk"
# 名前もシンボルも分からない、APK 内に非圧縮で格納された共有ライブラリのフレーム (実機の書式)。
APK_UNNAMED_LINE = f"  native: #00 pc 0000000000a0a4dc  {APK_PATH} (offset 420c000) (???) (BuildId: {'7147' * 10})"

PC_NAMES = {
    0x1000: "ResourceManager_Update",
    0x1010: "ResourceManager_Update",
    0x1020: "ResourceManager_Update",
    0x2000: "AsyncOperationBase_WaitForCompletion",
    0x3000: "ModeProvider_get_Modes",
    0x4000: "SettingsManager_OnModeChanged",
    0x5000: "BasePanel_TryLoadAsync",
}
GENERATED = "C:/build/unityLibrary/src/main/Il2CppOutputProject/Source/il2cppOutput/"
PC_FILES = {
    0x1000: GENERATED + "Unity.ResourceManager.cpp",
    0x1010: GENERATED + "Unity.ResourceManager.cpp",
    0x1020: GENERATED + "Unity.ResourceManager.cpp",
    0x2000: GENERATED + "Unity.ResourceManager.cpp",
    0x3000: GENERATED + "Unity.Localization.cpp",
    0x4000: GENERATED + "Contoso.App.Presentation__1.cpp",
    0x5000: GENERATED + "Contoso.App.Presentation__1.cpp",
}


def native(index: int, pc: int, path: str, symbol: str | None = None, build_id: str | None = None) -> str:
    sym = f" ({symbol})" if symbol else ""
    bid = f" (BuildId: {build_id})" if build_id else ""
    return f"  native: #{index:02d} pc {pc:016x}  {path}{sym}{bid}"


def thread_block(
    name: str,
    tid: int,
    sys_tid: int,
    art_state: str,
    os_state: str,
    utm: int,
    stm: int,
    frames: list[str],
) -> str:
    header = [
        f'"{name}" prio=5 tid={tid} {art_state}',
        '  | group="main" sCount=0 ucsCount=0 flags=0 obj=0x1 self=0x2',
        f"  | sysTid={sys_tid} nice=-8 cgrp=top-app sched=0/0 handle=0x3",
        f"  | state={os_state} schedstat=( 1 2 3 ) utm={utm} stm={stm} core=3 HZ=100",
        "  | stack=0x4-0x5 stackSize=1039KB",
        "  | held mutexes=",
    ]
    return "\n".join(header + frames) + "\n"


def unity_main_frames(k: int) -> list[str]:
    inner = [("syscall", 28), ("clock_gettime", 12), ("nanosleep", 8)][k % 3]
    return [
        native(0, 0x9A1B4, LIBC_PATH, f"{inner[0]}+{inner[1]}", LIBC_BUILD_ID),
        native(1, 0x1000 + 0x10 * k, IL2CPP_PATH, None, IL2CPP_BUILD_ID),
        native(2, 0x2000, IL2CPP_PATH, None, IL2CPP_BUILD_ID),
        native(3, 0x3000, IL2CPP_PATH, None, IL2CPP_BUILD_ID),
        native(4, 0x4000, IL2CPP_PATH, None, IL2CPP_BUILD_ID),
        native(5, 0x5000, IL2CPP_PATH, None, IL2CPP_BUILD_ID),
        native(6, 0x100, UNITY_PATH, None, UNITY_BUILD_ID),
        native(7, 0x200, UNITY_PATH, None, UNITY_BUILD_ID),
        native(8, 0x300, UNITY_PATH, None, UNITY_BUILD_ID),
        native(9, 0x4583, LIBC_PATH, "art_quick_invoke_stub+556", LIBC_BUILD_ID),
        native(10, 0xF55C8, LIBC_PATH, "__pthread_start(void*)+208", LIBC_BUILD_ID),
        native(11, 0x5A000, LIBC_PATH, "__start_thread+64", LIBC_BUILD_ID),
    ]


def anr_section(pid: int, time_text: str, cmdline: str | None, threads: str) -> str:
    cmd = f"Cmd line: {cmdline}\n" if cmdline is not None else ""
    return f"----- pid {pid} at {time_text} -----\n{cmd}\nDALVIK THREADS (3):\n{threads}\n----- end {pid} -----\n"


def stuck_section(k: int, pid: int = PID, cmdline: str | None = PACKAGE, second: int = 35, step: int = 2) -> str:
    time_text = f"2026-09-24 20:30:{second + step * k:02d}.123456789+0900"
    threads = "".join(
        [
            thread_block("main", 1, pid, "Native", "S", 50, 5, [native(0, 0x1234, LIBC_PATH, "epoll_wait+8", LIBC_BUILD_ID)]),
            thread_block("UnityMain", 12, 8620, "Runnable", "R", 100 + 200 * k, 10 + 10 * k, unity_main_frames(k)),
            thread_block("Worker", 15, 8630, "Waiting", "S", 7, 1, unity_main_frames(0)[1:]),
            '"Binder:8589_1" sysTid=8640\n' + native(0, 0x20, LIBC_PATH, "__ioctl+4", LIBC_BUILD_ID) + "\n",
        ]
    )
    return anr_section(pid, time_text, cmdline, threads)


def stuck_trace(count: int = 3) -> str:
    return "".join(stuck_section(k) for k in range(count))


def make_session(trace_text: str, source: str = "FS/data/anr/trace_00") -> Session:
    sections = parse_trace_text(trace_text, source)
    samples = [
        Sample(index=i, time=s.time.isoformat(), pid=s.pid, cmdline=s.cmdline, source=s.source, threads=s.threads)
        for i, s in enumerate(sections)
    ]
    return Session(
        session_id="test",
        package=PACKAGE,
        serial="",
        pid=PID,
        created_at="2026-09-24T20:31:00+09:00",
        samples=samples,
    )


def make_store(tmp_path: Path, build_id: str = IL2CPP_BUILD_ID) -> SymbolStore:
    source = tmp_path / "src" / "libil2cpp.dbg.so"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"fake-elf")
    store = SymbolStore(tmp_path / "symbols")
    store.add(source, build_id)
    return store


class FakeResolver:
    def __init__(self) -> None:
        self.calls: list[tuple[Path, list[int]]] = []

    def resolve(self, symbol_file: Path, addresses: list[int]) -> dict[int, ResolvedSymbol]:
        self.calls.append((symbol_file, list(addresses)))
        return {a: ResolvedSymbol(PC_NAMES[a], PC_FILES.get(a)) for a in addresses if a in PC_NAMES}
