from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from ..adb import Adb
from ..errors import AdbError

# getprop に渡す固定の項目。利用者の入力は混ぜない。
_PROPS = (
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.fingerprint",
    "ro.build.type",
    "ro.debuggable",
)

_PACKAGE_KEYS = ("versionName", "versionCode", "firstInstallTime", "lastUpdateTime", "pkgFlags")
_MEMINFO_ROWS = {
    "Java Heap": "java_heap_pss",
    "Dalvik Heap": "java_heap_pss",  # 端末によっては Java Heap ではなく Dalvik Heap と出力される
    "Native Heap": "native_heap_pss",
    "Code": "code_pss",
    "Stack": "stack_pss",
    "Graphics": "graphics_pss",
}
_MEMINFO_TOTALS = {
    "TOTAL PSS": "total_pss",
    "TOTAL RSS": "total_rss",
    "TOTAL SWAP PSS": "total_swap_pss",
}
_FOCUS_KEYS = ("mCurrentFocus", "mFocusedApp", "mFocusedWindow")

Warn = Callable[[str], None]


def parse_props(text: str) -> dict[str, str]:
    """`getprop` の `[key]: [value]` 形式を辞書にする。"""
    props: dict[str, str] = {}
    for match in re.finditer(r"^\[(?P<k>[^\]]+)\]:\s*\[(?P<v>.*)\]\s*$", text, re.MULTILINE):
        props[match.group("k")] = match.group("v")
    return props


def parse_package_dump(text: str) -> dict[str, str]:
    """`dumpsys package <pkg>` から版数・更新日時・フラグ (DEBUGGABLE の有無) を抜く。"""
    result: dict[str, str] = {}
    for key in _PACKAGE_KEYS:
        match = re.search(rf"^\s*{key}=(.+?)\s*$", text, re.MULTILINE)
        if match:
            result[key] = match.group(1)
    flags = re.search(r"^\s*pkgFlags=\[(?P<f>[^\]]*)\]", text, re.MULTILINE)
    if flags:
        result["pkgFlags"] = flags.group("f").strip()
        result["debuggable"] = "DEBUGGABLE" in flags.group("f").split()
    return result


def parse_meminfo(text: str) -> dict[str, int]:
    """`dumpsys meminfo <pkg>` から主要な PSS/RSS を kB で取り出す。行頭ラベルの後の最初の数値が PSS。"""
    result: dict[str, int] = {}
    for line in text.splitlines():
        stripped = line.strip()
        for label, key in _MEMINFO_ROWS.items():
            match = re.match(rf"{re.escape(label)}:?\s+(\d[\d,]*)", stripped)
            if match and key not in result:
                result[key] = int(match.group(1).replace(",", ""))
        for label, key in _MEMINFO_TOTALS.items():
            match = re.search(rf"{re.escape(label)}:\s*(\d[\d,]*)", stripped)
            if match and key not in result:
                result[key] = int(match.group(1).replace(",", ""))
    return result


def parse_power_state(text: str) -> dict[str, str]:
    """`dumpsys power` から画面のスリープ状態を拾う。mWakefulness は Awake / Asleep / Dozing。"""
    result: dict[str, str] = {}
    wakefulness = re.search(r"^\s*mWakefulness=(\w+)", text, re.MULTILINE)
    if wakefulness:
        result["mWakefulness"] = wakefulness.group(1)
    display = re.search(r"Display Power: state=(\w+)", text)
    if display:
        result["displayState"] = display.group(1)
    return result


def parse_window_focus(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for key in _FOCUS_KEYS:
        match = re.search(rf"^\s*{key}=(.+?)\s*$", text, re.MULTILINE)
        if match:
            result[key] = match.group(1)
    return result


def parse_surface_layers(text: str, package: str) -> list[str]:
    """SurfaceFlinger のレイヤー名一覧のうち、対象パッケージに関わるものだけを返す。"""
    return [line.strip() for line in text.splitlines() if package in line]


def parse_process_record(text: str, package: str) -> dict[str, str]:
    """`dumpsys activity processes` から対象プロセスの oom_adj 等を抜く。見つからなければ空。"""
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if package in line and "ProcessRecord" in line:
            block = "\n".join(lines[index : index + 40])
            result = {"record": line.strip()}
            for key, pattern in (
                ("state", r"\bstate=([A-Z]+)"),
                ("curAdj", r"\bcurAdj=(-?\d+)"),
                ("setAdj", r"\bsetAdj=(-?\d+)"),
                ("lastPss", r"\blastPss=([\d.]+\w*)"),
            ):
                match = re.search(pattern, block)
                if match:
                    result[key] = match.group(1)
            return result
    return {}


def parse_wchan_listing(text: str) -> dict[str, str]:
    """`tid comm wchan` の行を {tid: wchan} にする。読めなかった行 (エラー文) は空文字にする。"""
    result: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        wchan = parts[2].strip() if len(parts) > 2 else ""
        if wchan in ("0", "") or "denied" in wchan.lower() or "no such" in wchan.lower():
            wchan = ""
        result[parts[0]] = wchan
    return result


def collect_device_info(adb: Adb, package: str, raw_dir: Path, warn: Warn) -> dict:
    """取得の最初に 1 回だけ読む端末・APK・プロセス・画面の情報。各項目は独立して失敗できる。"""
    info: dict = {}

    def read(name: str, command: str, timeout: float = 60) -> str | None:
        try:
            text = adb.shell(command, timeout=timeout)
        except AdbError as exc:
            warn(f"{name} を取得できませんでした: {exc}")
            return None
        (raw_dir / f"{name}.txt").write_text(text, encoding="utf-8")
        return text

    props_text = read("getprop", "getprop")
    if props_text is not None:
        props = parse_props(props_text)
        info["props"] = {k: props[k] for k in _PROPS if k in props}
    package_text = read("dumpsys_package", f"dumpsys package {package}")
    if package_text is not None:
        info["package"] = parse_package_dump(package_text)
    window_text = read("dumpsys_window", "dumpsys window")
    if window_text is not None:
        info["window"] = parse_window_focus(window_text)
    power_text = read("dumpsys_power", "dumpsys power")
    if power_text is not None:
        info["power"] = parse_power_state(power_text)
    surface_text = read("surfaceflinger_list", "dumpsys SurfaceFlinger --list")
    if surface_text is not None:
        info["layers"] = parse_surface_layers(surface_text, package)
    process_text = read("dumpsys_activity_processes", "dumpsys activity processes", timeout=120)
    if process_text is not None:
        info["process"] = parse_process_record(process_text, package)
    return info


def collect_wchan(adb: Adb, package: str, pid: int) -> dict[str, str]:
    """スレッドごとのカーネル待機場所。読めないスレッドは空文字。"""
    command = (
        f"run-as {package} sh -c 'for t in /proc/{pid}/task/*; do "
        'echo "$(basename $t) $(cat $t/comm 2>/dev/null) $(cat $t/wchan 2>&1)"; done\''
    )
    return parse_wchan_listing(adb.shell(command, check=False))


def collect_meminfo(adb: Adb, package: str) -> dict[str, int]:
    return parse_meminfo(adb.shell(f"dumpsys meminfo {package}", check=False, timeout=60))
