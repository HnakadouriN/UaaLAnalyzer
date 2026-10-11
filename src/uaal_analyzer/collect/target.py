from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Sequence

from ..adb import Adb
from ..errors import AdbError, TargetError
from .extra import parse_window_focus

_PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.]*")
_APP_USER_RE = re.compile(r"^u\d+_a\d+$")
_FOCUS_PACKAGE_RE = re.compile(r"\bu\d+\s+([A-Za-z][A-Za-z0-9_.]*)/")
_PACKAGE_LINE_RE = re.compile(r"^package:(\S+)", re.MULTILINE)
_NAME_COLUMNS = ("NAME", "CMD", "COMMAND")


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    user: str
    name: str

    @property
    def package(self) -> str:
        return self.name.split(":")[0]


@dataclass
class PackageInfo:
    package: str
    pids: list[int]
    unity_pids: list[int] = field(default_factory=list)
    run_as_denied: bool = False

    def to_dict(self) -> dict:
        status = "run-as 不可" if self.run_as_denied else ("Unity あり" if self.unity_pids else "Unity なし")
        return {"package": self.package, "pids": self.pids, "unity_pids": self.unity_pids, "status": status}


@dataclass
class Target:
    package: str
    pid: int
    # pid-option | package-option | config | foreground | process-list
    method: str
    candidates: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"package": self.package, "pid": self.pid, "method": self.method, "candidates": self.candidates}


def is_valid_package(name: str) -> bool:
    return _PACKAGE_RE.fullmatch(name) is not None


def parse_ps(text: str) -> list[ProcessInfo]:
    """`ps` の出力を行にする。見出し行の列名 (PID / USER / NAME) で位置を決め、最後の列に残りを入れる。"""
    header: list[str] | None = None
    rows: list[ProcessInfo] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if header is None:
            upper = [p.upper() for p in parts]
            name_column = next((c for c in _NAME_COLUMNS if c in upper), None)
            if "PID" in upper and "USER" in upper and name_column and upper.index(name_column) == len(upper) - 1:
                header = upper
            continue
        cells = line.split(None, len(header) - 1)
        if len(cells) < len(header):
            continue
        row = dict(zip(header, cells))
        name_key = next(c for c in _NAME_COLUMNS if c in row)
        if row["PID"].isdigit():
            rows.append(ProcessInfo(int(row["PID"]), row["USER"], row[name_key].strip()))
    return rows


def list_processes(adb: Adb) -> list[ProcessInfo]:
    for command in ("ps -A -o PID,USER,NAME", "ps -A"):
        processes = parse_ps(adb.shell(command, check=False))
        if processes:
            return processes
    return []


def foreground_package(adb: Adb) -> str:
    """フォーカス中のウィンドウのパッケージ名。取れなければ空。"""
    focus = parse_window_focus(adb.shell("dumpsys window", check=False))
    for key in ("mCurrentFocus", "mFocusedWindow", "mFocusedApp"):
        match = _FOCUS_PACKAGE_RE.search(focus.get(key, ""))
        if match:
            return match.group(1)
    return ""


def third_party_packages(adb: Adb) -> set[str] | None:
    """`pm list packages -3` のパッケージ名。取れなければ None (絞り込みをしない)。"""
    names = set(_PACKAGE_LINE_RE.findall(adb.shell("pm list packages -3", check=False)))
    return names or None


def package_pids(adb: Adb, processes: Sequence[ProcessInfo], package: str) -> list[int]:
    """そのパッケージのプロセス (`<pkg>` と `<pkg>:*`)。ps から取れなければ pidof に頼る。"""
    pids = [p.pid for p in processes if p.package == package]
    if pids:
        return pids
    return [int(t) for t in adb.shell(f"pidof {package}", check=False).split() if t.isdigit()]


def inspect_package(adb: Adb, package: str, pids: Sequence[int], main_names: Sequence[str]) -> PackageInfo:
    """各プロセスのスレッド名を run-as で読み、主スレッド (UnityMain) を持つ PID を調べる。"""
    info = PackageInfo(package, list(pids))
    for pid in pids:
        try:
            text = adb.shell(f"run-as {package} sh -c 'cat /proc/{pid}/task/*/comm'", check=False)
        except AdbError:
            info.run_as_denied = True
            break
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if any(line.startswith("run-as:") for line in lines):
            info.run_as_denied = True
            break
        if any(line in main_names for line in lines):
            info.unity_pids.append(pid)
    return info


def resolve_target(
    adb: Adb,
    *,
    package: str = "",
    pid: int | None = None,
    config_package: str = "",
    main_names: Sequence[str] = ("UnityMain",),
    log: Callable[[str], None] = print,
) -> Target:
    """対象のパッケージと PID を決める。指定 > 設定ファイル > 前面のアプリ > 起動中のアプリの順。

    複数の候補があるとき、または見つからないときは、理由と候補を添えて止める。
    """
    if package and not is_valid_package(package):
        raise TargetError(f"--package に使えない文字が含まれています: {package!r}")
    processes = list_processes(adb)

    if pid is not None:
        owner = next((p for p in processes if p.pid == pid), None)
        resolved = package or (owner.package if owner else "")
        if not resolved or not is_valid_package(resolved):
            raise TargetError(f"--pid {pid} のパッケージ名を調べられません。--package も指定してください")
        return Target(resolved, pid, "pid-option", [{"package": resolved, "pids": [pid]}])

    explicit = package or config_package
    if explicit:
        return _resolve_package(adb, explicit, processes, main_names, "package-option" if package else "config")

    log("対象のアプリを自動で検出します")
    candidates: list[PackageInfo] = []
    foreground = foreground_package(adb)
    if foreground and is_valid_package(foreground):
        info = inspect_package(adb, foreground, package_pids(adb, processes, foreground), main_names)
        candidates.append(info)
        if info.unity_pids:
            return _pick_pid(info, "foreground", candidates)
        log(f"前面のアプリ {foreground} は Unity ではありません。起動中のアプリを調べます")

    apps = _app_packages(adb, processes, exclude=foreground)
    for name, pids in apps.items():
        candidates.append(inspect_package(adb, name, pids, main_names))
    unity = [c for c in candidates if c.unity_pids]
    if len(unity) == 1:
        return _pick_pid(unity[0], "process-list", candidates)
    raise TargetError(_failure_message(candidates, unity))


def _app_packages(adb: Adb, processes: Sequence[ProcessInfo], exclude: str) -> dict[str, list[int]]:
    third_party = third_party_packages(adb)
    apps: dict[str, list[int]] = {}
    for process in processes:
        name = process.package
        if not _APP_USER_RE.match(process.user) or name == exclude or not is_valid_package(name):
            continue
        if third_party is not None and name not in third_party:
            continue
        apps.setdefault(name, []).append(process.pid)
    return apps


def _resolve_package(
    adb: Adb, package: str, processes: Sequence[ProcessInfo], main_names: Sequence[str], method: str
) -> Target:
    if not is_valid_package(package):
        raise TargetError(f"パッケージ名に使えない文字が含まれています: {package!r}")
    pids = package_pids(adb, processes, package)
    if not pids:
        raise TargetError(f"{package} のプロセスが見つかりません。アプリが起動しているか確認してください")
    info = inspect_package(adb, package, pids, main_names)
    if info.run_as_denied:
        raise TargetError(
            f"{package} に run-as が使えません。debuggable なビルドか、パッケージ名が正しいか確認してください"
        )
    if info.unity_pids:
        return _pick_pid(info, method, [info])
    if len(pids) == 1:
        note = f"{package} の主スレッド ({', '.join(main_names)}) を確認できなかったため、唯一のプロセス pid={pids[0]} を使います"
        return Target(package, pids[0], method, [info.to_dict()], [note])
    raise TargetError(
        f"{package} のプロセス {pids} のどれにも主スレッド ({', '.join(main_names)}) が見つかりません。--pid で指定してください"
    )


def _pick_pid(info: PackageInfo, method: str, candidates: Sequence[PackageInfo]) -> Target:
    if len(info.unity_pids) != 1:
        raise TargetError(
            f"{info.package} の Unity プロセスが複数あります {info.unity_pids}。--pid で指定してください"
        )
    return Target(info.package, info.unity_pids[0], method, [c.to_dict() for c in candidates])


def _failure_message(candidates: Sequence[PackageInfo], unity: Sequence[PackageInfo]) -> str:
    if len(unity) > 1:
        lines = [f"  - {c.package} (pid {c.unity_pids})" for c in unity]
        return "Unity のアプリが複数見つかりました。--package で指定して実行し直してください:\n" + "\n".join(lines)
    if not candidates:
        return "調べられるアプリのプロセスが見つかりません。アプリを起動して前面に出すか、--package で指定してください"
    lines = [f"  - {c.to_dict()['package']}: {c.to_dict()['status']}" for c in candidates]
    return (
        "Unity のアプリを見つけられませんでした (debuggable で、主スレッドを持つアプリが対象です)。調べた結果:\n"
        + "\n".join(lines)
        + "\n--package で指定してください"
    )
