from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Callable

from ..adb import Adb
from ..errors import AdbError, CaptureError
from ..model import ProcSnapshot, Sample, Session, load_session, save_session
from ..timeutil import parse_device_time
from .anr_trace import TraceSection
from .bugreport import parse_all_sections, read_anr_traces, select_sections
from .bugreport_sections import extract_from_report, read_main_report
from .extra import collect_device_info, collect_meminfo, collect_wchan
from .proc import parse_proc_stat

# adb shell に文字列で渡すため、シェルメタ文字を含む名前は受け付けない。
_PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.]*")


@dataclass
class CaptureOptions:
    package: str
    serial: str = ""
    pid: int | None = None
    samples: int = 5
    interval_sec: float = 2.0
    bugreport_timeout_sec: int = 900
    time_margin_sec: int = 30
    # 自動検出した対象 (選んだ方法と候補) と、session.json の警告に残す注記。
    target: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def run_capture(
    adb: Adb,
    options: CaptureOptions,
    session_dir: Path,
    session_id: str,
    log: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Session:
    """run-as で SIGQUIT を N 回送り、最後に bugreport を 1 回だけ回収して session.json を作る。"""
    package = options.package
    if not package:
        raise CaptureError("device.package が未設定です (設定ファイルの [device] package)")
    if not _PACKAGE_RE.fullmatch(package):
        raise CaptureError(f"device.package に使えない文字が含まれています: {package!r}")
    raw_dir = session_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = list(options.notes)
    phase_sec: dict[str, float] = {}
    lap_started = clock()
    log("進捗: 準備")

    def lap(name: str) -> None:
        nonlocal lap_started
        now = clock()
        phase_sec[name] = round(now - lap_started, 3)
        lap_started = now

    _verify_run_as(adb, package)
    pid = options.pid if options.pid is not None else _find_pid(adb, package)
    log(f"対象: {package} pid={pid}")
    lap("prepare")

    log("進捗: 端末情報")
    device = collect_device_info(adb, package, raw_dir, warnings.append)
    lap("device_info")
    window_start = _device_time(adb)
    snapshots: list[ProcSnapshot] = []
    log(f"進捗: サンプル取得 0/{options.samples}")
    for index in range(options.samples):
        started = clock()
        snapshot = _snapshot(adb, package, pid, index, raw_dir, warnings, clock)
        snapshots.append(snapshot)
        sigquit_started = clock()
        try:
            adb.shell(f"run-as {package} kill -3 {pid}")
        except AdbError as exc:
            raise CaptureError(f"SIGQUIT を送れません。プロセスが終了した可能性があります: {exc}") from exc
        snapshot.timings["sigquit"] = _elapsed(clock, sigquit_started)
        log(f"SIGQUIT 送信 {index + 1}/{options.samples}")
        log(f"進捗: サンプル取得 {index + 1}/{options.samples}")
        sleep(options.interval_sec)
        snapshot.timings["sample_total"] = _elapsed(clock, started)
    window_end = _device_time(adb)
    lap("sampling")

    bugreport_path = raw_dir / "bugreport.zip"
    log("進捗: bugreport")
    log("bugreport を取得中 (数分かかることがあります)")
    adb.bugreport(bugreport_path, options.bugreport_timeout_sec, progress=_bugreport_reporter(log))
    lap("bugreport")

    log("進捗: トレース解析")

    sections = parse_all_sections(read_anr_traces(bugreport_path))
    selected, notes = select_sections(sections, pid, package, window_start, window_end, options.time_margin_sec)
    warnings.extend(notes)
    warnings.extend(_header_warnings(selected))
    if not selected:
        raise CaptureError(
            f"bugreport に pid={pid} のトレースが見つかりません (取得窓 {window_start.isoformat()} - {window_end.isoformat()})。"
            f" 生データ: {bugreport_path}"
        )
    if len(selected) != options.samples:
        warnings.append(f"送信 {options.samples} 回に対し、抽出されたトレースは {len(selected)} 件です")

    samples = _to_samples(selected)
    session = Session(
        session_id=session_id,
        package=package,
        serial=options.serial,
        pid=pid,
        created_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        capture={
            "samples": options.samples,
            "interval_sec": options.interval_sec,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
        },
        samples=samples,
        proc_snapshots=snapshots,
        warnings=warnings,
        device=device,
    )
    session.logs = _extract_logs(bugreport_path, pid, window_end, session.warnings)
    lap("parse")
    session.capture["phase_sec"] = phase_sec
    if options.target:
        session.capture["target"] = options.target
    save_session(session_dir / "session.json", session)
    return session


def _bugreport_reporter(log: Callable[[str], None]) -> Callable[[int | None, float], None]:
    """bugreport の進み具合を `進捗:` 行にする。割合が同じなら繰り返して出さない。"""
    last: list[int | None] = [-1]

    def report(percent: int | None, elapsed: float) -> None:
        if percent is None:
            log(f"進捗: bugreport 経過 {int(elapsed)}秒")
        elif percent != last[0]:
            log(f"進捗: bugreport {percent}%")
        last[0] = percent

    return report


def _header_warnings(sections: list[TraceSection]) -> list[str]:
    """読めないスレッド見出しがあった区間を警告にする (直後のスタックは無視している)。"""
    return [
        f"{section.source} ({section.time_text}): 読めないスレッド見出しが {len(section.unknown_headers)} 件あり、"
        f"直後のスタックは無視しました (例: {section.unknown_headers[0]})"
        for section in sections
        if section.unknown_headers
    ]


def _extract_logs(bugreport_path: Path, pid: int, end: datetime, warnings: list[str]) -> dict:
    """bugreport からログ・カーネルログ・メモリを抽出する。失敗しても取得全体は止めない。"""
    try:
        text = read_main_report(bugreport_path)
    except (OSError, ValueError) as exc:
        warnings.append(f"bugreport 本体を読めませんでした: {exc}")
        return {}
    if text is None:
        warnings.append("bugreport に dumpstate 本体 (bugreport-*.txt) がありません")
        return {}
    extract = extract_from_report(text, pid, end)
    warnings.extend(extract.warnings)
    return extract.to_dict()


def _to_samples(sections: list[TraceSection]) -> list[Sample]:
    return [
        Sample(
            index=i,
            time=section.time.isoformat(),
            pid=section.pid,
            cmdline=section.cmdline,
            source=section.source,
            threads=section.threads,
        )
        for i, section in enumerate(sections)
    ]


def _is_capture_time_warning(warning: str) -> bool:
    """端末から読んだ時点の失敗は rebuild では再現できないため、元の警告を引き継ぐ。"""
    return any(marker in warning for marker in ("/proc", "取得できません", "が空でした", "端末の時刻"))


def rebuild_session(session_dir: Path, time_margin_sec: int) -> Session:
    """保存済みの raw/bugreport.zip を再解析して session.json を作り直す (パーサー修正後の再解析用)。"""
    old = load_session(session_dir / "session.json")
    bugreport_path = session_dir / "raw" / "bugreport.zip"
    if not bugreport_path.exists():
        raise CaptureError(f"生データがありません: {bugreport_path}")
    try:
        window_start = parse_device_time(old.capture["window_start"])
        window_end = parse_device_time(old.capture["window_end"])
    except (KeyError, ValueError) as exc:
        raise CaptureError(f"session.json の取得窓を読めません: {exc}") from exc

    sections = parse_all_sections(read_anr_traces(bugreport_path))
    selected, notes = select_sections(sections, old.pid, old.package, window_start, window_end, time_margin_sec)
    if not selected:
        raise CaptureError(f"bugreport に pid={old.pid} のトレースが見つかりません: {bugreport_path}")
    warnings = [w for w in old.warnings if _is_capture_time_warning(w)] + notes + _header_warnings(selected)
    expected = old.capture.get("samples")
    if expected and len(selected) != expected:
        warnings.append(f"送信 {expected} 回に対し、抽出されたトレースは {len(selected)} 件です")
    logs = _extract_logs(bugreport_path, old.pid, window_end, warnings)
    session = replace(old, samples=_to_samples(selected), warnings=warnings, symbol_report={}, logs=logs)
    save_session(session_dir / "session.json", session)
    return session


def _verify_run_as(adb: Adb, package: str) -> None:
    try:
        adb.shell(f"run-as {package} id")
    except AdbError as exc:
        raise CaptureError(
            f"run-as が使えません。debuggable なビルドか、パッケージ名が正しいか確認してください: {exc}"
        ) from exc


def _find_pid(adb: Adb, package: str) -> int:
    output = adb.shell(f"pidof {package}", check=False).split()
    pids = [int(p) for p in output if p.isdigit()]
    if not pids:
        raise CaptureError(f"プロセスが見つかりません: {package}")
    if len(pids) > 1:
        raise CaptureError(f"PID が複数あります {pids}。--pid で指定してください")
    return pids[0]


def _device_time(adb: Adb) -> datetime:
    text = adb.shell("date +%Y-%m-%dT%H:%M:%S%z").strip()
    try:
        return parse_device_time(text)
    except ValueError as exc:
        raise CaptureError(f"端末の時刻を取得できません: {text!r}") from exc


def _elapsed(clock: Callable[[], float], started: float) -> float:
    return round(clock() - started, 3)


def _snapshot(
    adb: Adb,
    package: str,
    pid: int,
    index: int,
    raw_dir: Path,
    warnings: list[str],
    clock: Callable[[], float] = time.monotonic,
) -> ProcSnapshot:
    timings: dict[str, float] = {}
    try:
        device_time = _device_time(adb).isoformat()
    except CaptureError as exc:
        warnings.append(str(exc))
        device_time = ""
    step = clock()
    top_text = adb.shell(f"top -H -b -n 1 -p {pid}", check=False)
    (raw_dir / f"top_{index:02d}.txt").write_text(top_text, encoding="utf-8")
    timings["top"] = _elapsed(clock, step)
    step = clock()
    stat_text = adb.shell(f"run-as {package} sh -c 'cat /proc/{pid}/task/*/stat'", check=False)
    (raw_dir / f"stat_{index:02d}.txt").write_text(stat_text, encoding="utf-8")
    threads = parse_proc_stat(stat_text)
    if not threads:
        warnings.append(f"/proc の thread stat を取得できませんでした (sample {index})")
    timings["stat"] = _elapsed(clock, step)
    step = clock()
    wchan = _best_effort(lambda: collect_wchan(adb, package, pid), {}, f"wchan (sample {index})", warnings)
    timings["wchan"] = _elapsed(clock, step)
    step = clock()
    meminfo = _best_effort(lambda: collect_meminfo(adb, package), {}, f"dumpsys meminfo (sample {index})", warnings)
    timings["meminfo"] = _elapsed(clock, step)
    return ProcSnapshot(
        index=index, device_time=device_time, threads=threads, wchan=wchan, meminfo=meminfo, timings=timings
    )


def _best_effort(action: Callable[[], dict], default: dict, name: str, warnings: list[str]) -> dict:
    """補助情報の取得。失敗しても警告にとどめ、取得全体は止めない。"""
    try:
        result = action()
    except AdbError as exc:
        warnings.append(f"{name} を取得できませんでした: {exc}")
        return default
    if not result:
        warnings.append(f"{name} が空でした")
    return result
