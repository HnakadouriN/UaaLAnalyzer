from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ..config import Config
from ..model import Frame, ProcSnapshot, Session, ThreadInfo
from ..timeutil import parse_device_time

DEFAULT_HZ = 100


@dataclass
class ThreadAnalysis:
    key: int | str
    name: str
    sys_tid: int | None
    is_main: bool
    samples_seen: int
    samples_total: int
    os_states: list[str]
    art_states: list[str]
    common_len: int
    stuck: bool
    cpu_ticks_delta: int | None
    window_sec: float | None
    cpu_ratio: float | None
    classification: str  # spinning | waiting | mixed | unknown
    frames: list[Frame] = field(default_factory=list)  # 最新サンプル。内側 -> 外側の順
    common_ratio: float = 0.0  # 共通経路の深さ / サンプル中の最大深さ
    # 主スレッドの候補を比べる根拠。
    attached: bool = True  # ART に登録済み (tid がある)
    in_latest_sample: bool = True  # 最新のサンプルに存在する
    unity_player: bool = False  # com.unity3d.player の Java フレームを持つ

    @property
    def common_frames(self) -> list[Frame]:
        if self.common_len <= 0:
            return []
        return self.frames[len(self.frames) - self.common_len :]


def frame_identity(frame: Frame) -> str:
    if frame.resolved:
        return frame.resolved
    if frame.symbol:
        return f"{frame.module_label}:{frame.symbol}"
    return f"{frame.module_label}+0x{frame.pc:x}"


def analyze_threads(session: Session, cfg: Config) -> list[ThreadAnalysis]:
    """全サンプルで外側のフレーム列が一致するスレッドを、CPU 消費と合わせて分類する。"""
    samples = sorted(session.samples, key=lambda s: s.index)
    total = len(samples)
    latest_time = parse_device_time(samples[-1].time) if samples else None
    entries: dict[int | str, list[tuple[datetime, ThreadInfo]]] = {}
    for sample in samples:
        sample_time = parse_device_time(sample.time)
        for thread in sample.threads:
            entries.setdefault(thread.key, []).append((sample_time, thread))

    results: list[ThreadAnalysis] = []
    for key, items in entries.items():
        latest = items[-1][1]
        complete = len(items) == total and total >= 2
        common_len = _common_outer_length([t for _, t in items]) if complete else 0
        depth = max(len(t.frames) for _, t in items)
        common_ratio = common_len / depth if depth else 0.0
        ticks, window, ratio = _cpu(session, items)
        results.append(
            ThreadAnalysis(
                key=key,
                name=latest.name,
                sys_tid=latest.sys_tid,
                is_main=latest.name in cfg.main_thread_names,
                samples_seen=len(items),
                samples_total=total,
                os_states=[t.os_state or "?" for _, t in items],
                art_states=[t.art_state or "?" for _, t in items],
                common_len=common_len,
                stuck=complete and common_len >= cfg.min_common_frames and common_ratio >= cfg.min_common_ratio,
                cpu_ticks_delta=ticks,
                window_sec=window,
                cpu_ratio=ratio,
                classification=_classify(ratio, cfg),
                frames=latest.frames,
                common_ratio=common_ratio,
                attached=latest.tid is not None,
                in_latest_sample=items[-1][0] == latest_time,
                unity_player=any(f.kind == "java" and "com.unity3d.player" in (f.symbol or "") for f in latest.frames),
            )
        )
    return results


def _main_key(thread: ThreadAnalysis) -> tuple[bool, int, bool, bool]:
    return (thread.in_latest_sample, thread.samples_seen, thread.attached, thread.unity_player)


def rank_main_threads(threads: list[ThreadAnalysis]) -> tuple[list[ThreadAnalysis], str, bool]:
    """名前が一致する候補を、最新サンプルでの存在 > 出現サンプル数 > ART 登録 > Unity プレイヤーの順で並べる。

    ここまでで差がつかない候補は CPU 消費で順位を決め、曖昧として報告する。
    """
    candidates = [t for t in threads if t.is_main]
    ordered = sorted(
        candidates,
        key=lambda t: (_main_key(t), t.cpu_ticks_delta if t.cpu_ticks_delta is not None else -1),
        reverse=True,
    )
    if len(ordered) < 2:
        return ordered, "", False
    top, second = ordered[0], ordered[1]
    if _main_key(top) == _main_key(second):
        note = (
            f"主スレッドの候補が {len(ordered)} 件あり、最新サンプルでの存在・出現サンプル数・ART 登録・Unity プレイヤーでは差がつかないため、"
            f"CPU 消費が多い tid {top.sys_tid} を採用しました (曖昧)。"
        )
        return ordered, note, True
    note = (
        f"主スレッドの候補が {len(ordered)} 件あり、tid {top.sys_tid} を採用しました "
        "(最新サンプルでの存在、出現サンプル数、ART 登録、Unity プレイヤーの Java フレームの順で比較)。"
    )
    return ordered, note, False


def _common_outer_length(threads: list[ThreadInfo]) -> int:
    columns = zip(*[[frame_identity(f) for f in reversed(t.frames)] for t in threads])
    length = 0
    for column in columns:
        if all(name == column[0] for name in column):
            length += 1
        else:
            break
    return length


def _classify(ratio: float | None, cfg: Config) -> str:
    if ratio is None:
        return "unknown"
    if ratio >= cfg.busy_ratio:
        return "spinning"
    if ratio <= cfg.idle_ratio:
        return "waiting"
    return "mixed"


def _cpu(
    session: Session, items: list[tuple[datetime, ThreadInfo]]
) -> tuple[int | None, float | None, float | None]:
    first_time, first = items[0]
    last_time, last = items[-1]
    ticks: int | None = None
    window: float | None = (last_time - first_time).total_seconds()
    hz = last.hz or first.hz or DEFAULT_HZ
    if first.cpu_ticks is not None and last.cpu_ticks is not None and len(items) >= 2:
        ticks = last.cpu_ticks - first.cpu_ticks
    elif last.sys_tid is not None:
        proc = _proc_ticks(session.proc_snapshots, last.sys_tid)
        if proc is not None:
            ticks, window = proc
    if ticks is None or window is None or window <= 0:
        return ticks, window, None
    return ticks, window, ticks / (window * hz)


def _proc_ticks(snapshots: list[ProcSnapshot], tid: int) -> tuple[int, float] | None:
    found: list[tuple[datetime, int]] = []
    for snapshot in snapshots:
        if not snapshot.device_time:
            continue
        for thread in snapshot.threads:
            if thread.tid == tid:
                found.append((parse_device_time(snapshot.device_time), thread.utime + thread.stime))
    if len(found) < 2:
        return None
    return found[-1][1] - found[0][1], (found[-1][0] - found[0][0]).total_seconds()
