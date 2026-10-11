from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

MAX_LOG_LINES = 200
MAX_KERNEL_LINES = 40
MAX_MEMINFO_LINES = 60

_SECTION_RE = re.compile(r"^------ (?P<name>.+?)(?: \((?P<cmd>.*)\))? ------\s*$")
# logcat -v threadtime -v uid: "MM-DD HH:MM:SS.mmm  UID  PID  TID P TAG: message"
_LOGCAT_RE = re.compile(
    r"^(?P<date>\d\d-\d\d)\s+(?P<time>\d\d:\d\d:\d\d\.\d+)\s+(?P<uid>\S+)\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+"
    r"(?P<level>[VDIWEFS])\s+(?P<tag>.*?)\s*:\s?(?P<message>.*)$"
)
_KERNEL_KEYWORDS = re.compile(r"lowmemory|lmkd|oom|killed|thermal|throttl|out of memory", re.IGNORECASE)
_MEMINFO_BLOCK_RE = re.compile(r"^\*\* MEMINFO in pid (?P<pid>\d+) \[(?P<pkg>[^\]]+)\] \*\*")
# このツールが送る SIGQUIT に対する ART の自己応答。調べたい「止まる前のアプリの動き」を押し出すため表示から外す。
_SELF_SIGNAL_PATTERNS = (
    re.compile(r"reacting to signal 3"),
    re.compile(r"^sched_get(scheduler|param)\(\d+.*No such process"),
    re.compile(r"^Wrote stack traces to tombstoned"),
)


@dataclass
class LogEntry:
    time: str  # "MM-DD HH:MM:SS.mmm"
    pid: int
    tid: int
    level: str
    tag: str
    message: str


def is_self_signal_log(entry: LogEntry) -> bool:
    """SIGQUIT 応答のログか。空メッセージは Signal Catcher の直後に必ず出る区切り行。"""
    return entry.message.strip() == "" or any(p.search(entry.message) for p in _SELF_SIGNAL_PATTERNS)


@dataclass
class BugreportExtract:
    logs: list[LogEntry] = field(default_factory=list)
    log_total: int = 0
    log_range: dict[str, str] = field(default_factory=dict)
    self_signal_count: int = 0
    kernel_lines: list[str] = field(default_factory=list)
    meminfo_block: list[str] = field(default_factory=list)
    system_meminfo: dict[str, int] = field(default_factory=dict)
    thermal_lines: list[str] = field(default_factory=list)
    unity_log_count: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "logs": [vars(e) for e in self.logs],
            "log_total": self.log_total,
            "log_range": self.log_range,
            "self_signal_count": self.self_signal_count,
            "unity_log_count": self.unity_log_count,
            "kernel_lines": self.kernel_lines,
            "meminfo_block": self.meminfo_block,
            "system_meminfo": self.system_meminfo,
            "thermal_lines": self.thermal_lines,
        }


def read_main_report(bugreport_zip: Path) -> str | None:
    """ZIP 内で最大の dumpstate テキスト (bugreport-*.txt) を返す。"""
    with zipfile.ZipFile(bugreport_zip) as archive:
        candidates = [
            info
            for info in archive.infolist()
            if "/" not in info.filename and info.filename.lower().endswith(".txt") and info.filename.startswith("bugreport")
        ]
        if not candidates:
            return None
        main = max(candidates, key=lambda i: i.file_size)
        return archive.read(main).decode("utf-8", errors="replace")


def split_sections(text: str) -> dict[str, list[str]]:
    """`------ 名前 (コマンド) ------` 見出しごとに本文の行を分ける。同名は後のものを別名にして残す。"""
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in text.splitlines():
        match = _SECTION_RE.match(line)
        if match:
            name = match.group("name")
            key = name
            suffix = 2
            while key in sections:
                key = f"{name}#{suffix}"
                suffix += 1
            current = sections[key] = []
            continue
        if current is not None:
            current.append(line)
    return sections


def parse_logcat_line(line: str) -> LogEntry | None:
    match = _LOGCAT_RE.match(line)
    if not match:
        return None
    return LogEntry(
        time=f"{match.group('date')} {match.group('time')}",
        pid=int(match.group("pid")),
        tid=int(match.group("tid")),
        level=match.group("level"),
        tag=match.group("tag"),
        message=match.group("message"),
    )


def _logcat_section(sections: dict[str, list[str]]) -> list[str] | None:
    for name, lines in sections.items():
        if name.startswith("SYSTEM LOG") and "#" not in name:
            return lines
    for name, lines in sections.items():
        if name.startswith("SYSTEM LOG"):
            return lines
    return None


def _parse_meminfo_blocks(lines: list[str], pid: int) -> list[str]:
    """`** MEMINFO in pid N [pkg] **` から次のブロック開始 (または上限行) までを返す。見出し名に依存しない。"""
    block: list[str] = []
    collecting = False
    for line in lines:
        match = _MEMINFO_BLOCK_RE.match(line.strip())
        if match:
            if collecting:
                break
            collecting = int(match.group("pid")) == pid
        if collecting:
            block.append(line)
            if len(block) >= MAX_MEMINFO_LINES:
                break
    return block


def _system_meminfo(lines: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in lines:
        match = re.match(r"^(MemTotal|MemFree|MemAvailable|Cached|SwapTotal|SwapFree):\s+(\d+) kB", line)
        if match and match.group(1) not in result:
            result[match.group(1)] = int(match.group(2))
    return result


def extract_from_report(
    text: str, pid: int, window_end: datetime, margin_sec: float = 60
) -> BugreportExtract:
    """対象 PID の直近ログと、メモリ・カーネルログ・熱の関連行を抜く。見つからない節は警告に残して続行する。"""
    result = BugreportExtract()
    sections = split_sections(text)

    logcat = _logcat_section(sections)
    if logcat is None:
        result.warnings.append("bugreport に SYSTEM LOG セクションがありません")
    else:
        _fill_logs(result, logcat, pid, window_end, margin_sec)

    kernel = next((lines for name, lines in sections.items() if name.startswith("KERNEL LOG")), None)
    if kernel is None:
        result.warnings.append("bugreport に KERNEL LOG セクションがありません")
    else:
        result.kernel_lines = [l for l in kernel if _KERNEL_KEYWORDS.search(l)][:MAX_KERNEL_LINES]

    meminfo_lines: list[str] = []
    for lines in sections.values():
        meminfo_lines.extend(lines)
    result.meminfo_block = _parse_meminfo_blocks(meminfo_lines, pid)
    if not result.meminfo_block:
        result.warnings.append(f"bugreport に pid={pid} の MEMINFO ブロックがありません")

    memory = next((lines for name, lines in sections.items() if name.startswith("MEMORY INFO")), None)
    if memory is not None:
        result.system_meminfo = _system_meminfo(memory)

    thermal: list[str] = []
    for name, lines in sections.items():
        if "THERMAL" in name.upper():
            thermal.extend(l for l in lines if l.strip())
    result.thermal_lines = thermal[:MAX_KERNEL_LINES]
    return result


def _fill_logs(
    result: BugreportExtract,
    logcat: list[str],
    pid: int,
    window_end: datetime,
    margin_sec: float,
) -> None:
    """取得終了時刻より前の対象 PID のログを、新しい側から MAX_LOG_LINES 件残す。

    人が「止まった」と判断してから起動するため、止まる直前のログは取得窓よりディレイをおいて前にある。そのため窓の開始では切らない。
    logcat には年が無いため、取得窓の年を使う (年またぎの取得は対象外)。
    """
    year = window_end.year
    high = window_end + timedelta(seconds=margin_sec)
    selected: list[LogEntry] = []
    first = last = ""
    for line in logcat:
        entry = parse_logcat_line(line)
        if entry is None:
            continue
        if not first:
            first = entry.time
        last = entry.time
        if entry.pid != pid:
            continue
        result.log_total += 1
        if entry.tag == "Unity":
            result.unity_log_count += 1
        try:
            logged_at = datetime.strptime(f"{year}-{entry.time}", "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=window_end.tzinfo)
        except ValueError:
            continue
        if logged_at <= high:
            if is_self_signal_log(entry):
                result.self_signal_count += 1
            else:
                selected.append(entry)
    result.logs = selected[-MAX_LOG_LINES:]
    result.log_range = {"first": first, "last": last}
    if result.log_total == 0:
        result.warnings.append(f"SYSTEM LOG に pid={pid} のログがありません")
