from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

SCHEMA_VERSION = 4
SUPPORTED_SCHEMA_VERSIONS = (1, 2, 3, SCHEMA_VERSION)


@dataclass
class Frame:
    index: int
    kind: str  # "native" | "java"
    pc: int = 0
    module: str = ""
    symbol: str | None = None
    offset: int | None = None
    build_id: str | None = None
    resolved: str | None = None
    # none | resolved | unresolved | no_symbols | unverified
    resolution: str = "none"
    # APK 内に非圧縮で格納された共有ライブラリの、APK 先頭からのオフセット。
    map_offset: int | None = None
    # BuildId から引いた元のライブラリ名 (例: libil2cpp.so)。
    library: str | None = None
    # llvm-addr2line が返す生成元ファイル。
    source_file: str | None = None
    # resolved の内側にインライン展開された関数 (内側 -> 外側)。DWARF が無いシンボルでは空。
    inlined: list[str] = field(default_factory=list)

    @property
    def module_name(self) -> str:
        return self.module.replace("\\", "/").rsplit("/", 1)[-1]

    @property
    def module_label(self) -> str:
        if self.library:
            return self.library
        if self.map_offset is None:
            return self.module_name
        return f"{self.module_name}@{self.map_offset:x}"

    def display_name(self) -> str:
        if self.resolved:
            return self.resolved
        if self.symbol:
            return self.symbol
        return f"{self.module_label}+0x{self.pc:x}"


@dataclass
class ThreadInfo:
    name: str
    tid: int | None = None
    sys_tid: int | None = None
    art_state: str | None = None
    os_state: str | None = None
    daemon: bool = False
    utime: int | None = None
    stime: int | None = None
    hz: int | None = None
    frames: list[Frame] = field(default_factory=list)

    @property
    def key(self) -> int | str:
        if self.sys_tid is not None:
            return self.sys_tid
        return f"{self.name}:{self.tid}"

    @property
    def cpu_ticks(self) -> int | None:
        if self.utime is None or self.stime is None:
            return None
        return self.utime + self.stime


@dataclass
class Sample:
    index: int
    time: str
    pid: int
    cmdline: str | None
    source: str
    threads: list[ThreadInfo] = field(default_factory=list)


@dataclass
class ProcThread:
    tid: int
    comm: str
    state: str
    utime: int
    stime: int


@dataclass
class ProcSnapshot:
    index: int
    device_time: str
    threads: list[ProcThread] = field(default_factory=list)
    # tid -> /proc/<pid>/task/<tid>/wchan (カーネル上の待機場所)。読めないと空。
    wchan: dict[str, str] = field(default_factory=dict)
    # dumpsys meminfo から抜いた主要項目 (kB)。取れないと空。
    meminfo: dict[str, int] = field(default_factory=dict)
    # パソコン側の単調時計で計った各手順の所要秒 (top / stat / wchan / meminfo / sigquit / sample_total)。未計測のデータでは空。
    timings: dict[str, float] = field(default_factory=dict)


@dataclass
class Session:
    session_id: str
    package: str
    serial: str
    pid: int
    created_at: str
    capture: dict = field(default_factory=dict)
    samples: list[Sample] = field(default_factory=list)
    proc_snapshots: list[ProcSnapshot] = field(default_factory=list)
    symbol_report: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    # 取得開始時に 1 回だけ読む端末・APK・プロセス・画面の情報。変更しやすいため辞書のまま保持する。
    device: dict = field(default_factory=dict)
    # bugreport から抽出したログ・カーネルログ・メモリ等。
    logs: dict = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        version = data.get("schema_version")
        if version not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(f"未対応の schema_version です: {version}")
        samples = [
            Sample(
                index=s["index"],
                time=s["time"],
                pid=s["pid"],
                cmdline=s.get("cmdline"),
                source=s.get("source", ""),
                threads=[
                    ThreadInfo(
                        **{**t, "frames": [Frame(**f) for f in t.get("frames", [])]},
                    )
                    for t in s.get("threads", [])
                ],
            )
            for s in data.get("samples", [])
        ]
        snapshots = [
            ProcSnapshot(
                index=p["index"],
                device_time=p["device_time"],
                threads=[ProcThread(**t) for t in p.get("threads", [])],
                wchan=dict(p.get("wchan", {})),
                meminfo=dict(p.get("meminfo", {})),
                timings=dict(p.get("timings", {})),
            )
            for p in data.get("proc_snapshots", [])
        ]
        return cls(
            session_id=data["session_id"],
            package=data["package"],
            serial=data.get("serial", ""),
            pid=data["pid"],
            created_at=data["created_at"],
            capture=data.get("capture", {}),
            samples=samples,
            proc_snapshots=snapshots,
            symbol_report=data.get("symbol_report", {}),
            warnings=list(data.get("warnings", [])),
            device=dict(data.get("device", {})),
            logs=dict(data.get("logs", {})),
        )


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def save_session(path: Path, session: Session) -> None:
    save_json(path, session.to_dict())


def load_session(path: Path) -> Session:
    return Session.from_dict(json.loads(path.read_text(encoding="utf-8")))
