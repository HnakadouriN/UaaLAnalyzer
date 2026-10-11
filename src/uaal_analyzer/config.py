from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError

TOOL_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = TOOL_ROOT / "configs" / "example.toml"


@dataclass
class Config:
    package: str = ""
    serial: str = ""
    adb: str = "adb"
    ndk_bin_dir: str = ""
    symbol_search_paths: list[str] = field(default_factory=list)
    symbol_patterns: list[str] = field(default_factory=lambda: ["*.so"])
    symbol_modules: list[str] = field(default_factory=lambda: ["libil2cpp.so"])
    samples: int = 5
    interval_sec: float = 2.0
    bugreport_timeout_sec: int = 900
    time_margin_sec: int = 30
    main_thread_names: list[str] = field(default_factory=lambda: ["UnityMain"])
    min_common_frames: int = 5
    min_common_ratio: float = 0.8
    busy_ratio: float = 0.5
    idle_ratio: float = 0.05
    app_assemblies: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    data_dir: Path = TOOL_ROOT / "data"

    @property
    def sessions_dir(self) -> Path:
        return self.data_dir / "sessions"

    @property
    def symbols_dir(self) -> Path:
        return self.data_dir / "symbols"


def config_for_package(package: str, config_dir: Path | None = None) -> Path | None:
    """`configs/<パッケージ名>.toml` があればそのパス。パッケージ名にパス区切り等が含まれる場合は探さない。"""
    if not package or Path(package).name != package or package.startswith("."):
        return None
    candidate = (config_dir or DEFAULT_CONFIG_PATH.parent) / f"{package}.toml"
    return candidate if candidate.is_file() else None


def load_config(path: Path | None = None, data_dir: Path | None = None) -> Config:
    config_path = path or DEFAULT_CONFIG_PATH
    cfg = Config()
    if config_path.exists():
        try:
            raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"設定ファイルを解釈できません: {config_path}: {exc}") from exc
        _apply(cfg, raw)
    elif path is not None:
        raise ConfigError(f"設定ファイルがありません: {config_path}")
    if data_dir is not None:
        cfg.data_dir = data_dir
    if cfg.samples < 2:
        raise ConfigError("capture.samples は 2 以上にしてください (停止判定に複数サンプルが必要)")
    return cfg


def _apply(cfg: Config, raw: dict) -> None:
    device = raw.get("device", {})
    cfg.package = device.get("package", cfg.package)
    cfg.serial = device.get("serial", cfg.serial)
    cfg.adb = device.get("adb", cfg.adb)
    cfg.ndk_bin_dir = raw.get("ndk", {}).get("bin_dir", cfg.ndk_bin_dir)
    symbols = raw.get("symbols", {})
    cfg.symbol_search_paths = list(symbols.get("search_paths", cfg.symbol_search_paths))
    cfg.symbol_patterns = list(symbols.get("patterns", cfg.symbol_patterns))
    cfg.symbol_modules = list(symbols.get("modules", cfg.symbol_modules))
    capture = raw.get("capture", {})
    cfg.samples = int(capture.get("samples", cfg.samples))
    cfg.interval_sec = float(capture.get("interval_sec", cfg.interval_sec))
    cfg.bugreport_timeout_sec = int(capture.get("bugreport_timeout_sec", cfg.bugreport_timeout_sec))
    cfg.time_margin_sec = int(capture.get("time_margin_sec", cfg.time_margin_sec))
    analysis = raw.get("analysis", {})
    cfg.main_thread_names = list(analysis.get("main_thread_names", cfg.main_thread_names))
    cfg.min_common_frames = int(analysis.get("min_common_frames", cfg.min_common_frames))
    cfg.min_common_ratio = float(analysis.get("min_common_ratio", cfg.min_common_ratio))
    cfg.busy_ratio = float(analysis.get("busy_ratio", cfg.busy_ratio))
    cfg.idle_ratio = float(analysis.get("idle_ratio", cfg.idle_ratio))
    cfg.app_assemblies = list(analysis.get("app_assemblies", cfg.app_assemblies))
    cfg.rules = list(analysis.get("rules", cfg.rules))
    if "data_dir" in raw:
        cfg.data_dir = Path(raw["data_dir"])
