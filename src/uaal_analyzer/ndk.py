from __future__ import annotations

import os
from pathlib import Path

from .errors import ConfigError


def ndk_tool(bin_dir: str, name: str) -> Path:
    """NDK の llvm ツールの実体パスを返す。"""
    if not bin_dir:
        raise ConfigError("ndk.bin_dir が未設定です (設定ファイルの [ndk] bin_dir)")
    base = Path(bin_dir)
    candidates = [base / (name + ".exe"), base / name] if os.name == "nt" else [base / name]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise ConfigError(f"NDK ツールが見つかりません: {name} (探索先: {base})")
