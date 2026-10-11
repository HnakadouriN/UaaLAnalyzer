from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..errors import SymbolError

_META_NAME = "meta.json"


def normalize_library_name(file_name: str) -> str:
    """libil2cpp.dbg.so / libil2cpp.sym.so を libil2cpp.so に揃える。"""
    for marker in (".dbg.so", ".sym.so"):
        if file_name.endswith(marker):
            return file_name[: -len(marker)] + ".so"
    return file_name


@dataclass
class SymbolEntry:
    build_id: str
    path: Path
    source: str
    size: int


class SymbolStore:
    """BuildId をキーにシンボル付き ELF を保管する。次回ビルドでの上書きから守る。"""

    def __init__(self, root: Path) -> None:
        self._root = root

    def find(self, build_id: str) -> Path | None:
        directory = self._root / build_id.lower()
        if not directory.is_dir():
            return None
        for item in sorted(directory.iterdir()):
            if item.is_file() and item.name != _META_NAME:
                return item
        return None

    def library_name(self, build_id: str) -> str | None:
        found = self.find(build_id)
        return normalize_library_name(found.name) if found else None

    def add(self, source: Path, build_id: str) -> Path:
        build_id = build_id.lower()
        existing = self.find(build_id)
        if existing is not None:
            return existing
        directory = self._root / build_id
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / source.name
        try:
            shutil.copy2(source, destination)
        except OSError as exc:
            raise SymbolError(f"シンボルを保管できません: {source} -> {destination}: {exc}") from exc
        meta = {
            "build_id": build_id,
            "source": str(source),
            "name": source.name,
            "size": destination.stat().st_size,
            "added_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        }
        (directory / _META_NAME).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return destination

    def entries(self) -> list[SymbolEntry]:
        result: list[SymbolEntry] = []
        if not self._root.is_dir():
            return result
        for directory in sorted(self._root.iterdir()):
            path = self.find(directory.name)
            if path is None:
                continue
            source = ""
            meta_path = directory / _META_NAME
            if meta_path.exists():
                try:
                    source = json.loads(meta_path.read_text(encoding="utf-8")).get("source", "")
                except (OSError, json.JSONDecodeError):
                    source = ""
            result.append(SymbolEntry(directory.name, path, source, path.stat().st_size))
        return result
