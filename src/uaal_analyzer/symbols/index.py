from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator

from .importer import BuildIdReader
from .store import SymbolStore, normalize_library_name

_INDEX_VERSION = 1


def _rank(path: Path, size: int) -> tuple[int, int]:
    """小さいほど優先。デバッグ情報を持つ見込みが高い名前・置き場所を先にする。"""
    name = path.name.lower()
    if name.endswith(".dbg.so"):
        tier = 0
    elif name.endswith(".sym.so"):
        tier = 1
    elif any(part.lower() == "symbols" for part in path.parts):
        tier = 2
    else:
        tier = 3
    return tier, -size


def _iter_files(root: Path, patterns: Iterable[str]) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    for pattern in patterns:
        for path in sorted(root.rglob(pattern)):
            if path.is_file():
                yield path


class SymbolIndex:
    """検索パス配下の .so の BuildId を、サイズと更新時刻をキーにキャッシュする。"""

    def __init__(self, cache_path: Path, reader: BuildIdReader) -> None:
        self._cache_path = cache_path
        self._reader = reader
        self._entries: dict[str, dict] = self._load()
        self._dirty = False

    def scan(self, roots: Iterable[Path], patterns: Iterable[str]) -> None:
        patterns = list(patterns)
        seen: set[str] = set()
        for root in roots:
            for path in _iter_files(root, patterns):
                key = str(path)
                if key not in seen:
                    seen.add(key)
                    self._refresh(path)
        self._save()

    def candidates(self, build_id: str) -> list[Path]:
        build_id = build_id.lower()
        found = [
            (Path(key), entry["size"])
            for key, entry in self._entries.items()
            if entry.get("build_id") == build_id and Path(key).exists()
        ]
        found.sort(key=lambda item: _rank(item[0], item[1]))
        return [path for path, _ in found]

    def library_name(self, build_id: str) -> str | None:
        candidates = self.candidates(build_id)
        return normalize_library_name(candidates[0].name) if candidates else None

    def _refresh(self, path: Path) -> None:
        try:
            stat = path.stat()
        except OSError:
            return
        cached = self._entries.get(str(path))
        if cached and cached.get("size") == stat.st_size and cached.get("mtime_ns") == stat.st_mtime_ns:
            return
        self._entries[str(path)] = {
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "build_id": self._reader(path),
        }
        self._dirty = True

    def _load(self) -> dict[str, dict]:
        try:
            data = json.loads(self._cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if data.get("version") != _INDEX_VERSION:
            return {}
        return dict(data.get("entries", {}))

    def _save(self) -> None:
        if not self._dirty:
            return
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": _INDEX_VERSION, "entries": self._entries}
        self._cache_path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        self._dirty = False


def ensure_symbols(store: SymbolStore, index: SymbolIndex, needed: Iterable[str]) -> set[str]:
    """保管庫に無い BuildId だけ、インデックスの最良候補を取り込む。保管庫で見つかった BuildId を返す。"""
    wanted = {b.lower() for b in needed}
    for build_id in sorted(wanted):
        if store.find(build_id) is not None:
            continue
        candidates = index.candidates(build_id)
        if candidates:
            store.add(candidates[0], build_id)
    return {b for b in wanted if store.find(b) is not None}
