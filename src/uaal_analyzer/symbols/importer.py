from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from ..errors import SymbolError
from .store import SymbolStore

_BUILD_ID_RE = re.compile(r"Build ID:\s*([0-9a-fA-F]+)")
SYMBOL_FILE_PATTERN = "*.dbg.so"
READELF_TIMEOUT_SEC = 300

BuildIdReader = Callable[[Path], "str | None"]


def make_build_id_reader(readelf: Path, runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> BuildIdReader:
    def read(path: Path) -> str | None:
        try:
            proc = runner([str(readelf), "-n", str(path)], capture_output=True, timeout=READELF_TIMEOUT_SEC)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SymbolError(f"llvm-readelf を実行できません: {path}: {exc}") from exc
        text = proc.stdout.decode("utf-8", errors="replace")
        match = _BUILD_ID_RE.search(text)
        return match.group(1).lower() if match else None

    return read


@dataclass
class ImportResult:
    source: Path
    build_id: str | None
    stored: Path | None
    already_stored: bool = False


def find_candidates(paths: Iterable[Path], pattern: str = SYMBOL_FILE_PATTERN) -> list[Path]:
    """ファイルはそのまま、ディレクトリは再帰して *.dbg.so を集める。"""
    found: list[Path] = []
    for path in paths:
        if path.is_file():
            found.append(path)
        elif path.is_dir():
            found.extend(sorted(p for p in path.rglob(pattern) if p.is_file()))
    return found


def import_symbols(store: SymbolStore, reader: BuildIdReader, paths: Iterable[Path]) -> list[ImportResult]:
    results: list[ImportResult] = []
    for candidate in find_candidates(paths):
        build_id = reader(candidate)
        if build_id is None:
            results.append(ImportResult(candidate, None, None))
            continue
        already = store.find(build_id) is not None
        results.append(ImportResult(candidate, build_id, store.add(candidate, build_id), already))
    return results
