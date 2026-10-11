from __future__ import annotations

import copy
from collections import defaultdict
from typing import Iterator, Mapping

from ..errors import SymbolError
from ..model import Frame, Session
from ..symbols.store import SymbolStore
from .resolver import Resolver


def needed_build_ids(session: Session, modules: list[str]) -> set[str]:
    return {f.build_id for f in _target_frames(session, modules) if f.build_id}


def symbolize_session(
    session: Session,
    store: SymbolStore,
    resolver: Resolver,
    modules: list[str],
    library_names: Mapping[str, str] | None = None,
) -> Session:
    """モジュールの BuildId がストアと完全一致した場合だけ名前解決する。一致しなければ警告して解決しない。"""
    result = copy.deepcopy(session)
    names = {build_id.lower(): name for build_id, name in (library_names or {}).items()}
    by_build_id: dict[str, list[Frame]] = defaultdict(list)
    unverified: dict[str, int] = defaultdict(int)

    for frame in _target_frames(result, modules):
        if frame.build_id in names:
            frame.library = names[frame.build_id]
        if frame.build_id is None:
            frame.resolution = "unverified"
            unverified[frame.module_label] += 1
        else:
            by_build_id[frame.build_id].append(frame)

    for module, count in unverified.items():
        result.warnings.append(f"{module}: BuildId が無い {count} フレームは照合できないため解決しません")

    known = [entry.build_id for entry in store.entries()]
    for build_id, frames in by_build_id.items():
        module = frames[0].module_label
        symbol_file = store.find(build_id)
        if symbol_file is None:
            for frame in frames:
                frame.resolution = "no_symbols"
            result.symbol_report[build_id] = {"status": "no_symbols", "module": module, "frames": len(frames)}
            result.warnings.append(
                f"{module}: BuildId {build_id} に一致するシンボルが保管庫にありません"
                f" (保管済み: {', '.join(known) or 'なし'})。"
                f" `uaal symbols add <ビルド出力のパス>` で取り込んでください"
            )
            continue
        addresses = sorted({f.pc for f in frames})
        try:
            symbols = resolver.resolve(symbol_file, addresses)
        except SymbolError as exc:
            for frame in frames:
                frame.resolution = "unresolved"
            result.symbol_report[build_id] = {"status": "error", "module": module, "frames": len(frames)}
            result.warnings.append(f"{module}: シンボル解決に失敗しました: {exc}")
            continue
        resolved_count = 0
        for frame in frames:
            symbol = symbols.get(frame.pc)
            if symbol is not None:
                frame.resolved = symbol.name
                frame.source_file = symbol.source_file
                frame.inlined = list(symbol.inlined)
                frame.resolution = "resolved"
                resolved_count += 1
            else:
                frame.resolution = "unresolved"
        result.symbol_report[build_id] = {
            "status": "resolved",
            "module": module,
            "frames": len(frames),
            "resolved": resolved_count,
            "file": str(symbol_file),
        }
    return result


def _target_frames(session: Session, modules: list[str]) -> Iterator[Frame]:
    """名前付きの対象モジュールと、BuildId を持つ APK 内の共有ライブラリのフレームを返す。"""
    wanted = {m.lower() for m in modules}
    for sample in session.samples:
        for thread in sample.threads:
            for frame in thread.frames:
                if frame.kind != "native":
                    continue
                is_named = frame.module_name.lower() in wanted
                is_mapped_library = frame.map_offset is not None and frame.build_id is not None
                if is_named or is_mapped_library:
                    yield frame
