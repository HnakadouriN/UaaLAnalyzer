from __future__ import annotations

from ..naming import assembly_of, is_app_assembly, short_name
from .stuck import ThreadAnalysis


def find_origin(thread: ThreadAnalysis, app_assemblies: list[str]) -> tuple[dict | None, list[str]]:
    """最新サンプルの経路から、最も内側の自社メソッドと、そこまでに通った自社メソッド (外側 -> 内側) を返す。

    人が停止と判断して起動する前提のため、全サンプルで共通かどうかには依存しない。
    """
    app_frames = []
    for frame in reversed(thread.frames):  # 外側 -> 内側
        assembly = assembly_of(frame.source_file)
        if is_app_assembly(assembly, app_assemblies):
            app_frames.append((frame, assembly))
    if not app_frames:
        return None, []
    frame, assembly = app_frames[-1]
    raw = frame.display_name()
    origin = {
        "function": short_name(raw),
        "raw": raw,
        "assembly": assembly,
        "source_file": frame.source_file,
        "library": frame.module_label,
    }
    reached = [short_name(f.display_name()) for f, _ in app_frames]
    return origin, reached
