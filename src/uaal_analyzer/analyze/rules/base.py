from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ...model import Frame
from ..stuck import ThreadAnalysis


@dataclass
class Finding:
    rule_id: str
    title: str
    thread: str
    message: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class RuleContext:
    thread: ThreadAnalysis

    @property
    def common_frames(self) -> list[Frame]:
        return self.thread.common_frames


class Rule(ABC):
    id: str = ""
    title: str = ""

    @abstractmethod
    def check(self, ctx: RuleContext) -> Finding | None:
        """停止経路 (全サンプルで共通の外側フレーム) を調べ、該当すれば Finding を返す。"""


REGISTRY: dict[str, type[Rule]] = {}


def register(cls: type[Rule]) -> type[Rule]:
    REGISTRY[cls.id] = cls
    return cls


def frame_text(frame: Frame) -> str:
    return f"{frame.module_label} {frame.display_name()}"


def matching_frames(frames: list[Frame], pattern: re.Pattern[str]) -> list[Frame]:
    return [f for f in frames if pattern.search(frame_text(f))]


def evidence_of(frames: list[Frame], limit: int = 5) -> list[str]:
    return [f.display_name() for f in frames[:limit]]
