from __future__ import annotations

import importlib
import pkgutil

from ...errors import ConfigError
from .base import REGISTRY, Finding, Rule, RuleContext

__all__ = ["Finding", "Rule", "RuleContext", "load_rules"]


def load_rules(enabled: list[str] | None = None) -> list[Rule]:
    """このパッケージ内の規則モジュールを自動で読み込む。追加はファイルを置くだけでよい。"""
    for module in pkgutil.iter_modules(__path__):
        if not module.name.startswith("_") and module.name != "base":
            importlib.import_module(f"{__name__}.{module.name}")
    if enabled:
        unknown = [rule_id for rule_id in enabled if rule_id not in REGISTRY]
        if unknown:
            raise ConfigError(f"未知の規則です: {', '.join(unknown)} (利用可能: {', '.join(sorted(REGISTRY))})")
        return [REGISTRY[rule_id]() for rule_id in enabled]
    return [REGISTRY[rule_id]() for rule_id in sorted(REGISTRY)]
