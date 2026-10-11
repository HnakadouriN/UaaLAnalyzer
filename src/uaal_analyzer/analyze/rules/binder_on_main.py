from __future__ import annotations

import re

from .base import Finding, Rule, RuleContext, evidence_of, matching_frames, register

_PATTERN = re.compile(r"libbinder|IPCThreadState|BpBinder|android\.os\.BinderProxy")


@register
class BinderOnMainRule(Rule):
    id = "binder-on-main"
    title = "主スレッドで Binder 通信が停止経路に残っている"

    def check(self, ctx: RuleContext) -> Finding | None:
        hits = matching_frames(ctx.common_frames, _PATTERN)
        if not hits:
            return None
        return Finding(
            rule_id=self.id,
            title=self.title,
            thread=ctx.thread.name,
            message="同期 Binder 呼び出しの応答待ちで主スレッドが止まっている疑いがあります。呼び出し先プロセスの状態も確認してください。",
            evidence=evidence_of(hits),
        )
