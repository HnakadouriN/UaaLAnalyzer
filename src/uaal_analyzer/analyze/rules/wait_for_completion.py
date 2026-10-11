from __future__ import annotations

import re

from .base import Finding, Rule, RuleContext, evidence_of, matching_frames, register

_PATTERN = re.compile(r"WaitForCompletion")


@register
class WaitForCompletionRule(Rule):
    id = "wait-for-completion"
    title = "主スレッドで Addressables の WaitForCompletion が停止経路に残っている"

    def check(self, ctx: RuleContext) -> Finding | None:
        hits = matching_frames(ctx.common_frames, _PATTERN)
        if not hits:
            return None
        return Finding(
            rule_id=self.id,
            title=self.title,
            thread=ctx.thread.name,
            message="同期ロードが完了せず、主スレッドが占有され続けている疑いがあります。非同期待機への置換を検討してください。",
            evidence=evidence_of(hits),
        )
