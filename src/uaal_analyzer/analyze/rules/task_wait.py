from __future__ import annotations

import re

from .base import Finding, Rule, RuleContext, evidence_of, matching_frames, register

_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])Task(?:`1|_1)?(?:_|\.|::)(?:Wait|get_Result|InternalWait|WaitAll|WaitAny)(?![A-Za-z0-9])"
    r"|Awaiter(?:_|\.|::)GetResult(?![A-Za-z0-9])"
)


@register
class TaskWaitRule(Rule):
    id = "task-wait"
    title = "主スレッドで Task.Wait / .Result による同期待機が停止経路に残っている"

    def check(self, ctx: RuleContext) -> Finding | None:
        hits = matching_frames(ctx.common_frames, _PATTERN)
        if not hits:
            return None
        return Finding(
            rule_id=self.id,
            title=self.title,
            thread=ctx.thread.name,
            message="完了しないタスクを同期的に待っている疑いがあります。await への置換を検討してください。",
            evidence=evidence_of(hits),
        )
