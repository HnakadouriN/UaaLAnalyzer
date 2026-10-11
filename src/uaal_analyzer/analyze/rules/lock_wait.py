from __future__ import annotations

import re

from .base import Finding, Rule, RuleContext, evidence_of, matching_frames, register

_PATTERN = re.compile(
    r"pthread_mutex_lock|pthread_cond_(?:timed)?wait|__futex_wait"
    r"|(?<![A-Za-z0-9])Monitor(?:_|::|\.)(?:Enter|Wait|TryEnter)(?![A-Za-z0-9])"
    r"|Mutex(?:_|::|\.)Lock(?![A-Za-z0-9])"
)


@register
class LockWaitRule(Rule):
    id = "lock-wait"
    title = "主スレッドがロック・条件変数の待機で停止している"

    def check(self, ctx: RuleContext) -> Finding | None:
        hits = matching_frames(ctx.common_frames, _PATTERN)
        if not hits:
            return None
        return Finding(
            rule_id=self.id,
            title=self.title,
            thread=ctx.thread.name,
            message="他スレッドが保持するロックを待ち続けている疑いがあります。保持側スレッドのスタックも確認してください。",
            evidence=evidence_of(hits),
        )
