from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone, tzinfo

_TIME_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?"
)


def parse_device_time(text: str, default_tz: tzinfo = timezone.utc) -> datetime:
    """ART トレースのヘッダや `date +%z` 形式の時刻を、タイムゾーン付きで返す。"""
    match = _TIME_RE.search(text)
    if match is None:
        raise ValueError(f"時刻を解釈できません: {text!r}")
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    micro = int(((match.group(7) or "") + "000000")[:6])
    zone = match.group(8)
    if zone is None:
        tz = default_tz
    elif zone == "Z":
        tz = timezone.utc
    else:
        sign = -1 if zone[0] == "-" else 1
        digits = zone[1:].replace(":", "")
        tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    return datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)
