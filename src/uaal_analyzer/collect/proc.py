from __future__ import annotations

from ..model import ProcThread


def parse_proc_stat(text: str) -> list[ProcThread]:
    """`cat /proc/<pid>/task/*/stat` の連結出力を解析する。comm に空白や括弧があっても最後の ')' で分ける。"""
    threads: list[ProcThread] = []
    for line in text.splitlines():
        line = line.strip()
        left = line.find("(")
        right = line.rfind(")")
        if left < 0 or right < left:
            continue
        try:
            tid = int(line[:left].strip())
            fields = line[right + 1 :].split()
            state = fields[0]
            utime = int(fields[11])
            stime = int(fields[12])
        except (ValueError, IndexError):
            continue
        threads.append(ProcThread(tid=tid, comm=line[left + 1 : right], state=state, utime=utime, stime=stime))
    return threads
