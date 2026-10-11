from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Run:
    start: int
    period: int
    count: int


def find_runs(items: list[str], max_period: int = 8) -> list[Run]:
    """連続して繰り返される並びを検出する。count が 1 のものは繰り返しなし。表示専用で、元データは変えない。"""
    runs: list[Run] = []
    index = 0
    size = len(items)
    while index < size:
        best_period, best_count = 1, 1
        for period in range(1, max_period + 1):
            if index + 2 * period > size:
                break
            count = 1
            while (
                index + (count + 1) * period <= size
                and items[index + count * period : index + (count + 1) * period] == items[index : index + period]
            ):
                count += 1
            if count >= 2 and count * period > best_period * best_count:
                best_period, best_count = period, count
        runs.append(Run(index, best_period, best_count))
        index += best_period * best_count
    return runs
