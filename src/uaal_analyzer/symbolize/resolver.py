from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from ..errors import SymbolError

_ADDRESS_LINE_RE = re.compile(r"^0x[0-9a-fA-F]+$")
ADDR2LINE_TIMEOUT_SEC = 1800


@dataclass(frozen=True)
class ResolvedSymbol:
    # 最も外側の関数 (実際に呼ばれた関数)。インライン展開された内側の関数は inlined に内側 -> 外側の順で入る。
    name: str
    source_file: str | None = None
    inlined: tuple[str, ...] = ()


class Resolver(Protocol):
    def resolve(self, symbol_file: Path, addresses: list[int]) -> dict[int, ResolvedSymbol]: ...


class Addr2LineResolver:
    """llvm-addr2line に stdin でアドレスを渡し、関数名と生成元ファイルを一括解決する。"""

    def __init__(
        self,
        tool: Path,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        timeout: float = ADDR2LINE_TIMEOUT_SEC,
    ) -> None:
        self._tool = tool
        self._runner = runner
        self._timeout = timeout

    def resolve(self, symbol_file: Path, addresses: list[int]) -> dict[int, ResolvedSymbol]:
        if not addresses:
            return {}
        stdin = "".join(f"0x{address:x}\n" for address in addresses)
        try:
            proc = self._runner(
                [str(self._tool), "-a", "-C", "-f", "-i", "-e", str(symbol_file)],
                input=stdin.encode("ascii"),
                capture_output=True,
                timeout=self._timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SymbolError(f"llvm-addr2line を実行できません: {exc}") from exc
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            raise SymbolError(f"llvm-addr2line が失敗しました (code {proc.returncode}): {err}")
        return parse_addr2line_output(proc.stdout.decode("utf-8", errors="replace"))


def parse_addr2line_output(text: str) -> dict[int, ResolvedSymbol]:
    """`-a -f -i` 形式 (アドレス行の後に、関数名行 / 位置行の組が内側 -> 外側の順で続く) を {アドレス: ResolvedSymbol} にする。"""
    result: dict[int, ResolvedSymbol] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if not _is_address_line(lines[i]):
            i += 1
            continue
        address = int(lines[i].strip(), 16)
        i += 1
        pairs: list[tuple[str, str]] = []
        while i < len(lines) and not _is_address_line(lines[i]):
            function = lines[i].strip()
            i += 1
            location = ""
            if i < len(lines) and not _is_address_line(lines[i]):
                location = lines[i].strip()
                i += 1
            if function and function != "??":
                pairs.append((function, location))
        if pairs:
            outer_name, outer_location = pairs[-1]
            result[address] = ResolvedSymbol(
                outer_name, _source_file(outer_location), tuple(name for name, _ in pairs[:-1])
            )
    return result


def _is_address_line(line: str) -> bool:
    return _ADDRESS_LINE_RE.match(line.strip()) is not None


def _source_file(location: str) -> str | None:
    """`path:行` から path を取り出す。Windows のドライブ文字の ':' を壊さないよう、末尾だけを見る。"""
    if not location or location.startswith("??"):
        return None
    head, sep, tail = location.rpartition(":")
    if sep and tail.split(" ")[0].isdigit():
        return head or None
    return location
