from __future__ import annotations

import fnmatch
import re

# IL2CPP が付けるメソッド名の末尾: _m<40桁のハッシュ>[_gshared][_inline][(引数)]
_IL2CPP_NAME_RE = re.compile(
    r"^(?P<base>.+?)_m[0-9A-Fa-f]{16,}(?:_gshared)?(?:_inline)?(?P<args>\(.*\))?$"
)
_COMPILER_GENERATED_RE = re.compile(r"U3C(.+?)U3E")
_ASSEMBLY_RE = re.compile(r"^(?P<assembly>.+?)(?:__\d+)?\.cpp$")
_GENERATED_DIR = "/il2cppOutput/"


def pretty_name(name: str) -> str:
    """IL2CPP のハッシュ接尾辞と U3C/U3E だけを戻す。型名とメソッド名の区切りは曖昧なので触らない。"""
    match = _IL2CPP_NAME_RE.match(name)
    if match is None:
        return name
    return _COMPILER_GENERATED_RE.sub(r"<\1>", match.group("base"))


def strip_args(name: str) -> str:
    """末尾の引数リスト `(...)` を外す。括弧が対応しない場合や `operator()` そのものは残す。"""
    if not name.endswith(")"):
        return name
    depth = 0
    for index in range(len(name) - 1, -1, -1):
        char = name[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                head = name[:index]
                if not head or head.endswith("operator"):
                    return name
                return head
    return name


def short_name(name: str) -> str:
    """表示用の名前。IL2CPP のハッシュと末尾の引数リストを外す。"""
    return strip_args(pretty_name(name))


def assembly_of(source_file: str | None) -> str | None:
    """il2cppOutput の生成 .cpp 名から元のアセンブリ名を求める。

    行情報 (DWARF) が無いシンボルではファイル名だけが返るため、ディレクトリが無い場合も .cpp 名で判定する。
    ディレクトリがある場合は il2cppOutput 配下のファイルに限る (libil2cpp ランタイムの .cpp を除く)。
    """
    if not source_file:
        return None
    normalized = source_file.replace("\\", "/")
    if "/" in normalized and _GENERATED_DIR not in normalized:
        return None
    match = _ASSEMBLY_RE.match(normalized.rsplit("/", 1)[-1])
    return match.group("assembly") if match else None


def is_app_assembly(assembly: str | None, patterns: list[str]) -> bool:
    return assembly is not None and any(fnmatch.fnmatchcase(assembly, p) for p in patterns)
