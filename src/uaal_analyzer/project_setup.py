from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from .config import DEFAULT_CONFIG_PATH, Config
from .errors import ConfigError

# Unity が生成する、IL2CPP のシンボルが置かれる場所 (unityLibrary からの相対パス。* は版や ABI を表す)。
_UNITY_LIBRARY_SUBPATHS = (
    "symbols",
    "src/main/jniLibs",
    "build/il2cpp_*/il2cpp_cache/buildstate/artifacts",
    "build/intermediates/merged_native_libs",
)
_BEE_ARTIFACTS = "Library/Bee/artifacts/Android"
_VARIATIONS_SUBPATHS = (
    "Editor/Data/PlaybackEngines/AndroidPlayer/Variations",
    "Unity.app/Contents/PlaybackEngines/AndroidPlayer/Variations",
)
_IMPLICIT_ASSEMBLIES = ("Assembly-CSharp", "Assembly-CSharp-firstpass")


@dataclass
class SetupResult:
    path: Path
    text: str
    assemblies: list[str]
    symbol_paths: list[str]
    ndk_bin: str | None
    notes: list[str] = field(default_factory=list)


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _app_assembly_name(data: dict) -> str | None:
    """製品のコードを含む asmdef の名前。エディター専用とテスト用は対象外にする。"""
    name = data.get("name")
    if not isinstance(name, str) or not name:
        return None
    platforms = [str(p).lower() for p in data.get("includePlatforms") or []]
    if platforms == ["editor"]:
        return None
    if "UNITY_INCLUDE_TESTS" in (data.get("defineConstraints") or []):
        return None
    if "TestAssemblies" in (data.get("optionalUnityReferences") or []):
        return None
    return name


def _asmdef_names(root: Path, notes: list[str]) -> list[str]:
    names: list[str] = []
    for path in sorted(root.rglob("*.asmdef")):
        data = _read_json(path)
        if data is None:
            notes.append(f"asmdef を読めないためスキップ: {path}")
            continue
        name = _app_assembly_name(data)
        if name:
            names.append(name)
    return names


def _local_package_dirs(project: Path, notes: list[str]) -> list[Path]:
    """manifest.json で `file:` 参照されている自社のパッケージ (com.unity.* は除く)。"""
    manifest = _read_json(project / "Packages" / "manifest.json")
    if manifest is None:
        return []
    directories: list[Path] = []
    for name, value in (manifest.get("dependencies") or {}).items():
        if not isinstance(value, str) or not value.startswith("file:") or name.startswith("com.unity."):
            continue
        directory = (project / "Packages" / value[len("file:") :]).resolve()
        if directory.is_dir():
            directories.append(directory)
        else:
            notes.append(f"パッケージ {name} の場所が見つかりません: {directory}")
    return directories


def collect_assemblies(project: Path, notes: list[str] | None = None) -> list[str]:
    """プロジェクトの自社アセンブリ名。Assets と、file: 参照の自社パッケージの asmdef から集める。"""
    notes = notes if notes is not None else []
    names: list[str] = []
    assets = project / "Assets"
    if assets.is_dir():
        names += _asmdef_names(assets, notes)
    for directory in _local_package_dirs(project, notes):
        names += _asmdef_names(directory, notes)
    names += list(_IMPLICIT_ASSEMBLIES)
    return list(dict.fromkeys(names))


def default_unity_roots(env: Mapping[str, str]) -> list[Path]:
    program_files = env.get("ProgramFiles", "C:/Program Files")
    return [
        Path(program_files) / "Unity" / "Hub" / "Editor",
        Path.home() / "Unity" / "Hub" / "Editor",
        Path("/Applications/Unity/Hub/Editor"),
    ]


def _editor_version(project: Path) -> str | None:
    try:
        text = (project / "ProjectSettings" / "ProjectVersion.txt").read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r"^m_EditorVersion:\s*(\S+)", text, re.MULTILINE)
    return match.group(1) if match else None


def collect_symbol_paths(
    project: Path, unity_roots: Sequence[Path], notes: list[str] | None = None
) -> list[str]:
    """IL2CPP のシンボルがありそうな場所のうち、実在するものだけを返す。"""
    notes = notes if notes is not None else []
    found: list[Path] = []
    library_roots = [project / "unityLibrary", *sorted(project.glob("*/unityLibrary"))]
    for root in library_roots:
        for sub in _UNITY_LIBRARY_SUBPATHS:
            found += [p for p in sorted(root.glob(sub)) if p.is_dir()]
    bee = project / _BEE_ARTIFACTS
    if bee.is_dir():
        found.append(bee)
    version = _editor_version(project)
    if version is None:
        notes.append("ProjectSettings/ProjectVersion.txt を読めないため、Unity エディターのシンボルの場所は探しません")
    else:
        variations = [
            root / version / sub for root in unity_roots for sub in _VARIATIONS_SUBPATHS if (root / version / sub).is_dir()
        ]
        if variations:
            found += variations[:1]
        else:
            notes.append(
                f"Unity {version} の Variations フォルダが標準の場所に見つかりません。"
                "libunity のシンボルが必要なら、[symbols] search_paths に手で追加してください"
            )
    if not found:
        notes.append("シンボルの場所が見つかりません。Android のビルドを実行してから、もう一度実行してください")
    return list(dict.fromkeys(p.as_posix() for p in found))


def _version_key(path: Path) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", path.name))


def _ndk_bin_dirs(ndk_dir: Path) -> list[Path]:
    return [
        p
        for p in sorted(ndk_dir.glob("toolchains/llvm/prebuilt/*/bin"))
        if any((p / f"llvm-addr2line{ext}").exists() for ext in ("", ".exe"))
        and any((p / f"llvm-readelf{ext}").exists() for ext in ("", ".exe"))
    ]


def find_ndk_bin(env: Mapping[str, str], home: Path | None = None) -> str | None:
    """llvm-addr2line と llvm-readelf がある NDK の bin フォルダ。環境変数の NDK、新しい版の順に探す。"""
    ndk_dirs: list[Path] = []
    if env.get("ANDROID_NDK_HOME"):
        ndk_dirs.append(Path(env["ANDROID_NDK_HOME"]))
    sdk_roots = [Path(env[k]) for k in ("ANDROID_SDK_ROOT", "ANDROID_HOME") if env.get(k)]
    if env.get("LOCALAPPDATA"):
        sdk_roots.append(Path(env["LOCALAPPDATA"]) / "Android" / "Sdk")
    sdk_roots.append((home or Path.home()) / "Android" / "Sdk")
    for sdk in sdk_roots:
        ndk_dirs += sorted((p for p in (sdk / "ndk").glob("*") if p.is_dir()), key=_version_key, reverse=True)
    for ndk in ndk_dirs:
        bins = _ndk_bin_dirs(ndk)
        if bins:
            return bins[0].as_posix()
    return None


def _toml_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _toml_list(values: Sequence[str], indent: str = "    ") -> str:
    if not values:
        return "[]"
    return "[\n" + "".join(f"{indent}{_toml_str(v)},\n" for v in values) + "]"


def render_config(package: str, assemblies: Sequence[str], symbol_paths: Sequence[str], ndk_bin: str | None) -> str:
    defaults = Config()
    return "\n".join(
        [
            "# UaaLAnalyzer 設定 (uaal init で自動作成)。自社アセンブリとシンボルの場所を確認してください。",
            "",
            "[device]",
            f"package = {_toml_str(package)}",
            'serial = ""',
            f"adb = {_toml_str(defaults.adb)}",
            "",
            "[ndk]",
            f"bin_dir = {_toml_str(ndk_bin or '')}",
            "",
            "[symbols]",
            f"search_paths = {_toml_list(symbol_paths)}",
            f"patterns = {json.dumps(defaults.symbol_patterns, ensure_ascii=False)}",
            f"modules = {json.dumps(defaults.symbol_modules, ensure_ascii=False)}",
            "",
            "[capture]",
            f"samples = {defaults.samples}",
            f"interval_sec = {defaults.interval_sec}",
            f"bugreport_timeout_sec = {defaults.bugreport_timeout_sec}",
            f"time_margin_sec = {defaults.time_margin_sec}",
            "",
            "[analysis]",
            f"main_thread_names = {json.dumps(defaults.main_thread_names, ensure_ascii=False)}",
            f"min_common_frames = {defaults.min_common_frames}",
            f"min_common_ratio = {defaults.min_common_ratio}",
            f"busy_ratio = {defaults.busy_ratio}",
            f"idle_ratio = {defaults.idle_ratio}",
            f"app_assemblies = {_toml_list(assemblies)}",
            "rules = []",
            "",
        ]
    )


def write_project_config(
    project: Path,
    package: str,
    *,
    config_dir: Path | None = None,
    force: bool = False,
    env: Mapping[str, str] | None = None,
    unity_roots: Sequence[Path] | None = None,
) -> SetupResult:
    """Unity プロジェクトから設定ファイルを作る。同名のファイルは --force が無い限り上書きしない。"""
    env = os.environ if env is None else env
    if not project.is_dir():
        raise ConfigError(f"Unity プロジェクトが見つかりません: {project}")
    if not (project / "Assets").is_dir() and not (project / "ProjectSettings").is_dir():
        raise ConfigError(f"Unity プロジェクトではないようです (Assets も ProjectSettings もありません): {project}")
    directory = config_dir or DEFAULT_CONFIG_PATH.parent
    path = directory / f"{package}.toml"
    if path.exists() and not force:
        raise ConfigError(f"設定ファイルが既にあります: {path} (上書きするには --force を付けてください)")

    notes: list[str] = []
    assemblies = collect_assemblies(project, notes)
    roots = list(unity_roots) if unity_roots is not None else default_unity_roots(env)
    symbol_paths = collect_symbol_paths(project, roots, notes)
    ndk_bin = find_ndk_bin(env)
    if ndk_bin is None:
        notes.append("NDK (llvm-addr2line / llvm-readelf) が見つかりません。[ndk] bin_dir を手で設定してください")
    text = render_config(package, assemblies, symbol_paths, ndk_bin)
    directory.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return SetupResult(path, text, assemblies, symbol_paths, ndk_bin, notes)
