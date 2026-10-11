from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from uaal_analyzer.config import config_for_package, load_config
from uaal_analyzer.errors import ConfigError
from uaal_analyzer.project_setup import (
    collect_assemblies,
    collect_symbol_paths,
    find_ndk_bin,
    render_config,
    write_project_config,
)


def _write(path: Path, text: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding=encoding)


@pytest.fixture(autouse=True)
def _no_real_home(tmp_path, monkeypatch):
    # この PC の SDK や Unity Hub を拾わない。
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "nohome")


def _unity_project(root: Path) -> Path:
    project = root / "Game"
    # 自社コード (BOM 付きの asmdef も読める)
    _write(project / "Assets/Scripts/Core/Core.asmdef", '{"name": "Game.Core", "includePlatforms": []}', "utf-8-sig")
    # エディター専用・テスト用は対象外
    _write(project / "Assets/Scripts/Editor/Tools.asmdef", '{"name": "Game.Editor", "includePlatforms": ["Editor"]}')
    _write(project / "Assets/Tests/Tests.asmdef", '{"name": "Game.Tests", "defineConstraints": ["UNITY_INCLUDE_TESTS"]}')
    _write(project / "Assets/Old/OldTests.asmdef", '{"name": "Game.OldTests", "optionalUnityReferences": ["TestAssemblies"]}')
    _write(project / "Assets/Bad/Bad.asmdef", "{not json")
    # file: 参照の自社パッケージ (com.unity.* は除く)
    _write(
        project / "Packages/manifest.json",
        '{"dependencies": {'
        '"com.game.debug": "file:../CustomPackages/com.game.debug",'
        '"com.unity.ugui": "file:com.unity.ugui",'
        '"com.cysharp.r3": "https://github.com/Cysharp/R3.git",'
        '"com.game.missing": "file:../Nope"}}',
    )
    _write(project / "CustomPackages/com.game.debug/Runtime/Debug.asmdef", '{"name": "Game.Debug"}')
    _write(
        project / "CustomPackages/com.game.debug/Tests/DebugTests.asmdef",
        '{"name": "Game.Debug.Tests", "defineConstraints": ["UNITY_INCLUDE_TESTS"]}',
    )
    _write(project / "Packages/com.unity.ugui/Runtime/UI.asmdef", '{"name": "UnityEngine.UI"}')
    _write(project / "ProjectSettings/ProjectVersion.txt", "m_EditorVersion: 6000.3.10f1\nm_EditorVersionWithRevision: x\n")
    return project


def test_collect_assemblies_keeps_product_code_and_skips_editor_test_and_unity_packages(tmp_path):
    notes: list[str] = []
    project = _unity_project(tmp_path)

    names = collect_assemblies(project, notes)

    assert names == ["Game.Core", "Game.Debug", "Assembly-CSharp", "Assembly-CSharp-firstpass"]
    assert any("Bad.asmdef" in n for n in notes)
    assert any("com.game.missing" in n for n in notes)


def test_collect_symbol_paths_lists_only_existing_locations(tmp_path):
    project = _unity_project(tmp_path)
    library = project / "androidBuild" / "unityLibrary"
    (library / "symbols").mkdir(parents=True)
    (library / "build" / "il2cpp_arm64-v8a_Release" / "il2cpp_cache" / "buildstate" / "artifacts").mkdir(parents=True)
    (project / "Library" / "Bee" / "artifacts" / "Android").mkdir(parents=True)
    hub = tmp_path / "Hub"
    variations = hub / "6000.3.10f1" / "Editor" / "Data" / "PlaybackEngines" / "AndroidPlayer" / "Variations"
    variations.mkdir(parents=True)
    notes: list[str] = []

    paths = collect_symbol_paths(project, [hub], notes)

    assert paths == [
        (library / "symbols").as_posix(),
        (library / "build" / "il2cpp_arm64-v8a_Release" / "il2cpp_cache" / "buildstate" / "artifacts").as_posix(),
        (project / "Library" / "Bee" / "artifacts" / "Android").as_posix(),
        variations.as_posix(),
    ]
    assert notes == []


def test_collect_symbol_paths_explains_what_is_missing(tmp_path):
    project = _unity_project(tmp_path)
    notes: list[str] = []

    paths = collect_symbol_paths(project, [tmp_path / "NoHub"], notes)

    assert paths == []
    assert any("Variations" in n and "6000.3.10f1" in n for n in notes)
    assert any("Android のビルド" in n for n in notes)


def test_collect_symbol_paths_without_a_project_version_skips_the_editor_lookup(tmp_path):
    project = tmp_path / "Game"
    (project / "Assets").mkdir(parents=True)
    notes: list[str] = []

    collect_symbol_paths(project, [tmp_path], notes)

    assert any("ProjectVersion.txt" in n for n in notes)


def _fake_ndk(sdk: Path, version: str, with_tools: bool = True) -> Path:
    bin_dir = sdk / "ndk" / version / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin"
    bin_dir.mkdir(parents=True)
    if with_tools:
        (bin_dir / "llvm-addr2line.exe").write_bytes(b"")
        (bin_dir / "llvm-readelf.exe").write_bytes(b"")
    return bin_dir


def test_find_ndk_bin_prefers_the_newest_ndk_that_has_both_tools(tmp_path):
    sdk = tmp_path / "Sdk"
    _fake_ndk(sdk, "26.1.10909125")
    newest = _fake_ndk(sdk, "27.2.12479018")
    _fake_ndk(sdk, "28.0.1", with_tools=False)

    assert find_ndk_bin({"ANDROID_SDK_ROOT": str(sdk)}, home=tmp_path / "nohome") == newest.as_posix()
    assert find_ndk_bin({"LOCALAPPDATA": str(tmp_path / "Local")}, home=tmp_path / "nohome") is None


def test_find_ndk_bin_uses_ndk_home_first_and_the_standard_sdk_folder(tmp_path):
    sdk = tmp_path / "Local" / "Android" / "Sdk"
    standard = _fake_ndk(sdk, "27.2.12479018")
    pinned_root = tmp_path / "pinned"
    pinned_bin = pinned_root / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin"
    pinned_bin.mkdir(parents=True)
    (pinned_bin / "llvm-addr2line.exe").write_bytes(b"")
    (pinned_bin / "llvm-readelf.exe").write_bytes(b"")

    assert find_ndk_bin({"LOCALAPPDATA": str(tmp_path / "Local")}, home=tmp_path / "x") == standard.as_posix()
    env = {"LOCALAPPDATA": str(tmp_path / "Local"), "ANDROID_NDK_HOME": str(pinned_root)}
    assert find_ndk_bin(env, home=tmp_path / "x") == pinned_bin.as_posix()


def test_render_config_is_valid_toml_that_load_config_reads(tmp_path):
    text = render_config("com.game.app", ["Game.Core", "Assembly-CSharp"], ["C:/a b/symbols"], "C:/ndk/bin")
    path = tmp_path / "c.toml"
    path.write_text(text, encoding="utf-8")

    data = tomllib.loads(text)
    cfg = load_config(path)

    assert data["device"]["package"] == "com.game.app"
    assert cfg.app_assemblies == ["Game.Core", "Assembly-CSharp"]
    assert cfg.symbol_search_paths == ["C:/a b/symbols"]
    assert cfg.ndk_bin_dir == "C:/ndk/bin"
    assert (cfg.samples, cfg.interval_sec, cfg.main_thread_names, cfg.symbol_modules) == (5, 2.0, ["UnityMain"], ["libil2cpp.so"])


def test_write_project_config_writes_a_loadable_file_and_does_not_overwrite(tmp_path):
    project = _unity_project(tmp_path)
    sdk = tmp_path / "Sdk"
    ndk = _fake_ndk(sdk, "27.2.12479018")
    configs = tmp_path / "configs"
    env = {"ANDROID_SDK_ROOT": str(sdk)}

    result = write_project_config(project, "com.game.app", config_dir=configs, env=env, unity_roots=[tmp_path / "Hub"])

    assert result.path == configs / "com.game.app.toml"
    cfg = load_config(result.path)
    assert cfg.package == "com.game.app"
    assert cfg.app_assemblies == ["Game.Core", "Game.Debug", "Assembly-CSharp", "Assembly-CSharp-firstpass"]
    assert cfg.ndk_bin_dir == ndk.as_posix()
    assert any("Variations" in n for n in result.notes)
    with pytest.raises(ConfigError, match="--force"):
        write_project_config(project, "com.game.app", config_dir=configs, env=env, unity_roots=[])
    again = write_project_config(project, "com.game.app", config_dir=configs, env=env, unity_roots=[], force=True)
    assert again.path.exists()


def test_write_project_config_reports_a_missing_ndk_and_bad_projects(tmp_path):
    project = _unity_project(tmp_path)

    result = write_project_config(project, "p.q", config_dir=tmp_path / "c", env={}, unity_roots=[])
    assert result.ndk_bin is None and any("NDK" in n for n in result.notes)

    with pytest.raises(ConfigError, match="見つかりません"):
        write_project_config(tmp_path / "nope", "p.q", config_dir=tmp_path / "c")
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(ConfigError, match="Unity プロジェクトではない"):
        write_project_config(plain, "p.q", config_dir=tmp_path / "c")


def test_config_for_package_finds_only_plain_file_names(tmp_path):
    (tmp_path / "com.game.app.toml").write_text("", encoding="utf-8")

    assert config_for_package("com.game.app", tmp_path) == tmp_path / "com.game.app.toml"
    assert config_for_package("com.other", tmp_path) is None
    assert config_for_package("../escape", tmp_path) is None
    assert config_for_package("", tmp_path) is None
