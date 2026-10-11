from __future__ import annotations

import pytest

from uaal_analyzer.naming import assembly_of, is_app_assembly, pretty_name, short_name, strip_args
from uaal_analyzer.report.compress import find_runs

HASH = "0123456789ABCDEF0123456789ABCDEF01234567"


@pytest.mark.parametrize(
    "raw,expected",
    [
        (f"SettingsManager_OnModeChanged_m{HASH}", "SettingsManager_OnModeChanged"),
        (f"AsyncOperationBase_1_WaitForCompletion_m{HASH}_gshared", "AsyncOperationBase_1_WaitForCompletion"),
        (
            f"ContainerBuilderExtensions_Register_TisRuntimeObject_m{HASH}_gshared_inline(Il2CppObject*, int, MethodInfo const*)",
            "ContainerBuilderExtensions_Register_TisRuntimeObject",
        ),
        (f"U3CStartU3Ed__9_MoveNext_m{HASH}", "<Start>d__9_MoveNext"),
        (f"U3CTryLoadAsyncU3Ed__11_MoveNext_m{HASH}", "<TryLoadAsync>d__11_MoveNext"),
    ],
)
def test_pretty_name_strips_il2cpp_hash_and_restores_compiler_generated_names(raw, expected):
    assert pretty_name(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        (f"ItemList_1_get_Count_m{HASH}(ItemList_1_t85D*, MethodInfo const*)", "ItemList_1_get_Count"),
        ("il2cpp::vm::Runtime::Invoke(MethodInfo const*, void*, void**, Il2CppException**)", "il2cpp::vm::Runtime::Invoke"),
        ("Foo::operator()", "Foo::operator()"),
        ("Foo::operator()(int)", "Foo::operator()"),
        ("_MultiplyMatrixArrayWithBase4x4_NEON", "_MultiplyMatrixArrayWithBase4x4_NEON"),
    ],
)
def test_short_name_drops_hash_and_trailing_arguments_only(raw, expected):
    assert short_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "il2cpp::vm::Runtime::Invoke(MethodInfo const*, void*, void**, Il2CppException**)",
        "_MultiplyMatrixArrayWithBase4x4_NEON",
        f"RuntimeInvoker_TrueUniTaskVoid_t{HASH}(void (*)(), MethodInfo const*)",
        "SomethingU3CNotGeneratedU3E",
        "com.unity3d.player.U.handleMessage",
    ],
)
def test_pretty_name_leaves_other_names_untouched(raw):
    assert pretty_name(raw) == raw


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("VirtualFuncInvoker0<bool>::Invoke(unsigned short, Il2CppObject*)", "VirtualFuncInvoker0<bool>::Invoke"),
        ("RuntimeInvoker_X(void (*)(), MethodInfo const*, void*)", "RuntimeInvoker_X"),
        ("plain_name", "plain_name"),
        ("name_with_const(int) const", "name_with_const(int) const"),
        ("(only_parens)", "(only_parens)"),
        ("unbalanced)", "unbalanced)"),
        ("Foo::operator()", "Foo::operator()"),
        ("Foo::operator()(int)", "Foo::operator()"),
    ],
)
def test_strip_args_removes_only_a_trailing_balanced_argument_list(raw, expected):
    assert strip_args(raw) == expected


@pytest.mark.parametrize(
    "source,expected",
    [
        ("C:/b/Source/il2cppOutput/Contoso.App.Presentation__1.cpp", "Contoso.App.Presentation"),
        ("C:\\b\\Source\\il2cppOutput\\Unity.ResourceManager.cpp", "Unity.ResourceManager"),
        ("C:/b/Source/il2cppOutput/Generics__154.cpp", "Generics"),
        ("C:/b/IL2CPP/libil2cpp/codegen/il2cpp-codegen.h", None),
        ("C:/b/IL2CPP/libil2cpp/vm/Runtime.cpp", None),
        ("C:/b/Source/il2cppOutput/header.h", None),
        ("Contoso.App.Presentation__1.cpp", "Contoso.App.Presentation"),
        ("Generics__154.cpp", "Generics"),
        ("il2cpp-codegen.h", None),
        (None, None),
    ],
)
def test_assembly_is_derived_only_from_generated_cpp_files(source, expected):
    assert assembly_of(source) == expected


def test_app_assembly_matching_uses_glob_patterns():
    assert is_app_assembly("Contoso.App.Core", ["Contoso.*"])
    assert not is_app_assembly("Unity.Localization", ["Contoso.*"])
    assert not is_app_assembly(None, ["Contoso.*"])


def test_find_runs_collapses_consecutive_repeats_only():
    items = ["a", "b", "c", "b", "c", "b", "c", "d", "d", "d", "e"]

    runs = [(r.start, r.period, r.count) for r in find_runs(items)]

    assert runs == [(0, 1, 1), (1, 2, 3), (7, 1, 3), (10, 1, 1)]


def test_find_runs_returns_single_runs_when_nothing_repeats():
    assert [(r.start, r.period, r.count) for r in find_runs(["a", "b", "c"])] == [(0, 1, 1), (1, 1, 1), (2, 1, 1)]
    assert find_runs([]) == []


def test_find_runs_does_not_merge_non_adjacent_repeats():
    assert [(r.start, r.count) for r in find_runs(["a", "b", "a"])] == [(0, 1), (1, 1), (2, 1)]
