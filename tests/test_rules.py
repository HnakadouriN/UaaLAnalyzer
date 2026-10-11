from __future__ import annotations

import pytest

from uaal_analyzer.analyze.rules import load_rules
from uaal_analyzer.analyze.rules.base import RuleContext
from uaal_analyzer.analyze.stuck import ThreadAnalysis
from uaal_analyzer.errors import ConfigError
from uaal_analyzer.model import Frame


def _thread(names: list[str], module: str = "libil2cpp.so", common: int | None = None) -> ThreadAnalysis:
    frames = [Frame(index=i, kind="native", pc=0x10 * i, module=f"/lib/{module}", resolved=name) for i, name in enumerate(names)]
    return ThreadAnalysis(
        key=1,
        name="UnityMain",
        sys_tid=1,
        is_main=True,
        samples_seen=3,
        samples_total=3,
        os_states=["R", "R", "R"],
        art_states=["Runnable"] * 3,
        common_len=len(frames) if common is None else common,
        stuck=True,
        cpu_ticks_delta=0,
        window_sec=4.0,
        cpu_ratio=0.0,
        classification="waiting",
        frames=frames,
    )


def _check(rule_id: str, thread: ThreadAnalysis):
    rule = next(r for r in load_rules() if r.id == rule_id)
    return rule.check(RuleContext(thread))


@pytest.mark.parametrize(
    "rule_id,hit,miss",
    [
        ("wait-for-completion", "AsyncOperationBase_WaitForCompletion_m1", "AsyncOperationBase_Complete_m1"),
        ("task-wait", "System_Threading_Tasks_Task_Wait_m123", "System_Threading_Tasks_Task_WaitAsync_m1"),
        ("task-wait", "Task_1_get_Result_m9", "Task_Run_m9"),
        ("task-wait", "System.Threading.Tasks.Task.Wait", "TaskScheduler_Schedule"),
        ("task-wait", "TaskAwaiter_GetResult_m5", "TaskAwaiter_OnCompleted_m5"),
        ("lock-wait", "pthread_mutex_lock", "pthread_mutex_unlock"),
        ("lock-wait", "System_Threading_Monitor_Enter_m12", "System_Threading_Monitor_Exit_m12"),
        ("lock-wait", "__futex_wait_ex", "epoll_wait"),
    ],
)
def test_rule_detects_hit_and_ignores_miss(rule_id, hit, miss):
    found = _check(rule_id, _thread(["outer", hit, "inner"]))
    assert found is not None
    assert found.rule_id == rule_id
    assert hit in found.evidence

    assert _check(rule_id, _thread(["outer", miss, "inner"])) is None


def test_binder_rule_matches_by_module_and_symbol():
    by_module = _thread(["transact"], module="libbinder.so")
    by_symbol = _thread(["android.os.BinderProxy.transact"], module="java")
    assert _check("binder-on-main", by_module) is not None
    assert _check("binder-on-main", by_symbol) is not None
    assert _check("binder-on-main", _thread(["epoll_wait"], module="libc.so")) is None


def test_rules_only_look_at_frames_common_to_all_samples():
    thread = _thread(["a", "AsyncOperationBase_WaitForCompletion", "b"], common=1)
    # frames は内側 -> 外側。共通なのは最も外側の 1 フレーム ("b") だけ。
    assert _check("wait-for-completion", thread) is None


def test_load_rules_filters_by_name_and_rejects_unknown():
    assert [r.id for r in load_rules(["task-wait"])] == ["task-wait"]
    assert {r.id for r in load_rules()} >= {"wait-for-completion", "task-wait", "lock-wait", "binder-on-main"}
    with pytest.raises(ConfigError):
        load_rules(["nope"])
