from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..config import Config
from ..model import Frame, Session
from ..naming import assembly_of, is_app_assembly, short_name
from .origin import find_origin
from .rules import load_rules
from .rules.base import Finding, RuleContext
from .stuck import ThreadAnalysis, analyze_threads, rank_main_threads

MAX_THREAD_ROWS = 40
_WAIT_MARKERS = ("pthread_cond_wait", "futex_wait", "epoll_wait")


@dataclass
class AnalysisResult:
    session_id: str
    package: str
    pid: int
    sample_count: int
    observation: str
    main_threads: list[ThreadAnalysis] = field(default_factory=list)
    busy_threads: list[ThreadAnalysis] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    origin: dict | None = None
    origin_note: str = ""
    reached: list[str] = field(default_factory=list)
    thread_table: list[dict] = field(default_factory=list)
    memory: list[dict] = field(default_factory=list)
    # 主スレッドの選定理由と候補一覧。同名スレッドが複数ある場合に取り違えを確認できるようにする。
    main_note: str = ""
    main_ambiguous: bool = False
    main_candidates: list[dict] = field(default_factory=list)
    # 選んだ主スレッドのサンプルごとの観測数 (稼働率ではない)。
    main_observation: dict = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        """旧名。人が停止と判断して起動する前提のため、判定ではなく観測結果として扱う。"""
        return self.observation

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_session(session: Session, cfg: Config) -> AnalysisResult:
    threads = analyze_threads(session, cfg)
    warnings = list(session.warnings)
    main_threads, main_note, main_ambiguous = rank_main_threads(threads)
    busy_threads = [t for t in threads if not t.is_main and t.stuck and t.classification == "spinning"]

    if main_ambiguous:
        warnings.append(main_note)
    if not session.samples:
        warnings.append("サンプルがありません")
    if not main_threads:
        warnings.append(f"主スレッドが見つかりません (名前: {', '.join(cfg.main_thread_names)})")

    rules = load_rules(cfg.rules)
    findings: list[Finding] = []
    # 規則は採用した主スレッドだけに適用する (同名の別候補の所見を混ぜない)。
    for thread in main_threads[:1]:
        if not thread.stuck:
            continue
        ctx = RuleContext(thread)
        for rule in rules:
            finding = rule.check(ctx)
            if finding is not None:
                findings.append(finding)

    origin, origin_note, reached = _origin(main_threads, cfg, session)
    return AnalysisResult(
        session_id=session.session_id,
        package=session.package,
        pid=session.pid,
        sample_count=len(session.samples),
        observation=_observation(main_threads),
        main_threads=main_threads,
        busy_threads=busy_threads,
        findings=findings,
        warnings=warnings,
        origin=origin,
        origin_note=origin_note,
        reached=reached,
        thread_table=_thread_table(threads),
        memory=_memory(session),
        main_note=main_note,
        main_ambiguous=main_ambiguous,
        main_candidates=[_candidate(t, i == 0) for i, t in enumerate(main_threads)],
        main_observation=_main_observation(session, main_threads[0], cfg) if main_threads else {},
    )


def describe_main_observation(observation: dict) -> str:
    """主スレッドで IL2CPP を観測したサンプル数の説明文。稼働率や停止確率ではない。"""
    if not observation:
        return ""
    text = (
        f"主スレッドで IL2CPP を観測したサンプル: {observation['il2cpp']}/{observation['total']} "
        f"(スタック取得 {observation['with_stack']} 件、うち自社メソッドを観測 {observation['app']} 件)。"
    )
    if observation["unidentified_library"]:
        text += f" ライブラリ不明のフレームを含むサンプルが {observation['unidentified_library']} 件あり、それらは IL2CPP の有無を判定できません。"
    return text + " (稼働率や停止確率ではありません)"


def _candidate(thread: ThreadAnalysis, selected: bool) -> dict:
    return {
        "name": thread.name,
        "sys_tid": thread.sys_tid,
        "selected": selected,
        "samples_seen": thread.samples_seen,
        "samples_total": thread.samples_total,
        "in_latest_sample": thread.in_latest_sample,
        "attached": thread.attached,
        "unity_player": thread.unity_player,
        "cpu_ticks_delta": thread.cpu_ticks_delta,
    }


def _is_il2cpp(frame: Frame) -> bool:
    return frame.module_name.lower() == "libil2cpp.so" or frame.library == "libil2cpp.so"


def _is_unidentified_library(frame: Frame) -> bool:
    # BuildId を持つがどのライブラリか分からない (シンボル未取り込み)。memfd:jit-cache など BuildId 無しは含めない。
    return frame.map_offset is not None and frame.library is None and frame.build_id is not None


def _main_observation(session: Session, main: ThreadAnalysis, cfg: Config) -> dict:
    """選んだ主スレッドについて、IL2CPP や自社メソッドを観測したサンプル数を数える。"""
    with_stack = il2cpp = app = unidentified = 0
    for sample in session.samples:
        thread = next((t for t in sample.threads if t.key == main.key), None)
        if thread is None or not thread.frames:
            continue
        with_stack += 1
        if any(_is_il2cpp(f) for f in thread.frames):
            il2cpp += 1
        if any(is_app_assembly(assembly_of(f.source_file), cfg.app_assemblies) for f in thread.frames):
            app += 1
        if any(_is_unidentified_library(f) for f in thread.frames):
            unidentified += 1
    return {
        "total": len(session.samples),
        "with_stack": with_stack,
        "il2cpp": il2cpp,
        "app": app,
        "unidentified_library": unidentified,
    }


def _origin(main_threads: list[ThreadAnalysis], cfg: Config, session: Session) -> tuple[dict | None, str, list[str]]:
    """最新サンプルの経路から、最後に到達した自社メソッドと、そこまでに通った自社メソッドを返す。"""
    if not main_threads:
        return None, "主スレッドが見つからないため、到達点を判定できません。", []
    main = main_threads[0]
    if not main.in_latest_sample:
        return None, "最新のサンプルに主スレッドが存在しないため、到達点を判定できません。", []
    origin, reached = find_origin(main, cfg.app_assemblies)
    if origin is not None:
        return origin, "", reached
    return None, _origin_note(main, cfg, session), []


def _origin_note(main: ThreadAnalysis, cfg: Config, session: Session) -> str:
    """判定できない理由。シンボルの問題と、アプリのコードが動いていない状態を区別する。"""
    if any(f.source_file for f in main.frames):
        if not cfg.app_assemblies:
            return "app_assemblies が未設定のため、到達点を判定できません (設定ファイルの [analysis] app_assemblies に自社アセンブリを指定してください)。"
        return f"経路上に自社アセンブリ ({', '.join(cfg.app_assemblies)}) のメソッドが見つかりません。"
    screen = _screen_note(session)
    # BuildId を持つものだけがシンボル解決の候補。memfd:jit-cache など BuildId の無い領域は含めない。
    unresolved = [f for f in main.frames if f.map_offset is not None and f.library is None and f.build_id is not None]
    has_il2cpp = any(f.module_name.lower() == "libil2cpp.so" or f.library == "libil2cpp.so" for f in main.frames)
    if has_il2cpp:
        return "IL2CPP のフレームはあるが生成元ファイルを解決できていません (シンボル未解決、または BuildId 不一致)。"
    if unresolved:
        return (
            "経路に名前が分からない共有ライブラリがあり、シンボル未解決と、アプリのコードが動いていない状態の"
            "どちらかは断定できません。" + screen
        )
    return (
        "最新サンプルの主スレッドのスタックに、IL2CPP のフレームは見つかりませんでした。正常に動いていても起こり得ます。"
        + _wait_note(main)
        + screen
    )


def _wait_note(main: ThreadAnalysis) -> str:
    """待機呼び出しの根拠がスタックにあるときだけ、待機中であることを添える。"""
    for frame in main.frames:
        name = frame.display_name().lower()
        for marker in _WAIT_MARKERS:
            if marker in name:
                return f" スタック内に待機呼び出し ({marker}) があります。"
    return ""


def _screen_note(session: Session) -> str:
    """取得している場合だけ、画面のスリープ状態を併記する。"""
    wakefulness = session.device.get("power", {}).get("mWakefulness")
    if not wakefulness:
        return ""
    if wakefulness == "Awake":
        return f" 画面の状態: {wakefulness}。"
    return f" 画面の状態: {wakefulness} (画面がスリープ中のため、アプリが動いていない可能性があります)。"


def _observation(main_threads: list[ThreadAnalysis]) -> str:
    """参考の観測結果。人が停止と判断して起動する前提のため、停止の断定はしない。"""
    if not main_threads:
        return "主スレッドを特定できませんでした。"
    main = main_threads[0]
    cpu = {
        "spinning": "CPU を消費し続けています (空回りの可能性)",
        "waiting": "CPU をほとんど消費していません (待機の可能性)",
        "mixed": "CPU 消費は中程度です",
        "unknown": "CPU 消費は不明です",
    }[main.classification]
    if main.stuck:
        return f"全 {main.samples_total} サンプルで同じ経路 (共通フレーム {main.common_len} 件) にあり、{cpu}。"
    return f"サンプル間で経路が変化しています (共通フレームは経路全体の {main.common_ratio * 100:.0f}%)。{cpu}。"


def _thread_table(threads: list[ThreadAnalysis]) -> list[dict]:
    rows = []
    for thread in threads:
        innermost = thread.frames[0] if thread.frames else None
        rows.append(
            {
                "name": thread.name,
                "sys_tid": thread.sys_tid,
                "attached": thread.attached,
                "is_main": thread.is_main,
                "os_states": thread.os_states,
                "cpu_ticks_delta": thread.cpu_ticks_delta,
                "cpu_ratio": thread.cpu_ratio,
                "samples_seen": thread.samples_seen,
                "same_path": thread.stuck,
                "common_len": thread.common_len,
                "depth": len(thread.frames),
                "innermost": short_name(innermost.display_name()) if innermost else "",
                "innermost_library": innermost.module_label if innermost else "",
            }
        )
    rows.sort(key=lambda r: (not r["is_main"], -(r["cpu_ticks_delta"] or 0), r["name"]))
    return rows[:MAX_THREAD_ROWS]


def _memory(session: Session) -> list[dict]:
    return [
        {"index": s.index, "time": s.device_time, **s.meminfo}
        for s in sorted(session.proc_snapshots, key=lambda s: s.index)
        if s.meminfo
    ]
