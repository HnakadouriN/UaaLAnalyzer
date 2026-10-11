from __future__ import annotations

from ..analyze.engine import AnalysisResult, describe_main_observation
from ..model import Session
from ..naming import short_name

MAX_REACHED = 12
MAX_LOG_LINES = 15
MAX_WARNINGS = 10


def render_report(session: Session, result: AnalysisResult) -> str:
    """Issue や会話に貼れる短い要約。詳細は report.html を参照する。"""
    first = session.samples[0].time if session.samples else "-"
    last = session.samples[-1].time if session.samples else "-"
    lines: list[str] = [
        "# UaaLAnalyzer 要約",
        "",
        f"- セッション: {result.session_id}",
        f"- 対象: {result.package} (pid {result.pid})",
        f"- サンプル: {result.sample_count} 件 ({first} 〜 {last})",
        "",
        "## 最後に到達した自社メソッド",
        "",
    ]
    if result.origin:
        origin = result.origin
        lines.append(f"{origin['function']} ({origin['assembly']} / {origin['library']})")
    else:
        lines.append(f"判定できません: {result.origin_note}")
    lines.append("")

    if result.reached:
        lines += ["## ここまで通った自社メソッド (外側 → 内側)", ""]
        lines += [f"1. {name}" if i == 0 else f"{i + 1}. {name}" for i, name in enumerate(result.reached[-MAX_REACHED:])]
        lines += ["", "スタックで分かるのは「今呼び出し中」のメソッドだけです。完了済みの処理は下のログで補います。", ""]

    lines += ["## 参考: 観測結果", "", result.observation, ""]
    observed = describe_main_observation(result.main_observation)
    if observed:
        lines += [observed, ""]
    if result.main_note:
        lines += [result.main_note, ""]

    lines += ["## 参考: 既知の危険パターン", ""]
    if result.findings:
        for finding in result.findings:
            evidence = ", ".join(short_name(e) for e in finding.evidence)
            lines.append(f"- [{finding.rule_id}] {finding.title} ({evidence})")
    else:
        lines.append("該当なし")
    lines.append("")

    entries = session.logs.get("logs", [])
    if entries:
        lines += [f"## 直近のログ (対象 PID、新しい側の {min(len(entries), MAX_LOG_LINES)} 行)", ""]
        skipped = session.logs.get("self_signal_count", 0)
        if skipped:
            lines += [f"このツールが送った SIGQUIT への応答 {skipped} 件は除外済み。", ""]
        lines.append("```")
        for entry in entries[-MAX_LOG_LINES:]:
            lines.append(f"{entry['time']} {entry['level']} {entry['tag']}: {entry['message']}")
        lines += ["```", ""]

    if result.warnings:
        lines += ["## 警告", ""]
        lines += [f"- {w}" for w in result.warnings[:MAX_WARNINGS]]
        if len(result.warnings) > MAX_WARNINGS:
            lines.append(f"- ほか {len(result.warnings) - MAX_WARNINGS} 件 (report.html を参照)")
        lines.append("")

    lines += ["詳細 (到達経路・全スレッド・ログ全体・プロセスと画面): report.html", ""]
    return "\n".join(lines)