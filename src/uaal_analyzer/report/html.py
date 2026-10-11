from __future__ import annotations

import json
from html import escape

from ..analyze.engine import AnalysisResult, describe_main_observation
from ..analyze.stuck import ThreadAnalysis
from ..model import Session
from ..naming import assembly_of, is_app_assembly, short_name
from ..timeutil import parse_device_time
from .compress import find_runs

HEAD_LINES = 60
TAIL_LINES = 80

_STYLE = """
body{font-family:system-ui,'Segoe UI','Yu Gothic UI',sans-serif;margin:0;color:#1f2328;background:#f6f8fa}
header{background:#24292f;color:#fff;padding:12px 20px}
header h1{font-size:16px;margin:0 0 4px}header p{margin:0;font-size:12px;opacity:.8}
nav{display:flex;flex-wrap:wrap;gap:4px;padding:8px 20px 0;background:#fff;border-bottom:1px solid #d0d7de}
nav button{border:0;background:none;padding:8px 14px;cursor:pointer;font-size:14px;border-bottom:3px solid transparent}
nav button[aria-selected=true]{border-bottom-color:#0969da;font-weight:600}
main{padding:16px 20px;max-width:1200px}
section.tab{display:none}section.tab.active{display:block}
.card{background:#fff;border:1px solid #d0d7de;border-radius:6px;padding:12px 16px;margin-bottom:14px}
.origin{border-left:5px solid #cf222e;font-size:16px}.origin.none{border-left-color:#9a6700}
.note{color:#57606a;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px;background:#fff}
th,td{border:1px solid #d0d7de;padding:4px 8px;text-align:left;vertical-align:top}th{background:#f6f8fa}
td.num{text-align:right;font-variant-numeric:tabular-nums}
pre{background:#0d1117;color:#e6edf3;padding:10px;border-radius:6px;overflow:auto;font-size:12px;line-height:1.5;margin:0}
.f.common{color:#8b949e}.f.varies{color:#e6edf3}.f.app{color:#ffa657;font-weight:700}
.lv-E,.lv-F{color:#ff7b72}.lv-W{color:#d29922}.lv-I,.lv-D,.lv-V{color:#e6edf3}
.warn{color:#9a6700}ul{margin:6px 0 6px 18px;padding:0}
"""

_SCRIPT = """
document.querySelectorAll('nav button').forEach(b=>b.addEventListener('click',()=>{
 document.querySelectorAll('nav button').forEach(x=>x.setAttribute('aria-selected','false'));
 document.querySelectorAll('section.tab').forEach(s=>s.classList.remove('active'));
 b.setAttribute('aria-selected','true');document.getElementById(b.dataset.tab).classList.add('active');}));
"""

_TABS = (
    ("summary", "概要"),
    ("path", "到達経路"),
    ("threads", "全スレッド"),
    ("logs", "ログ"),
    ("process", "プロセスと画面"),
    ("device", "端末とビルド"),
    ("warnings", "警告と生データ"),
)


def render_html(session: Session, result: AnalysisResult, app_assemblies: list[str]) -> str:
    bodies = {
        "summary": _summary(result),
        "path": _path_tab(result, app_assemblies),
        "threads": _threads_tab(result),
        "logs": _logs_tab(session),
        "process": _process_tab(session, result),
        "device": _device_tab(session),
        "warnings": _warnings_tab(session, result),
    }
    nav = "".join(
        f'<button data-tab="{key}" aria-selected="{"true" if i == 0 else "false"}">{escape(label)}</button>'
        for i, (key, label) in enumerate(_TABS)
    )
    sections = "".join(
        f'<section class="tab{" active" if i == 0 else ""}" id="{key}">{bodies[key]}</section>'
        for i, (key, _) in enumerate(_TABS)
    )
    return (
        "<!DOCTYPE html><html lang=\"ja\"><head><meta charset=\"utf-8\">"
        f"<title>UaaLAnalyzer {escape(result.session_id)}</title><style>{_STYLE}</style></head><body>"
        f"<header><h1>UaaLAnalyzer レポート: {escape(result.session_id)}</h1>"
        f"<p>{escape(result.package)} (pid {result.pid}) / サンプル {result.sample_count} 件</p></header>"
        f"<nav>{nav}</nav><main>{sections}</main><script>{_SCRIPT}</script></body></html>"
    )


def _summary(result: AnalysisResult) -> str:
    if result.origin:
        origin = result.origin
        head = (
            f'<div class="card origin"><strong>最後に到達した自社メソッド</strong><br>'
            f"{escape(origin['function'])} <span class=\"note\">({escape(origin['assembly'] or '')} / {escape(origin['library'])})</span></div>"
        )
    else:
        head = f'<div class="card origin none"><strong>自社メソッドを判定できません</strong><br>{escape(result.origin_note)}</div>'
    reached = ""
    if result.reached:
        items = "".join(f"<li>{escape(name)}</li>" for name in result.reached)
        reached = f'<div class="card"><strong>ここまで通った自社メソッド (外側 → 内側)</strong><ul>{items}</ul>' \
                  '<p class="note">スタックで分かるのは「今呼び出し中」のメソッドだけです。完了済みの処理は「ログ」タブで補ってください。</p></div>'
    findings = "".join(
        f"<li><strong>[{escape(f.rule_id)}]</strong> {escape(f.title)}<br><span class=\"note\">{escape(f.message)}</span><br>"
        f"<code>{escape(', '.join(short_name(e) for e in f.evidence))}</code></li>"
        for f in result.findings
    ) or "<li>該当なし</li>"
    return (
        head
        + reached
        + f'<div class="card"><strong>参考: 観測結果</strong><p>{escape(result.observation)}</p>'
        + f"<p>{escape(describe_main_observation(result.main_observation))}</p>"
        + _main_candidates_html(result)
        + '<p class="note">人が停止と判断して起動する前提のため、停止の断定はしません。</p></div>'
        + f'<div class="card"><strong>参考: 既知の危険パターン</strong><ul>{findings}</ul></div>'
    )


def _main_candidates_html(result: AnalysisResult) -> str:
    if len(result.main_candidates) < 2:
        return ""
    rows = "".join(
        "<tr>"
        f"<td>{'採用' if c['selected'] else ''}</td>"
        f"<td>{escape(str(c['name']))}</td><td class=\"num\">{escape(str(c['sys_tid']))}</td>"
        f"<td class=\"num\">{c['samples_seen']}/{c['samples_total']}</td>"
        f"<td>{'あり' if c['in_latest_sample'] else 'なし'}</td>"
        f"<td>{'登録済み' if c['attached'] else '未登録'}</td>"
        f"<td>{'あり' if c['unity_player'] else 'なし'}</td>"
        f"<td class=\"num\">{escape(str(c['cpu_ticks_delta']))}</td></tr>"
        for c in result.main_candidates
    )
    header = (
        "<tr><th></th><th>名前</th><th>tid</th><th>出現サンプル</th><th>最新サンプル</th>"
        "<th>ART</th><th>Unity プレイヤーの Java フレーム</th><th>tick差</th></tr>"
    )
    return f'<p class="note">{escape(result.main_note)}</p><table>{header}{rows}</table>'


def _path_tab(result: AnalysisResult, app_assemblies: list[str]) -> str:
    if not result.main_threads:
        return "<p>主スレッドが見つかりません。</p>"
    parts = []
    for position, thread in enumerate(result.main_threads):
        role = "採用" if position == 0 else "候補 (不採用)"
        parts.append(f"<h3>{escape(thread.name)} (tid {escape(str(thread.sys_tid))}, {role})</h3>")
        if not thread.in_latest_sample:
            parts.append('<p class="note warn">最新のサンプルに存在しません。下は最後に現れたサンプルの経路です。</p>')
        parts.append(
            f'<p class="note">共通フレーム {thread.common_len} 件 / 経路全体の {thread.common_ratio * 100:.0f}% / '
            f"OS 状態: {escape(' '.join(thread.os_states))} / 灰色は全サンプルで共通、白は変化あり、橙は自社メソッド。同じ並びの繰り返しは ×N に圧縮。</p>"
        )
        parts.append(f"<pre>{_stack_html(thread, app_assemblies)}</pre>")
    return "".join(parts)


def _stack_html(thread: ThreadAnalysis, app_assemblies: list[str]) -> str:
    frames = list(reversed(thread.frames))
    labels = [f"[{f.module_label}] {short_name(f.display_name())}" for f in frames]
    lines: list[str] = []
    for run in find_runs(labels):
        end = run.start + run.period * run.count
        common = "common" if end <= thread.common_len else "varies"
        block: list[tuple[str, str]] = []
        for offset in range(run.period):
            index = run.start + offset
            is_app = is_app_assembly(assembly_of(frames[index].source_file), app_assemblies)
            block.append(("app" if is_app else common, labels[index] + _inlined_suffix(frames[index].inlined)))
        if run.count > 1 and run.period == 1:
            block[0] = (block[0][0], f"{block[0][1]}  ×{run.count}")
        elif run.count > 1:
            block.append(("varies", f"  (上の {run.period} 行を ×{run.count} 回繰り返し)"))
        lines += [f'<span class="f {css}">{escape(text)}</span>' for css, text in block]
    if len(lines) > HEAD_LINES + TAIL_LINES:
        omitted = len(lines) - HEAD_LINES - TAIL_LINES
        lines = lines[:HEAD_LINES] + [f'<span class="f varies">... 中間 {omitted} 行を省略</span>'] + lines[-TAIL_LINES:]
    return "\n".join(lines)


def _inlined_suffix(inlined: list[str]) -> str:
    if not inlined:
        return ""
    return "  [インライン展開: " + " → ".join(short_name(name) for name in inlined) + "]"


def _threads_tab(result: AnalysisResult) -> str:
    if not result.thread_table:
        return "<p>スレッド情報がありません。</p>"
    rows = []
    for row in result.thread_table:
        ratio = "-" if row["cpu_ratio"] is None else f"{row['cpu_ratio'] * 100:.0f}%"
        rows.append(
            "<tr>"
            f"<td>{escape(str(row['name']))}{' (主)' if row['is_main'] else ''}</td>"
            f"<td class=\"num\">{escape(str(row['sys_tid']))}{'' if row['attached'] else ' (ART未登録)'}</td>"
            f"<td>{escape(' '.join(row['os_states']))}</td>"
            f"<td class=\"num\">{escape(ratio)}</td>"
            f"<td class=\"num\">{escape(str(row['cpu_ticks_delta']))}</td>"
            f"<td>{'同じ' if row['same_path'] else '変化'}</td>"
            f"<td class=\"num\">{row['depth']}</td>"
            f"<td>{escape(row['innermost_library'])}: {escape(row['innermost'])}</td></tr>"
        )
    header = "<tr><th>スレッド</th><th>tid</th><th>OS状態の推移</th><th>CPU</th><th>tick差</th><th>経路</th><th>深さ</th><th>最内側のフレーム</th></tr>"
    return f'<p class="note">主スレッドを先頭に、CPU を多く使った順に並べています。</p><table>{header}{"".join(rows)}</table>'


def _logs_tab(session: Session) -> str:
    logs = session.logs
    if not logs:
        return "<p>ログは取得されていません (bugreport から抽出できませんでした)。</p>"
    entries = logs.get("logs", [])
    rng = logs.get("log_range", {})
    head = (
        f'<p class="note">対象 PID のログ {logs.get("log_total", 0)} 件中、取得の直前までの直近 {len(entries)} 行を表示 '
        f'(うち Unity タグ {logs.get("unity_log_count", 0)} 件)。'
        f'このツールが送った SIGQUIT への ART の応答 {logs.get("self_signal_count", 0)} 件は表示から除外しています (全件は raw/bugreport.zip)。'
        f' logcat 全体の範囲: {escape(str(rng.get("first", "")))} 〜 {escape(str(rng.get("last", "")))}</p>'
    )
    lines = "\n".join(
        f'<span class="lv-{escape(e["level"])}">{escape(e["time"])} {escape(e["level"])} {escape(e["tag"])}: {escape(e["message"])}</span>'
        for e in entries
    )
    return head + f"<pre>{lines}</pre>"


def _process_tab(session: Session, result: AnalysisResult) -> str:
    parts = []
    if result.memory:
        keys = [k for k in ("total_pss", "total_rss", "total_swap_pss", "java_heap_pss", "native_heap_pss", "graphics_pss", "code_pss", "stack_pss") if any(k in m for m in result.memory)]
        header = "<tr><th>sample</th><th>時刻</th>" + "".join(f"<th>{escape(k)} (kB)</th>" for k in keys) + "</tr>"
        rows = "".join(
            f"<tr><td class=\"num\">{m['index']}</td><td>{escape(str(m['time']))}</td>"
            + "".join(f"<td class=\"num\">{escape(str(m.get(k, '')))}</td>" for k in keys)
            + "</tr>"
            for m in result.memory
        )
        parts.append(f"<h3>メモリの推移 (dumpsys meminfo)</h3><table>{header}{rows}</table>")
    wchan_rows = _wchan_rows(session)
    if wchan_rows:
        parts.append(f"<h3>スレッドの待機先 (wchan、最後のサンプル)</h3><table><tr><th>tid</th><th>スレッド</th><th>wchan</th></tr>{wchan_rows}</table>")
    device = session.device
    if device.get("process"):
        parts.append("<h3>プロセス状態</h3>" + _kv_table(device["process"]))
    if device.get("window"):
        parts.append("<h3>フォーカス中のウィンドウ</h3>" + _kv_table(device["window"]))
    if device.get("power"):
        parts.append("<h3>画面の状態 (dumpsys power)</h3>" + _kv_table(device["power"]))
    if device.get("layers") is not None:
        layers = "".join(f"<li>{escape(l)}</li>" for l in device["layers"]) or "<li>対象パッケージのレイヤーがありません</li>"
        parts.append(f"<h3>SurfaceFlinger のレイヤー (対象パッケージ)</h3><ul>{layers}</ul>")
    logs = session.logs
    if logs.get("system_meminfo"):
        parts.append("<h3>端末全体のメモリ (kB)</h3>" + _kv_table(logs["system_meminfo"]))
    if logs.get("kernel_lines"):
        kernel = "\n".join(escape(l) for l in logs["kernel_lines"])
        parts.append(f"<h3>カーネルログの関連行</h3><pre>{kernel}</pre>")
    if logs.get("thermal_lines"):
        parts.append("<h3>温度</h3><pre>" + "\n".join(escape(l) for l in logs["thermal_lines"]) + "</pre>")
    return ("".join(parts) or "<p>プロセス・画面の情報は取得されていません。</p>") + _timing_table(session)


def _timing_table(session: Session) -> str:
    """取得回ごとの所要秒 (パソコン側計測) と、ART トレースの時刻の間隔を別々の表にする。

    抽出できたトレースの件数が送信回数と異なることがあるため、番号では結び付けない。
    """
    parts = []
    keys = ("top", "stat", "wchan", "meminfo", "sigquit", "sample_total")
    snapshots = sorted(session.proc_snapshots, key=lambda s: s.index)
    if snapshots:
        rows = []
        for snapshot in snapshots:
            cells = "".join(
                f'<td class="num">{snapshot.timings[key]:.2f}</td>' if key in snapshot.timings else "<td>未計測</td>"
                for key in keys
            )
            rows.append(
                f'<tr><td class="num">{snapshot.index + 1}</td><td>{escape(snapshot.device_time or "-")}</td>{cells}</tr>'
            )
        header = (
            "<tr><th>取得回</th><th>端末時刻 (取得開始)</th><th>top</th><th>stat</th><th>wchan</th><th>meminfo</th>"
            "<th>SIGQUIT 送信</th><th>1 回分の合計 (待ち時間を含む)</th></tr>"
        )
        note = (
            '<p class="note">所要秒はパソコン側の単調時計で計測。SIGQUIT の送信時間は ART のダンプ完了までの時間ではありません。'
            "「未計測」は所要秒を記録する前のデータです。設定の待ち時間は "
            f'{escape(str(session.capture.get("interval_sec", "-")))} 秒です。</p>'
        )
        parts.append(f"<h3>取得の所要時間 (送信順)</h3>{note}<table>{header}{''.join(rows)}</table>")
    samples = sorted(session.samples, key=lambda s: s.index)
    if samples:
        rows = []
        previous = None
        for sample in samples:
            current = parse_device_time(sample.time)
            gap = "-" if previous is None else f"{(current - previous).total_seconds():.1f}"
            previous = current
            rows.append(f'<tr><td class="num">{sample.index}</td><td>{escape(sample.time)}</td><td class="num">{gap}</td></tr>')
        header = "<tr><th>sample</th><th>ART トレースの時刻</th><th>前回との間隔 (秒)</th></tr>"
        parts.append(f"<h3>ART トレースの時刻と間隔</h3><table>{header}{''.join(rows)}</table>")
    return "".join(parts)


def _wchan_rows(session: Session) -> str:
    snapshots = [s for s in session.proc_snapshots if s.wchan]
    if not snapshots:
        return ""
    last = max(snapshots, key=lambda s: s.index)
    names = {str(t.tid): t.comm for t in last.threads}
    rows = [
        f"<tr><td class=\"num\">{escape(tid)}</td><td>{escape(names.get(tid, ''))}</td><td>{escape(wchan or '(取得不可)')}</td></tr>"
        for tid, wchan in sorted(last.wchan.items(), key=lambda kv: int(kv[0]))
    ]
    return "".join(rows)


def _device_tab(session: Session) -> str:
    device = session.device
    parts = []
    if device.get("props"):
        parts.append("<h3>端末</h3>" + _kv_table(device["props"]))
    if device.get("package"):
        parts.append("<h3>APK</h3>" + _kv_table(device["package"]))
    if session.symbol_report:
        rows = "".join(
            f"<tr><td>{escape(str(info.get('module', '?')))}</td><td><code>{escape(build_id)}</code></td>"
            f"<td>{escape(_symbol_detail(info))}</td></tr>"
            for build_id, info in session.symbol_report.items()
        )
        parts.append(f"<h3>ライブラリの BuildId とシンボル解決</h3><table><tr><th>ライブラリ</th><th>BuildId</th><th>解決</th></tr>{rows}</table>")
    return "".join(parts) or "<p>端末・ビルドの情報は取得されていません。</p>"


def _symbol_detail(info: dict) -> str:
    if info.get("status") == "resolved":
        return f"{info.get('resolved', 0)}/{info.get('frames', 0)} フレーム解決"
    return str(info.get("status", ""))


def _warnings_tab(session: Session, result: AnalysisResult) -> str:
    warnings = "".join(f'<li class="warn">{escape(w)}</li>' for w in result.warnings) or "<li>警告なし</li>"
    capture = escape(json.dumps(session.capture, ensure_ascii=False))
    return (
        f"<h3>警告</h3><ul>{warnings}</ul>"
        f"<h3>取得条件</h3><p><code>{capture}</code></p>"
        '<h3>生データ</h3><p class="note">raw/ に bugreport.zip、top_*.txt、stat_*.txt、getprop.txt、dumpsys_*.txt などを保存しています。</p>'
    )


def _kv_table(values: dict) -> str:
    rows = "".join(f"<tr><th>{escape(str(k))}</th><td>{escape(str(v))}</td></tr>" for k, v in values.items())
    return f"<table>{rows}</table>"
