from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

from .adb import Adb
from .analyze.engine import AnalysisResult, analyze_session
from .collect.capture import CaptureOptions, rebuild_session, run_capture
from .collect.target import resolve_target
from .config import Config, config_for_package, load_config
from .errors import SymbolError, UaalError
from .model import Session, load_session, save_json, save_session
from .ndk import ndk_tool
from .project_setup import write_project_config
from .report.html import render_html
from .report.markdown import render_report
from .symbolize.resolver import Addr2LineResolver
from .symbolize.symbolizer import needed_build_ids, symbolize_session
from .symbols.importer import import_symbols, make_build_id_reader
from .symbols.index import SymbolIndex, ensure_symbols
from .symbols.store import SymbolStore


class _NoResolver:
    def resolve(self, symbol_file: Path, addresses: list[int]) -> dict[int, str]:
        raise SymbolError("解決対象がありません")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="uaal", description="UaaL (Unity as a Library) 停止解析ツール")
    parser.add_argument("--config", type=Path, help="設定ファイル (既定: configs/example.toml)")
    parser.add_argument("--data-dir", type=Path, help="データ置き場 (既定: <ツール>/data)")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (("capture", "端末からスタックを取得して session.json を作る"), ("run", "取得 → シンボル解決 → 解析を一括実行")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--package", help="対象のパッケージ名 (既定: 前面の Unity アプリを自動で検出)")
        p.add_argument("--pid", type=int, help="対象 PID (既定: パッケージの Unity プロセスを検出)")
        p.add_argument("--serial", help="adb のデバイスシリアル")
        p.add_argument("--samples", type=int, help="SIGQUIT を送る回数")
        p.add_argument("--interval", type=float, help="サンプル間隔 (秒)")
        p.add_argument("--session-name", help="セッション名 (既定: 日時)")

    init = sub.add_parser("init", help="Unity プロジェクトから設定ファイル (configs/<パッケージ名>.toml) を作る")
    init.add_argument("--project", type=Path, required=True, help="Unity プロジェクトのパス (Assets と ProjectSettings があるフォルダ)")
    init.add_argument("--package", help="パッケージ名 (既定: 前面の Unity アプリを自動で検出)")
    init.add_argument("--serial", help="adb のデバイスシリアル")
    init.add_argument("--force", action="store_true", help="同名の設定ファイルを上書きする")

    symbols = sub.add_parser("symbols", help="シンボル保管庫の操作")
    symbols_sub = symbols.add_subparsers(dest="symbols_command", required=True)
    add = symbols_sub.add_parser("add", help="*.dbg.so を BuildId 付きで保管する")
    add.add_argument("paths", nargs="*", type=Path, help="ファイルまたはディレクトリ (省略時は設定の検索パス)")
    symbols_sub.add_parser("list", help="保管済みシンボルを表示する")

    for name, help_text in (
        ("symbolize", "session.json のフレームを名前解決する"),
        ("analyze", "停止箇所を抽出してレポートを出す"),
        ("rebuild", "保存済みの bugreport から session.json を再構築する"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("session", help="セッションのパス、またはセッション名 (latest 可)")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
    args = build_parser().parse_args(argv)
    try:
        cfg = load_config(args.config, args.data_dir)
        return _dispatch(args, cfg)
    except UaalError as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 1


_PHASE_LABELS = (
    ("prepare", "準備"),
    ("device_info", "端末情報"),
    ("sampling", "サンプル取得"),
    ("bugreport", "bugreport"),
    ("parse", "トレース解析"),
    ("symbolize", "シンボル解決"),
    ("report", "解析"),
)


def _format_phases(phases: dict[str, float]) -> str:
    """工程ごとの経過秒を 1 行にする。記録の無い工程は飛ばす。"""
    parts = [f"{label} {phases[key]:.1f}秒" for key, label in _PHASE_LABELS if key in phases]
    if not parts:
        return ""
    total = sum(phases[key] for key, _ in _PHASE_LABELS if key in phases)
    return "所要時間: " + " / ".join(parts) + f" / 合計 {total:.1f}秒"


def _dispatch(args: argparse.Namespace, cfg: Config) -> int:
    if args.command == "capture":
        session_dir, session, _ = _capture(args, cfg)
        print(f"保存しました: {session_dir / 'session.json'}")
        line = _format_phases(dict(session.capture.get("phase_sec", {})))
        if line:
            print(line)
    elif args.command == "run":
        session_dir, session, cfg = _capture(args, cfg)
        phases = dict(session.capture.get("phase_sec", {}))
        print("進捗: シンボル解決")
        started = time.monotonic()
        _symbolize(cfg, session_dir)
        phases["symbolize"] = round(time.monotonic() - started, 3)
        print("進捗: レポート作成")
        started = time.monotonic()
        result = _analyze(cfg, session_dir)
        phases["report"] = round(time.monotonic() - started, 3)
        _print_analysis(result, session_dir)
        print(_format_phases(phases))
    elif args.command == "symbols":
        _symbols(args, cfg)
    elif args.command == "init":
        _init(args, cfg)
    elif args.command == "symbolize":
        session_dir = _session_dir(cfg, args.session)
        _symbolize(cfg, session_dir)
        print(f"保存しました: {session_dir / 'symbolized.json'}")
    elif args.command == "analyze":
        session_dir = _session_dir(cfg, args.session)
        _print_analysis(_analyze(cfg, session_dir), session_dir)
    elif args.command == "rebuild":
        session_dir = _session_dir(cfg, args.session)
        session = rebuild_session(session_dir, cfg.time_margin_sec)
        print(f"再構築しました: {session_dir / 'session.json'} (サンプル {len(session.samples)} 件)")
    return 0


def _session_dir(cfg: Config, reference: str) -> Path:
    candidate = Path(reference)
    if (candidate / "session.json").exists():
        return candidate
    if reference == "latest":
        sessions = sorted(p for p in cfg.sessions_dir.glob("*") if (p / "session.json").exists())
        if sessions:
            return sessions[-1]
    named = cfg.sessions_dir / reference
    if (named / "session.json").exists():
        return named
    raise UaalError(f"セッションが見つかりません: {reference}")


def _capture(args: argparse.Namespace, cfg: Config) -> tuple[Path, Session, Config]:
    """対象を決めて取得する。--config を指定しないときは、見つけたパッケージの設定ファイルがあればそれを使う。"""
    print("進捗: 準備")
    serial = args.serial or cfg.serial
    samples = args.samples or cfg.samples
    if samples < 2:
        raise UaalError("--samples は 2 以上にしてください")
    session_id = args.session_name or datetime.now().strftime("%Y%m%d-%H%M%S")
    if Path(session_id).name != session_id or session_id in ("", ".", ".."):
        raise UaalError(f"--session-name にパス区切りは使えません: {session_id!r}")
    session_dir = cfg.sessions_dir / session_id
    if session_dir.exists():
        raise UaalError(f"同名のセッションが既にあります: {session_dir}")

    adb = Adb(serial, cfg.adb)
    explicit_config = args.config is not None
    target = resolve_target(
        adb,
        package=args.package or "",
        pid=args.pid,
        config_package=cfg.package if explicit_config else "",
        main_names=cfg.main_thread_names,
    )
    print(f"対象: {target.package} pid={target.pid} (検出方法: {target.method})")
    notes = list(target.notes)
    if not explicit_config:
        chosen = config_for_package(target.package)
        if chosen is not None:
            cfg = load_config(chosen, args.data_dir)
            print(f"設定ファイル: {chosen}")
        elif cfg.package != target.package:
            assemblies = str(cfg.app_assemblies) if cfg.app_assemblies else "app_assemblies が未設定"
            note = (
                f"{target.package} 用の設定ファイルが無いため、既定の設定を使います (自社アセンブリ: {assemblies}。このアプリと合わない可能性)。"
                "`uaal init --project <Unity プロジェクト>` で設定ファイルを作ってください"
            )
            print(f"警告: {note}")
            notes.append(note)
    options = CaptureOptions(
        package=target.package,
        serial=serial,
        pid=target.pid,
        samples=args.samples or cfg.samples,
        interval_sec=args.interval if args.interval is not None else cfg.interval_sec,
        bugreport_timeout_sec=cfg.bugreport_timeout_sec,
        time_margin_sec=cfg.time_margin_sec,
        target=target.to_dict(),
        notes=notes,
    )
    session = run_capture(adb, options, session_dir, session_id)
    return session_dir, session, cfg


def _init(args: argparse.Namespace, cfg: Config) -> None:
    print("進捗: 準備")
    package = args.package or ""
    if not package:
        adb = Adb(args.serial or cfg.serial, cfg.adb)
        target = resolve_target(adb, main_names=cfg.main_thread_names)
        package = target.package
        print(f"対象: {package} (検出方法: {target.method})")
    print("進捗: 設定ファイル作成")
    result = write_project_config(args.project, package, force=args.force)
    print(f"設定ファイルを作りました: {result.path}")
    print(f"自社アセンブリ ({len(result.assemblies)} 件):")
    for name in result.assemblies:
        print(f"  - {name}")
    print(f"シンボルの場所 ({len(result.symbol_paths)} 件):")
    for path in result.symbol_paths:
        print(f"  - {path}")
    print(f"NDK: {result.ndk_bin or '(見つかりません)'}")
    for note in result.notes:
        print(f"注意: {note}")
    print("自社アセンブリの一覧がこのアプリのものだけか確認してから、uaal run を実行してください")


def _symbols(args: argparse.Namespace, cfg: Config) -> None:
    store = SymbolStore(cfg.symbols_dir)
    if args.symbols_command == "list":
        entries = store.entries()
        for entry in entries:
            print(f"{entry.build_id}  {entry.size:,} bytes  {entry.path}")
        if not entries:
            print("保管済みのシンボルはありません")
        return
    paths = list(args.paths) or [Path(p) for p in cfg.symbol_search_paths]
    if not paths:
        raise UaalError("取り込み先のパスを指定するか、symbols.search_paths を設定してください")
    reader = make_build_id_reader(ndk_tool(cfg.ndk_bin_dir, "llvm-readelf"))
    results = import_symbols(store, reader, paths)
    for result in results:
        if result.build_id is None:
            print(f"BuildId を読めないためスキップ: {result.source}")
        else:
            state = "保管済み" if result.already_stored else "取り込み"
            print(f"{state}: {result.build_id}  {result.source}")
    if not results:
        print("*.dbg.so が見つかりませんでした")


def _symbolize(cfg: Config, session_dir: Path) -> Session:
    session = load_session(session_dir / "session.json")
    store = SymbolStore(cfg.symbols_dir)
    needed = needed_build_ids(session, cfg.symbol_modules)
    library_names: dict[str, str] = {}
    if needed:
        reader = make_build_id_reader(ndk_tool(cfg.ndk_bin_dir, "llvm-readelf"))
        index = SymbolIndex(cfg.symbols_dir / "index.json", reader)
        index.scan([Path(p) for p in cfg.symbol_search_paths], cfg.symbol_patterns)
        ensure_symbols(store, index, needed)
        for build_id in needed:
            name = index.library_name(build_id) or store.library_name(build_id)
            if name:
                library_names[build_id] = name
        resolver = Addr2LineResolver(ndk_tool(cfg.ndk_bin_dir, "llvm-addr2line"))
    else:
        resolver = _NoResolver()
    result = symbolize_session(session, store, resolver, cfg.symbol_modules, library_names)
    save_session(session_dir / "symbolized.json", result)
    return result


def _analyze(cfg: Config, session_dir: Path) -> AnalysisResult:
    source = session_dir / "session.json"
    symbolized = session_dir / "symbolized.json"
    if symbolized.exists() and symbolized.stat().st_mtime >= source.stat().st_mtime:
        source = symbolized
    session = load_session(source)
    result = analyze_session(session, cfg)
    save_json(session_dir / "analysis.json", result.to_dict())
    (session_dir / "report.md").write_text(render_report(session, result), encoding="utf-8")
    (session_dir / "report.html").write_text(render_html(session, result, cfg.app_assemblies), encoding="utf-8")
    return result


def _print_analysis(result: AnalysisResult, session_dir: Path) -> None:
    if result.origin:
        print(f"最後に到達した自社メソッド: {result.origin['function']} ({result.origin['assembly']})")
    else:
        print(f"自社メソッドを判定できません: {result.origin_note}")
    print(f"観測結果 (参考): {result.observation}")
    for finding in result.findings:
        print(f"[{finding.rule_id}] {finding.title}")
    for warning in result.warnings:
        print(f"警告: {warning}")
    print(f"レポート: {session_dir / 'report.html'}")
