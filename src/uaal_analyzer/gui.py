from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Sequence

SRC_DIR = Path(__file__).resolve().parents[1]
TOOL_ROOT = SRC_DIR.parent
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_FINDING_RE = re.compile(r"^\[[\w-]+\] ")


# ---- 画面に依存しない処理 (テストの対象) ----


@dataclass
class Summary:
    target: str = ""
    origin: str = ""
    observation: str = ""
    findings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    timing: str = ""
    report: str = ""
    config_path: str = ""
    assemblies: list[str] = field(default_factory=list)


def default_session_name(now: datetime | None = None) -> str:
    return (now or datetime.now()).strftime("%Y%m%d-%H%M%S")


def validate_session_name(name: str) -> str | None:
    """セッション名に使えない場合の理由。使えるなら None。"""
    if not name.strip():
        return "セッション名を入力してください"
    if Path(name).name != name or name in (".", ".."):
        return "セッション名に「\\」「/」などのパス区切りは使えません"
    return None


def cli_python(executable: str | None = None) -> str:
    """CLI を起動する Python。pythonw.exe は標準出力を持たないため、同じ場所の python.exe に替える。"""
    exe = Path(executable or sys.executable)
    if exe.name.lower() == "pythonw.exe":
        console = exe.with_name("python.exe")
        if console.exists():
            return str(console)
    return str(exe)


def build_run_command(python: str, session_name: str, package: str = "", serial: str = "") -> list[str]:
    command = [python, "-m", "uaal_analyzer", "run", "--session-name", session_name]
    if package:
        command += ["--package", package]
    if serial:
        command += ["--serial", serial]
    return command


def build_init_command(
    python: str, project: str, package: str = "", serial: str = "", force: bool = False
) -> list[str]:
    command = [python, "-m", "uaal_analyzer", "init", "--project", project]
    if package:
        command += ["--package", package]
    if serial:
        command += ["--serial", serial]
    if force:
        command.append("--force")
    return command


def parse_devices(text: str) -> list[str]:
    """`adb devices` の出力から、接続中 (device) の端末のシリアルを返す。unauthorized などは含めない。"""
    serials: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device" and not line.startswith("*"):
            serials.append(parts[0])
    return serials


def is_existing_config_error(lines: Sequence[str]) -> bool:
    return any("設定ファイルが既にあります" in line for line in lines)


def parse_summary(lines: Sequence[str]) -> Summary:
    """CLI の出力から、画面に出す要点を取り出す。見つからない項目は空のまま。"""
    summary = Summary()
    in_assemblies = False
    for raw in lines:
        line = raw.rstrip()
        if in_assemblies and line.startswith("  - "):
            summary.assemblies.append(line[4:].strip())
            continue
        in_assemblies = False
        if line.startswith("対象:"):
            summary.target = summary.target or line[len("対象:") :].strip()
        elif line.startswith("最後に到達した自社メソッド:") or line.startswith("自社メソッドを判定できません:"):
            summary.origin = line
        elif line.startswith("観測結果 (参考):"):
            summary.observation = line[len("観測結果 (参考):") :].strip()
        elif _FINDING_RE.match(line):
            summary.findings.append(line)
        elif line.startswith("警告:"):
            summary.warnings.append(line[len("警告:") :].strip())
        elif line.startswith("注意:"):
            summary.warnings.append(line[len("注意:") :].strip())
        elif line.startswith("所要時間:"):
            summary.timing = line[len("所要時間:") :].strip()
        elif line.startswith("レポート:"):
            summary.report = line[len("レポート:") :].strip()
        elif line.startswith("設定ファイルを作りました:"):
            summary.config_path = line[len("設定ファイルを作りました:") :].strip()
        elif line.startswith("自社アセンブリ ("):
            in_assemblies = True
    return summary


# ---- 進捗 ----

PHASES_RUN = (
    ("prepare", "準備"),
    ("device_info", "端末情報"),
    ("sampling", "サンプル取得"),
    ("bugreport", "bugreport"),
    ("parse", "トレース解析"),
    ("symbolize", "シンボル解決"),
    ("report", "レポート作成"),
)
PHASES_INIT = (("prepare", "準備"), ("setup", "設定ファイル作成"))
# 前回の記録が無いときの目安 (秒)。timing-check (2026-10-08) の実測値。
DEFAULT_WEIGHTS = {
    "prepare": 1.0,
    "device_info": 2.0,
    "sampling": 40.0,
    "bugreport": 94.0,
    "parse": 1.0,
    "symbolize": 2.0,
    "report": 1.0,
    "setup": 2.0,
}
_PHASE_BY_LABEL = {label: key for key, label in PHASES_RUN + PHASES_INIT}
_PROGRESS_RE = re.compile(r"^進捗:\s*(?P<label>\S+)(?:\s+(?P<rest>.+))?$")


@dataclass
class ProgressEvent:
    phase: str
    done: int | None = None
    total: int | None = None
    percent: int | None = None
    elapsed: int | None = None

    @property
    def fraction(self) -> float | None:
        if self.done is not None and self.total:
            return self.done / self.total
        if self.percent is not None:
            return self.percent / 100
        return None

    @property
    def has_detail(self) -> bool:
        return any(v is not None for v in (self.done, self.percent, self.elapsed))


def parse_progress_line(line: str) -> ProgressEvent | None:
    """`進捗: サンプル取得 3/5` のような行を読む。知らない工程名や進捗ではない行は None。"""
    match = _PROGRESS_RE.match(line.strip())
    if match is None or match.group("label") not in _PHASE_BY_LABEL:
        return None
    event = ProgressEvent(_PHASE_BY_LABEL[match.group("label")])
    rest = match.group("rest") or ""
    count = re.search(r"(\d+)/(\d+)", rest)
    if count:
        event.done, event.total = int(count.group(1)), int(count.group(2))
    percent = re.search(r"(\d+)%", rest)
    if percent:
        event.percent = int(percent.group(1))
    elapsed = re.search(r"経過\s*(\d+)秒", rest)
    if elapsed:
        event.elapsed = int(elapsed.group(1))
    return event


@dataclass
class ProgressRow:
    label: str
    state: str  # pending | running | done | failed
    detail: str = ""
    seconds: float | None = None


@dataclass
class ProgressView:
    rows: list[ProgressRow]
    percent: int
    elapsed: float
    remaining: float | None
    finished: bool


class ProgressTracker:
    """`進捗:` 行を読んで、工程の一覧・全体の割合・残り時間の目安を求める。各工程の重みは目安の秒数。"""

    def __init__(
        self,
        phases: Sequence[tuple[str, str]],
        weights: dict[str, float] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._phases = list(phases)
        self._weights = [{**DEFAULT_WEIGHTS, **(weights or {})}.get(key, 1.0) for key, _ in self._phases]
        self._clock = clock
        self._started = clock()
        self._current = 0
        self._phase_start = self._started
        self._event: ProgressEvent | None = None
        self._done: dict[int, float] = {}
        self._finished = False
        self._failed: int | None = None
        self._end = self._started

    def feed(self, line: str) -> bool:
        """進捗行を反映したら True。戻る工程や知らない工程は無視する。"""
        event = parse_progress_line(line)
        keys = [key for key, _ in self._phases]
        if event is None or event.phase not in keys or self._finished:
            return False
        index = keys.index(event.phase)
        now = self._clock()
        if index < self._current:
            return False
        if index > self._current:
            self._done[self._current] = now - self._phase_start
            for skipped in range(self._current + 1, index):
                self._done[skipped] = 0.0
            self._current = index
            self._phase_start = now
            self._event = event
        elif event.has_detail:
            self._event = event
        return True

    def finish(self, ok: bool) -> None:
        now = self._clock()
        self._end = now
        self._finished = True
        if ok:
            self._done.setdefault(self._current, now - self._phase_start)
            for index in range(len(self._phases)):
                self._done.setdefault(index, 0.0)
        else:
            self._failed = self._current

    @property
    def finished(self) -> bool:
        return self._finished

    def _fraction(self, now: float) -> float:
        if self._event is not None and self._event.fraction is not None:
            return min(self._event.fraction, 0.99)
        weight = self._weights[self._current]
        return min((now - self._phase_start) / weight, 0.95) if weight > 0 else 0.0

    def _detail(self, now: float) -> str:
        parts: list[str] = []
        event = self._event
        if event is not None:
            if event.done is not None and event.total is not None:
                parts.append(f"{event.done}/{event.total}")
            if event.percent is not None:
                parts.append(f"{event.percent}%")
        elapsed = int(now - self._phase_start)
        parts.append(f"(経過 {elapsed}秒 / 目安 {int(self._weights[self._current])}秒)")
        return "  ".join(parts)

    def view(self) -> ProgressView:
        now = self._end if self._finished else self._clock()
        total = sum(self._weights) or 1.0
        rows: list[ProgressRow] = []
        for index, (_, label) in enumerate(self._phases):
            if index in self._done:
                seconds = self._done[index] or None
                rows.append(ProgressRow(label, "done", "", seconds))
            elif index == self._current and self._failed == index:
                rows.append(ProgressRow(label, "failed"))
            elif index == self._current and not self._finished:
                rows.append(ProgressRow(label, "running", self._detail(now)))
            else:
                rows.append(ProgressRow(label, "pending"))
        progressed = sum(self._weights[i] for i in self._done)
        if not self._finished:
            progressed += self._weights[self._current] * self._fraction(now)
        elif self._failed is not None:
            progressed += self._weights[self._current] * self._fraction(now)
        ok = self._finished and self._failed is None
        percent = 100 if ok else int(min(99, 100 * progressed / total))
        remaining = 0.0 if ok else (None if self._finished else max(0.0, total - progressed))
        return ProgressView(rows, percent, now - self._started, remaining, self._finished)


def format_duration(seconds: float) -> str:
    whole = int(seconds)
    return f"{whole // 60}分{whole % 60:02d}秒" if whole >= 60 else f"{whole}秒"


def format_remaining(seconds: float) -> str:
    return "約" + format_duration(seconds)


def format_row(row: ProgressRow) -> str:
    mark = {"done": "✔", "running": "▶", "failed": "✖"}.get(row.state, " ")
    text = f"{mark} {row.label}"
    if row.seconds is not None:
        text += f"  {row.seconds:.1f}秒"
    if row.detail:
        text += f"  {row.detail}"
    return text


def format_progress_summary(view: ProgressView) -> str:
    text = f"{view.percent}%  経過 {format_duration(view.elapsed)}"
    if view.remaining is not None and not view.finished:
        text += f"  残り {format_remaining(view.remaining)}"
    return text


def load_phase_weights(sessions_dir: Path) -> dict[str, float]:
    """直近のセッションの capture.phase_sec (前回の工程ごとの所要秒) を、目安として返す。無ければ空。"""
    try:
        candidates = sorted(sessions_dir.glob("*/session.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    except OSError:
        return {}
    for path in candidates[:3]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        phases = (data.get("capture") or {}).get("phase_sec") if isinstance(data, dict) else None
        if isinstance(phases, dict):
            weights = {
                key: float(value)
                for key, value in phases.items()
                if key in DEFAULT_WEIGHTS and isinstance(value, (int, float)) and value > 0
            }
            if weights:
                return weights
    return {}


class CommandRunner:
    """CLI を別プロセスで動かし、出力を 1 行ずつ queue に流す。("line", 文字列) の後、("done", 終了コード)。"""

    def __init__(
        self,
        command: Sequence[str],
        events: queue.Queue,
        popen: Callable[..., subprocess.Popen] = subprocess.Popen,
    ) -> None:
        self._command = list(command)
        self._events = events
        self._popen = popen
        self._process: subprocess.Popen | None = None
        self._stopped = False

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True).start()

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def stop(self) -> None:
        """実行中のコマンドと、その子プロセス (adb など) を止める。"""
        self._stopped = True
        process = self._process
        if process is None or process.poll() is not None:
            return
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, creationflags=_NO_WINDOW
            )
        else:
            process.terminate()

    def _run(self) -> None:
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        # パイプ経由では標準出力がまとめて送られ、進捗の行が終わるまで届かないため。
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONPATH"] = str(SRC_DIR) + os.pathsep + env.get("PYTHONPATH", "")
        try:
            self._process = self._popen(
                self._command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                cwd=str(TOOL_ROOT),
                creationflags=_NO_WINDOW,
            )
        except OSError as exc:
            self._events.put(("line", f"エラー: コマンドを起動できません: {exc}"))
            self._events.put(("done", -1))
            return
        assert self._process.stdout is not None
        for raw in self._process.stdout:
            self._events.put(("line", raw.decode("utf-8", errors="replace").rstrip("\r\n")))
        code = self._process.wait()
        if self._stopped:
            self._events.put(("line", "エラー: 中断しました"))
        self._events.put(("done", code))


def read_devices(adb: str = "adb") -> tuple[list[str], str]:
    """接続中の端末と、取得できなかったときの理由。"""
    try:
        result = subprocess.run([adb, "devices"], capture_output=True, timeout=15, creationflags=_NO_WINDOW)
    except FileNotFoundError:
        return [], "adb が見つかりません"
    except subprocess.TimeoutExpired:
        return [], "adb がタイムアウトしました"
    return parse_devices(result.stdout.decode("utf-8", errors="replace")), ""


# ---- 画面 ----


def _tk():
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk

    return tk, ttk, filedialog, messagebox, scrolledtext


class GuiApp:
    def __init__(self, root) -> None:
        tk, ttk, self._filedialog, self._messagebox, scrolledtext = _tk()
        self._root = root
        self._events: queue.Queue = queue.Queue()
        self._runner: CommandRunner | None = None
        self._kind = ""
        self._lines: list[str] = []
        self._python = cli_python()
        self._init_args: tuple[str, str] = ("", "")
        self._serials: list[str] = []
        self._weights: dict[str, float] = {}
        self._tracker: ProgressTracker | None = None
        root.title("UaaLAnalyzer")
        root.geometry("820x860")

        self._device_var = tk.StringVar()
        self._device_note = tk.StringVar(value="端末を確認中...")
        self._package_var = tk.StringVar()
        self._session_var = tk.StringVar(value=default_session_name())
        self._project_var = tk.StringVar()
        self._status_var = tk.StringVar(value="待機中")
        self._report_path = ""

        pad = {"padx": 8, "pady": 4}
        top = ttk.LabelFrame(root, text="計測")
        top.pack(fill="x", **pad)
        ttk.Label(top, text="端末").grid(row=0, column=0, sticky="w", **pad)
        self._device_box = ttk.Combobox(top, textvariable=self._device_var, state="readonly", width=24)
        self._device_box.grid(row=0, column=1, sticky="w", **pad)
        self._refresh_button = ttk.Button(top, text="再確認", command=self.refresh_devices)
        self._refresh_button.grid(row=0, column=2, **pad)
        ttk.Label(top, textvariable=self._device_note).grid(row=0, column=3, sticky="w", **pad)
        ttk.Label(top, text="パッケージ名").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(top, textvariable=self._package_var, width=40).grid(row=1, column=1, columnspan=2, sticky="w", **pad)
        ttk.Label(top, text="空欄なら前面の Unity アプリを自動で検出します").grid(row=1, column=3, sticky="w", **pad)
        ttk.Label(top, text="セッション名").grid(row=2, column=0, sticky="w", **pad)
        ttk.Entry(top, textvariable=self._session_var, width=40).grid(row=2, column=1, columnspan=2, sticky="w", **pad)
        self._run_button = ttk.Button(top, text="計測する", command=self.start_run)
        self._run_button.grid(row=3, column=1, sticky="w", **pad)
        self._open_button = ttk.Button(top, text="レポートを開く", command=self.open_report, state="disabled")
        self._open_button.grid(row=3, column=2, sticky="w", **pad)
        ttk.Label(top, textvariable=self._status_var).grid(row=3, column=3, sticky="w", **pad)

        summary_frame = ttk.LabelFrame(root, text="結果の要点")
        summary_frame.pack(fill="x", **pad)
        self._summary_text = tk.Text(summary_frame, height=9, wrap="word", state="disabled")
        self._summary_text.pack(fill="x", padx=6, pady=4)

        setup = ttk.LabelFrame(root, text="別のアプリの初回設定")
        setup.pack(fill="x", **pad)
        ttk.Label(setup, text="Unity プロジェクト").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(setup, textvariable=self._project_var, width=56).grid(row=0, column=1, sticky="w", **pad)
        self._browse_button = ttk.Button(setup, text="参照", command=self.browse_project)
        self._browse_button.grid(row=0, column=2, **pad)
        self._init_button = ttk.Button(setup, text="設定ファイルを作る", command=self.start_init)
        self._init_button.grid(row=1, column=1, sticky="w", **pad)
        ttk.Label(setup, text="対象のアプリを前面に出してから押してください (パッケージ名は上の欄に入れても構いません)").grid(
            row=2, column=0, columnspan=3, sticky="w", **pad
        )

        phase_frame = ttk.LabelFrame(root, text="進捗")
        phase_frame.pack(fill="x", **pad)
        self._phase_labels = [ttk.Label(phase_frame, text="", anchor="w") for _ in PHASES_RUN]
        for label in self._phase_labels:
            label.pack(fill="x", padx=8)
        self._bar = ttk.Progressbar(phase_frame, maximum=100, mode="determinate")
        self._bar.pack(fill="x", padx=8, pady=4)
        self._progress_var = tk.StringVar(value="")
        ttk.Label(phase_frame, textvariable=self._progress_var, anchor="w").pack(fill="x", padx=8, pady=(0, 4))

        progress = ttk.LabelFrame(root, text="出力")
        progress.pack(fill="both", expand=True, **pad)
        self._progress = scrolledtext.ScrolledText(progress, height=10, wrap="word", state="disabled")
        self._progress.tag_configure("error", foreground="#cf222e")
        self._progress.pack(fill="both", expand=True, padx=6, pady=4)

        self._buttons = [self._run_button, self._init_button, self._browse_button, self._refresh_button]
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(100, self._poll)
        self.refresh_devices()
        self._load_weights()

    def _load_weights(self) -> None:
        def work() -> None:
            self._events.put(("weights", load_phase_weights(TOOL_ROOT / "data" / "sessions")))

        threading.Thread(target=work, daemon=True).start()

    def _render_progress(self) -> None:
        if self._tracker is None:
            return
        view = self._tracker.view()
        for index, label in enumerate(self._phase_labels):
            label.configure(text=format_row(view.rows[index]) if index < len(view.rows) else "")
        self._bar["value"] = view.percent
        self._progress_var.set(format_progress_summary(view))

    # -- 端末 --

    def refresh_devices(self) -> None:
        self._device_note.set("端末を確認中...")

        def work() -> None:
            self._events.put(("devices", read_devices()))

        threading.Thread(target=work, daemon=True).start()

    def _show_devices(self, serials: list[str], problem: str) -> None:
        self._serials = list(serials)
        self._device_box["values"] = serials
        if serials:
            if self._device_var.get() not in serials:
                self._device_var.set(serials[0])
            note = "接続中" if len(serials) == 1 else f"接続中 ({len(serials)} 台。使う端末を選んでください)"
        else:
            self._device_var.set("")
            note = problem or "未接続 (adb devices に表示されません)"
        self._device_note.set(note)

    def _serial(self) -> str:
        # 1 台だけなら adb に任せる (指定しない)。複数のときだけ選んだ端末を渡す。
        return self._device_var.get() if len(self._serials) > 1 else ""

    # -- 実行 --

    def start_run(self) -> None:
        name = self._session_var.get().strip()
        error = validate_session_name(name)
        if error:
            self._messagebox.showerror("セッション名", error)
            return
        command = build_run_command(self._python, name, self._package_var.get().strip(), self._serial())
        self._begin("run", command)

    def start_init(self) -> None:
        project = self._project_var.get().strip()
        if not project:
            self._messagebox.showerror("初回設定", "Unity プロジェクトのフォルダを選んでください")
            return
        self._init_args = (project, self._package_var.get().strip())
        self._begin("init", build_init_command(self._python, project, self._init_args[1], self._serial()))

    def browse_project(self) -> None:
        folder = self._filedialog.askdirectory(title="Unity プロジェクトのフォルダ (Assets と ProjectSettings がある場所)")
        if folder:
            self._project_var.set(folder)

    def _begin(self, kind: str, command: list[str]) -> None:
        self._kind = kind
        self._lines = []
        self._report_path = ""
        self._set_text(self._summary_text, "")
        self._set_text(self._progress, "")
        self._open_button.configure(state="disabled")
        for button in self._buttons:
            button.configure(state="disabled")
        self._status_var.set("実行中...")
        self._tracker = ProgressTracker(PHASES_RUN if kind == "run" else PHASES_INIT, self._weights)
        self._render_progress()
        self._runner = CommandRunner(command, self._events)
        self._runner.start()

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self._events.get_nowait()
                if kind == "line":
                    self._lines.append(payload)
                    self._append_progress(payload)
                    if self._tracker is not None:
                        self._tracker.feed(payload)
                elif kind == "done":
                    self._finish(payload)
                elif kind == "devices":
                    self._show_devices(*payload)
                elif kind == "weights":
                    self._weights = payload
        except queue.Empty:
            pass
        if self._tracker is not None and not self._tracker.finished:
            self._render_progress()
        self._root.after(100, self._poll)

    def _finish(self, code: int) -> None:
        kind, lines = self._kind, list(self._lines)
        self._runner = None
        for button in self._buttons:
            button.configure(state="normal")
        if kind == "init" and code != 0 and is_existing_config_error(lines):
            project, package = self._init_args
            if self._messagebox.askyesno("設定ファイルが既にあります", "同じ名前の設定ファイルを上書きしますか。"):
                self._begin("init", build_init_command(self._python, project, package, self._serial(), force=True))
                return
        if self._tracker is not None:
            self._tracker.finish(code == 0)
            self._render_progress()
        summary = parse_summary(lines)
        self._show_summary(summary, kind)
        if code == 0:
            self._status_var.set("完了")
        else:
            self._status_var.set(f"失敗しました (終了コード {code})")
            self._append_progress(f"エラー: 失敗しました (終了コード {code})")
        if kind == "run":
            self._session_var.set(default_session_name())
            if code == 0 and summary.report and Path(summary.report).exists():
                self._report_path = summary.report
                self._open_button.configure(state="normal")
                self.open_report()

    def open_report(self) -> None:
        if self._report_path:
            webbrowser.open(Path(self._report_path).as_uri())

    def on_close(self) -> None:
        if self._runner is not None and self._runner.running:
            if not self._messagebox.askyesno("実行中", "実行中の処理を中断して終了しますか。"):
                return
            self._runner.stop()
        self._root.destroy()

    # -- 表示 --

    def _show_summary(self, summary: Summary, kind: str) -> None:
        rows: list[tuple[str, str]] = []
        if kind == "init":
            rows.append(("設定ファイル", summary.config_path))
            rows.append(("自社アセンブリ", ", ".join(summary.assemblies)))
            rows += [("注意", w) for w in summary.warnings]
        else:
            rows.append(("対象", summary.target))
            rows.append(("到達点", summary.origin))
            rows.append(("観測結果", summary.observation))
            rows += [("危険パターン", f) for f in summary.findings]
            rows += [("警告", w) for w in summary.warnings]
            rows.append(("所要時間", summary.timing))
            rows.append(("レポート", summary.report))
        self._set_text(self._summary_text, "\n".join(f"{label}: {value}" for label, value in rows if value))

    def _set_text(self, widget, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    def _append_progress(self, line: str) -> None:
        tag = "error" if line.startswith("エラー") or line.startswith("Traceback") else ()
        self._progress.configure(state="normal")
        self._progress.insert("end", line + "\n", tag)
        self._progress.see("end")
        self._progress.configure(state="disabled")


def create_root(tk, attempts: int = 5, wait: float = 0.3, sleep: Callable[[float], None] = time.sleep):
    """Tk を作る。Store 版 Python では使える tk.tcl を見つけられずに散発的に失敗することがあるため、数回やり直す。"""
    last: Exception | None = None
    for _ in range(attempts):
        try:
            return tk.Tk()
        except tk.TclError as exc:
            last = exc
            sleep(wait)
    assert last is not None
    raise last


def _show_fatal(message: str) -> None:
    """pythonw で起動したときはコンソールが無いため、ログとメッセージボックスで知らせる。"""
    try:
        log = TOOL_ROOT / "data" / "gui-error.log"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(message + "\n", encoding="utf-8")
    except OSError:
        pass
    if os.name == "nt":
        import ctypes

        ctypes.windll.user32.MessageBoxW(0, message, "UaaLAnalyzer", 0x10)
    else:
        print(message, file=sys.stderr)


def run_gui() -> int:
    tk, *_ = _tk()
    try:
        root = create_root(tk)
    except tk.TclError as exc:
        _show_fatal(f"画面を開けませんでした: {exc}")
        return 1
    GuiApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_gui())
