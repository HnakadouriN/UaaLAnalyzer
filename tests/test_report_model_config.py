from __future__ import annotations

import pytest

from helpers import FakeResolver, make_session, make_store, stuck_trace
from uaal_analyzer.analyze.engine import analyze_session
from uaal_analyzer.config import Config, load_config
from uaal_analyzer.errors import ConfigError
from uaal_analyzer.model import Session
from uaal_analyzer.report.html import render_html
from uaal_analyzer.report.markdown import render_report
from uaal_analyzer.symbolize.symbolizer import symbolize_session


def test_session_roundtrips_through_json(tmp_path):
    from uaal_analyzer.model import load_session, save_session

    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), FakeResolver(), ["libil2cpp.so"])
    path = tmp_path / "session.json"

    save_session(path, session)

    assert load_session(path) == session


def test_session_rejects_unknown_schema_version():
    data = make_session(stuck_trace(1)).to_dict()
    data["schema_version"] = 99
    with pytest.raises(ValueError):
        Session.from_dict(data)


@pytest.mark.parametrize("version", [1, 2, 3])
def test_older_schema_versions_load_with_defaults(version):
    data = make_session(stuck_trace(1)).to_dict()
    data["schema_version"] = version
    for key in ("device", "logs"):
        data.pop(key, None)  # v1/v2 にはこれらの項目が無い
    for snapshot in data["proc_snapshots"]:
        snapshot.pop("wchan", None)
        snapshot.pop("meminfo", None)
    for sample in data["samples"]:
        for thread in sample["threads"]:
            for frame in thread["frames"]:
                frame.pop("library", None)
                frame.pop("source_file", None)

    session = Session.from_dict(data)

    assert session.device == {} and session.logs == {}
    assert session.samples[0].threads[0].frames[0].library is None


def test_report_shows_chain_in_html_and_summary_in_markdown(tmp_path):
    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path), FakeResolver(), ["libil2cpp.so"])
    result = analyze_session(session, Config(app_assemblies=["Contoso.*"]))

    html = render_html(session, result, Config(app_assemblies=["Contoso.*"]).app_assemblies)
    text = render_report(session, result)

    assert "[wait-for-completion]" in html and "[wait-for-completion]" in text
    assert "[libil2cpp.so] AsyncOperationBase_WaitForCompletion" in html
    assert "ab12cd34" in html and "解決" in html
    path = html.split('id="path"')[1].split("</section>")[0]
    assert path.index("SettingsManager_OnModeChanged") < path.index("ModeProvider_get_Modes")
    assert path.index("ModeProvider_get_Modes") < path.index("AsyncOperationBase_WaitForCompletion")
    assert path.index("AsyncOperationBase_WaitForCompletion") < path.index("ResourceManager_Update")
    assert 'class="f varies">[libc.so]' in path  # 最も内側のフレームは変化あり


def test_report_lists_warnings(tmp_path):
    session = symbolize_session(make_session(stuck_trace(3)), make_store(tmp_path, "dd" * 20), FakeResolver(), ["libil2cpp.so"])

    result = analyze_session(session, Config())

    assert "## 警告" in render_report(session, result)
    assert "保管庫にありません" in render_report(session, result)


def test_load_config_reads_toml_and_applies_overrides(tmp_path):
    path = tmp_path / "c.toml"
    path.write_text(
        '[device]\npackage = "com.example"\n[capture]\nsamples = 4\ninterval_sec = 1.5\n[analysis]\nmain_thread_names = ["A"]\n',
        encoding="utf-8",
    )

    cfg = load_config(path, tmp_path / "d")

    assert (cfg.package, cfg.samples, cfg.interval_sec, cfg.main_thread_names) == ("com.example", 4, 1.5, ["A"])
    assert cfg.sessions_dir == tmp_path / "d" / "sessions"
    assert cfg.symbols_dir == tmp_path / "d" / "symbols"


def test_load_config_rejects_missing_file_and_too_few_samples(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.toml")
    path = tmp_path / "c.toml"
    path.write_text("[capture]\nsamples = 1\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_default_config_file_is_valid():
    cfg = load_config()
    assert cfg.package
    assert cfg.symbol_modules == ["libil2cpp.so"]
