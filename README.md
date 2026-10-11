# UaaLAnalyzer

Android 上で動く Unity (UaaL / IL2CPP) アプリが固まったとき、ADB で停止時のスタックを集めて解析する個人用ツール。標準ライブラリだけで動く (Python 3.11 以上)。

## 何をするか

1. **取得**: 対象アプリのプロセスへ `run-as` で SIGQUIT を複数回送り、ART のスレッドダンプと bugreport を集める。
2. **シンボル解決**: `libil2cpp.so` などの BuildId をキーに、NDK の `llvm-addr2line` で関数名と生成元ファイルを求める。
3. **解析**: 主スレッドの共通の停止経路、CPU 消費、OS の状態から「空回り / 待機」を判定し、最後に到達した自社メソッドを示す。
4. **出力**: HTML と Markdown のレポートを作る。

## 前提

- Python 3.11 以上
- `adb` が使えること
- 対象アプリが debuggable なビルドであること (`run-as` を使うため)
- Android NDK (`llvm-addr2line` と `llvm-readelf`)
- 対象ビルドのシンボル付き `*.so` (`libil2cpp.so` など)
- GUI を使う場合は tkinter

## セットアップ

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .[dev]
```

`uaal.cmd` (CLI) と `uaal-gui.cmd` (GUI) は、このフォルダの `.venv` を使って起動する。`uaal.cmd` のあるフォルダを PATH に加えると、どこからでも `uaal` で呼べる。

## 設定

`configs/example.toml` をコピーして `configs/<パッケージ名>.toml` を作り、自分のアプリ向けに書き換える。Unity プロジェクトから作ることもできる。

```
uaal init --project <Unity プロジェクトのパス>
```

主な項目:

- `[device] package`: 対象のパッケージ名
- `[ndk] bin_dir`: NDK の llvm ツールがあるフォルダ
- `[symbols] search_paths`: シンボル付き `*.so` を探すフォルダ
- `[analysis] app_assemblies`: 自社アセンブリ名のパターン (例: `["Contoso.*"]`)。未設定だと「最後に到達した自社メソッド」を判定できない。

`--config` を付けないときは、検出したパッケージ名の `configs/<パッケージ名>.toml` があればそれを使い、無ければ `configs/example.toml` を使う。個人用の設定ファイルは `.gitignore` で除外してある。

## 使い方

```
uaal run                      # 取得 → シンボル解決 → 解析を一括実行
uaal capture                  # 取得だけ
uaal symbols add <パス>       # シンボルを BuildId 付きで保管
uaal symbols list
uaal symbolize latest
uaal analyze latest
uaal rebuild <セッション>     # 保存済みの bugreport から session.json を作り直す
```

結果は `data/sessions/<セッション名>/` (`report.html`, `report.md`, `session.json` など) に保存される。`data/` は `.gitignore` で除外してあり、bugreport などの実機データを含むためコミットしないこと。

## テスト

```
.venv\Scripts\python.exe -m pytest
```

## ライセンス

MIT。`LICENSE` を参照。
