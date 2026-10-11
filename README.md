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

以下は Windows の手順。コマンドプロンプトを開き、`README.md`・`pyproject.toml`・`uaal-gui.cmd` があるフォルダへ移動する。パスは実際の保存先に置き換える。

```cmd
cd /d C:\path\to\UaaLAnalyzer
python --version
```

`Python 3.11` 以上が表示されることを確認し、仮想環境の作成とインストールを行う。初回のみ必要。

```cmd
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
```

### GUI の起動

同じコマンドプロンプトで次を実行する。

```cmd
uaal-gui.cmd
```

以後は `uaal-gui.cmd` のダブルクリックでも起動できる。

`uaal.cmd` (CLI) と `uaal-gui.cmd` (GUI) は、このフォルダの `.venv` を使って起動する。CLI はこのフォルダから `uaal.cmd run` などで実行できる。`uaal.cmd` のあるフォルダを PATH に加えると、どこからでも `uaal` で呼べる。

## Android 端末の接続

1. Android 端末の「開発者向けオプション」で「USB デバッグ」を有効にする。
2. USB ケーブルで PC と接続する。
3. 端末に USB デバッグの許可画面が出たら、接続した PC を許可する。
4. コマンドプロンプトで接続を確認する。

```cmd
adb devices
```

対象端末の行に `device` と表示されれば接続できている。`unauthorized` の場合は端末の許可画面を確認する。端末の行が出ない場合は、USB 接続と USB デバッグの設定を確認する。

`adb` が見つからない場合は、Android SDK の `platform-tools` フォルダを PATH に追加して、コマンドプロンプトを開き直す。

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

`run` / `capture` に `--config` を付けないときは、検出したパッケージ名の `configs/<パッケージ名>.toml` があればそれを使い、無ければ `configs/example.toml` を使う。個人用の設定ファイルは `.gitignore` で除外してある。

## 使い方

設定ファイルを用意し、Android 端末で対象の Unity (UaaL) アプリを起動する。調べたい停止状態で、GUI から取得・解析を実行する。

CLI で対象を指定する場合は、ツールのフォルダで次を実行する。`com.example.app` は実際のパッケージ名に置き換える。

```cmd
uaal.cmd run --package com.example.app
```

TOML の `[device] adb` や `serial` を使う場合は、設定ファイルを明示する。

```cmd
uaal.cmd --config configs\com.example.app.toml run
```

PATH に追加した場合の主なコマンド:

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

## 起動時にエラーが出る場合

### `Virtual environment not found` と表示される

GUI が使う `.venv\Scripts\python.exe` が見つからない状態。`uaal-gui.cmd` があるフォルダで「セットアップ」の仮想環境作成とインストールを実行し、再度 `uaal-gui.cmd` を起動する。

別のフォルダに作った `.venv` は、この起動スクリプトでは使われない。

### `python --version` が実行できない

Python 3.11 以上が利用できる状態にしてからセットアップを行う。Python をインストールした直後や PATH を変更した後は、コマンドプロンプトを開き直す。

### tkinter が利用できないと表示される

GUI には tkinter が必要。使用する Python に Tcl/Tk のコンポーネントを追加し、その Python で仮想環境を作成する。

## テスト

開発用の依存パッケージをインストールしてから実行する。

```cmd
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m pytest
```

## ライセンス

MIT。`LICENSE` を参照。
