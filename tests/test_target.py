from __future__ import annotations

import pytest

from uaal_analyzer.collect.target import (
    foreground_package,
    is_valid_package,
    list_processes,
    parse_ps,
    resolve_target,
)
from uaal_analyzer.errors import TargetError

PS_O_FORMAT = (
    "  PID USER           NAME\n"
    "    1 root           init\n"
    " 1200 system         system_server\n"
    "17662 u0_a273        com.example.app\n"
    "17701 u0_a273        com.example.app:unity\n"
    "18000 u0_a99         com.example.launcher\n"
    "18100 u0_a120        com.other.unity\n"
    "18200 u0_a130        com.release.app\n"
)


class DeviceAdb:
    """端末の差し替え。ps / dumpsys window / pm / run-as の応答を辞書で持つ。"""

    def __init__(
        self,
        ps_text: str = PS_O_FORMAT,
        foreground: str = "com.example.app",
        threads: dict[int, list[str]] | None = None,
        denied: tuple[str, ...] = ("com.release.app",),
        third_party: tuple[str, ...] | None = None,
        ps_o_supported: bool = True,
    ) -> None:
        self.ps_text = ps_text
        self.foreground = foreground
        self.threads = threads if threads is not None else {17662: ["UnityMain", "binder:1"], 17701: ["main"]}
        self.denied = denied
        self.third_party = third_party
        self.ps_o_supported = ps_o_supported
        self.commands: list[str] = []

    def shell(self, command: str, timeout: float = 60, check: bool = True) -> str:
        self.commands.append(command)
        if command == "ps -A -o PID,USER,NAME":
            return self.ps_text if self.ps_o_supported else "ps: bad -o 'NAME'\n"
        if command == "ps -A":
            return self.ps_text
        if command == "dumpsys window":
            if not self.foreground:
                return "  mCurrentFocus=null\n"
            return f"  mCurrentFocus=Window{{2bd94d3 u0 {self.foreground}/{self.foreground}.MainActivity}}\n"
        if command == "pm list packages -3":
            if self.third_party is None:
                return ""
            return "".join(f"package:{p}\n" for p in self.third_party)
        if command.startswith("run-as "):
            package = command.split()[1]
            if package in self.denied:
                return f"run-as: package not debuggable: {package}\n"
            pid = int(command.split("/proc/")[1].split("/")[0])
            return "".join(f"{name}\n" for name in self.threads.get(pid, []))
        if command.startswith("pidof "):
            return ""
        raise AssertionError(f"想定外のコマンド: {command}")

    def run_as_packages(self) -> list[str]:
        return [c.split()[1] for c in self.commands if c.startswith("run-as ")]


def test_parse_ps_reads_the_o_format_and_the_default_format():
    default = (
        "USER           PID  PPID     VSZ    RSS WCHAN            ADDR S NAME\n"
        "u0_a273      17662   800 12345678 618000 0                   0 S com.example.app\n"
        "root             1     0   10000   1000 0                   0 S init\n"
    )

    assert [(p.pid, p.user, p.name) for p in parse_ps(PS_O_FORMAT)][:4] == [
        (1, "root", "init"),
        (1200, "system", "system_server"),
        (17662, "u0_a273", "com.example.app"),
        (17701, "u0_a273", "com.example.app:unity"),
    ]
    assert [(p.pid, p.name) for p in parse_ps(default)] == [(17662, "com.example.app"), (1, "init")]
    assert parse_ps("unexpected output\n") == []
    assert parse_ps(PS_O_FORMAT)[3].package == "com.example.app"


def test_list_processes_falls_back_to_plain_ps_when_o_is_not_supported():
    adb = DeviceAdb(ps_o_supported=False)

    processes = list_processes(adb)

    assert any(p.pid == 17662 for p in processes)
    assert adb.commands[:2] == ["ps -A -o PID,USER,NAME", "ps -A"]


def test_foreground_package_is_read_from_the_focused_window():
    assert foreground_package(DeviceAdb(foreground="com.example.app")) == "com.example.app"
    assert foreground_package(DeviceAdb(foreground="")) == ""


def test_foreground_unity_app_is_used_without_scanning_other_apps():
    adb = DeviceAdb()

    target = resolve_target(adb, log=lambda m: None)

    assert (target.package, target.pid, target.method) == ("com.example.app", 17662, "foreground")
    assert set(adb.run_as_packages()) == {"com.example.app"}
    assert target.to_dict()["candidates"][0]["status"] == "Unity あり"


def test_separate_unity_process_is_found_among_the_package_processes():
    adb = DeviceAdb(threads={17662: ["main"], 17701: ["UnityMain", "x"]})

    target = resolve_target(adb, log=lambda m: None)

    assert target.pid == 17701  # `<pkg>:unity` のプロセス


def test_when_foreground_is_not_unity_the_single_unity_app_in_the_process_list_is_used():
    adb = DeviceAdb(foreground="com.example.launcher", threads={17662: ["UnityMain"]})

    target = resolve_target(adb, log=lambda m: None)

    assert (target.package, target.pid, target.method) == ("com.example.app", 17662, "process-list")
    statuses = {c["package"]: c["status"] for c in target.candidates}
    assert statuses["com.example.launcher"] == "Unity なし"
    assert statuses["com.release.app"] == "run-as 不可"  # debuggable ではないアプリは除外


def test_third_party_filter_skips_system_apps():
    adb = DeviceAdb(foreground="", third_party=("com.example.app", "com.release.app"))

    target = resolve_target(adb, log=lambda m: None)

    assert target.package == "com.example.app"
    assert "com.example.launcher" not in adb.run_as_packages()
    assert "com.other.unity" not in adb.run_as_packages()


def test_several_unity_apps_stop_with_a_list():
    adb = DeviceAdb(foreground="", threads={17662: ["UnityMain"], 18100: ["UnityMain"]})

    with pytest.raises(TargetError) as exc:
        resolve_target(adb, log=lambda m: None)

    message = str(exc.value)
    assert "--package" in message and "com.example.app" in message and "com.other.unity" in message


def test_no_unity_app_stops_with_the_reason_for_each_candidate():
    adb = DeviceAdb(foreground="com.example.launcher", threads={})

    with pytest.raises(TargetError) as exc:
        resolve_target(adb, log=lambda m: None)

    message = str(exc.value)
    assert "見つけられませんでした" in message
    assert "com.release.app: run-as 不可" in message
    assert "com.example.launcher: Unity なし" in message


def test_no_app_processes_at_all_stops_with_guidance():
    adb = DeviceAdb(ps_text="  PID USER NAME\n    1 root init\n", foreground="")

    with pytest.raises(TargetError) as exc:
        resolve_target(adb, log=lambda m: None)

    assert "アプリのプロセスが見つかりません" in str(exc.value)


def test_several_unity_processes_in_one_package_must_be_chosen_with_pid():
    adb = DeviceAdb(threads={17662: ["UnityMain"], 17701: ["UnityMain"]})

    with pytest.raises(TargetError) as exc:
        resolve_target(adb, log=lambda m: None)

    assert "--pid" in str(exc.value) and "17662" in str(exc.value)


def test_pid_option_takes_the_package_from_the_process_list():
    adb = DeviceAdb()

    target = resolve_target(adb, pid=17701, log=lambda m: None)

    assert (target.package, target.pid, target.method) == ("com.example.app", 17701, "pid-option")
    assert adb.run_as_packages() == []


def test_pid_option_with_unknown_pid_needs_the_package():
    with pytest.raises(TargetError):
        resolve_target(DeviceAdb(), pid=99999, log=lambda m: None)

    target = resolve_target(DeviceAdb(), pid=99999, package="com.example.app", log=lambda m: None)
    assert target.pid == 99999


def test_package_option_checks_unity_and_records_the_method():
    target = resolve_target(DeviceAdb(), package="com.example.app", log=lambda m: None)

    assert (target.pid, target.method) == (17662, "package-option")


def test_config_package_is_used_before_the_foreground_app():
    adb = DeviceAdb(foreground="com.example.launcher")

    target = resolve_target(adb, config_package="com.example.app", log=lambda m: None)

    assert target.method == "config"
    assert "com.example.launcher" not in adb.run_as_packages()


def test_package_option_rejects_denied_and_missing_processes():
    with pytest.raises(TargetError, match="run-as"):
        resolve_target(DeviceAdb(), package="com.release.app", log=lambda m: None)
    with pytest.raises(TargetError, match="プロセスが見つかりません"):
        resolve_target(DeviceAdb(), package="com.not.running", log=lambda m: None)


def test_package_option_without_unity_thread_uses_the_only_process_with_a_note():
    ps = "  PID USER NAME\n 4000 u0_a50 com.plain.app\n"
    adb = DeviceAdb(ps_text=ps, threads={4000: ["main"]}, denied=())

    target = resolve_target(adb, package="com.plain.app", log=lambda m: None)

    assert target.pid == 4000
    assert target.notes and "確認できなかった" in target.notes[0]


def test_package_option_without_unity_thread_and_several_processes_stops():
    adb = DeviceAdb(threads={17662: ["main"], 17701: ["main"]})

    with pytest.raises(TargetError, match="--pid"):
        resolve_target(adb, package="com.example.app", log=lambda m: None)


def test_main_thread_names_come_from_the_caller():
    adb = DeviceAdb(threads={17662: ["MyMain"]})

    target = resolve_target(adb, main_names=["MyMain"], log=lambda m: None)

    assert target.pid == 17662


@pytest.mark.parametrize("name", ["bad name", "a;b", "../x", ""])
def test_invalid_package_names_are_rejected(name):
    assert not is_valid_package(name)
    if name:
        with pytest.raises(TargetError):
            resolve_target(DeviceAdb(), package=name, log=lambda m: None)
