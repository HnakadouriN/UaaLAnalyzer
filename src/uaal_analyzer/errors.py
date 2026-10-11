class UaalError(Exception):
    """利用者へそのまま報告する想定内のエラー。"""


class ConfigError(UaalError):
    pass


class AdbError(UaalError):
    pass


class CaptureError(UaalError):
    pass


class TargetError(UaalError):
    pass


class SymbolError(UaalError):
    pass
