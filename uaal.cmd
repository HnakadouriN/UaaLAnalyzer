@echo off
rem どのフォルダからでも `uaal run` のように起動するための入口。このファイルのあるフォルダを PATH に加えて使う。
setlocal
set "UAAL_ROOT=%~dp0"
set "PYTHONPATH=%UAAL_ROOT%src;%PYTHONPATH%"
if exist "%UAAL_ROOT%.venv\Scripts\python.exe" (
    "%UAAL_ROOT%.venv\Scripts\python.exe" -m uaal_analyzer %*
) else (
    python -m uaal_analyzer %*
)
exit /b %ERRORLEVEL%
