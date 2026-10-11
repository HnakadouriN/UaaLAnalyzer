@echo off
rem Double-click to open the UaaLAnalyzer window (uses the tool's own virtual environment).
setlocal
set "UAAL_ROOT=%~dp0"
set "PYTHONPATH=%UAAL_ROOT%src;%PYTHONPATH%"
set "PY=%UAAL_ROOT%.venv\Scripts\python.exe"
set "PYW=%UAAL_ROOT%.venv\Scripts\pythonw.exe"
if not exist "%PY%" (
    echo Virtual environment not found: %PY%
    pause
    exit /b 1
)
"%PY%" -c "import tkinter" 2>nul
if errorlevel 1 (
    echo tkinter is not available in this Python. Install the Tcl/Tk component of Python and try again.
    pause
    exit /b 1
)
start "" "%PYW%" -m uaal_analyzer.gui
exit /b 0
