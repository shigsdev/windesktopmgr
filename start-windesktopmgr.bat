@echo off
cd /d "C:\shigsapps\windesktopmgr"

:: Resolve pythonw.exe ? prefer py.exe launcher (always points to latest installed)
where py.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    for /f "delims=" %%i in ('py.exe -c "import sys, pathlib; print(pathlib.Path(sys.executable).parent / 'pythonw.exe')"') do set PYEXE=%%i
    if exist "%PYEXE%" goto :run
)

:: Fall back to pythonw.exe on PATH
where pythonw.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYEXE=pythonw.exe
    goto :run
)

:: Fall back to python.exe on PATH (console will show)
where python.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYEXE=python.exe
    goto :run
)

:: Last resort: hardcoded path from when the task was set up
set PYEXE=C:\Users\higs7\AppData\Local\Python\pythoncore-3.14-64\pythonw.exe

:run
echo [%DATE% %TIME%] Starting WinDesktopMgr tray mode with: %PYEXE% >> "C:\shigsapps\windesktopmgr\windesktopmgr.log"

:: Launch tray.py ? no console window, tray icon appears in system tray
start /b "" "%PYEXE%" "C:\shigsapps\windesktopmgr\tray.py" >> "C:\shigsapps\windesktopmgr\windesktopmgr.log" 2>&1