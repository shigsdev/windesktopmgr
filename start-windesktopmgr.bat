@echo off
cd /d "C:\Users\higs7\OneDrive\Coding\Windows Tools\windesktopmgr"

:: Resolve Python ??? prefer py.exe launcher (always points to latest installed)
where py.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    for /f "delims=" %%i in ('py.exe -c "import sys; print(sys.executable)"') do set PYEXE=%%i
    goto :run
)

:: Fall back to python.exe on PATH
where python.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYEXE=python.exe
    goto :run
)

:: Last resort: hardcoded path from when the task was set up
set PYEXE=C:\Users\higs7\AppData\Local\Python\pythoncore-3.14-64\python.exe

:run
echo [%DATE% %TIME%] Starting WinDesktopMgr with: %PYEXE% >> "C:\Users\higs7\OneDrive\Coding\Windows Tools\windesktopmgr\windesktopmgr.log"

:: Start Flask in the background so this script can continue
start /b "" "%PYEXE%" "C:\Users\higs7\OneDrive\Coding\Windows Tools\windesktopmgr\windesktopmgr.py" >> "C:\Users\higs7\OneDrive\Coding\Windows Tools\windesktopmgr\windesktopmgr.log" 2>&1

:: Wait 6 seconds for Flask to bind to port 5000, then open the browser
timeout /t 6 /nobreak >nul
start http://localhost:5000