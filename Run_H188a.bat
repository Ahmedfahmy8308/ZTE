@echo off
setlocal
title ZTE ZXHN H188A Toolkit Launcher

cd /d "%~dp0app" 2>nul || cd /d "%~dp0"

REM 1. Verify Python
set "PYTHON_EXE="
if exist "C:\Program Files\Python311\python.exe" set "PYTHON_EXE=C:\Program Files\Python311\python.exe"
if "%PYTHON_EXE%"=="" where python >nul 2>nul && set "PYTHON_EXE=python"
if "%PYTHON_EXE%"=="" where py >nul 2>nul && set "PYTHON_EXE=py"
if "%PYTHON_EXE%"=="" (
    echo [ERROR] Python 3.10+ was not found on your system.
    pause
    exit /b 1
)

REM 2. Auto-create H188a config.ini if missing
if not exist "H188a_toolkit\config.ini" if exist "H188a_toolkit\config.example.ini" copy /y "H188a_toolkit\config.example.ini" "H188a_toolkit\config.ini" >nul

REM 3. Build H188a Rust CLI if missing
set "H188A_CLI=H188a_toolkit\target\release\h188a-cli.exe"
where cargo >nul 2>nul
if errorlevel 1 goto skip_h188a_build
if not exist "%H188A_CLI%" (
    echo [BUILD] Compiling H188a_toolkit Rust CLI...
    cargo build --release --manifest-path "H188a_toolkit\Cargo.toml"
)
:skip_h188a_build

REM 4. Free port 8080
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8080" ^| findstr "LISTENING"') do taskkill /f /pid %%a >nul 2>nul

echo ========================================================
echo   ZTE ZXHN H188A Management Dashboard
echo ========================================================
if exist "%H188A_CLI%" (
    "%H188A_CLI%" ping 192.168.1.1
    if exist "..\Firmware\H188a\H188a.bin" "%H188A_CLI%" fw-inspect "..\Firmware\H188a\H188a.bin"
    echo.
)

echo [START] Launching H188A Web Dashboard at http://127.0.0.1:8080 ...
"%PYTHON_EXE%" web_app.py 8080 --mode h188a

echo.
echo H188A Dashboard stopped.
pause
