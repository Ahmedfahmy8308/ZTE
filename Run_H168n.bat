@echo off
setlocal
title ZTE ZXHN H168N V3.1 Toolkit Dashboard

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

REM 2. Auto-create H168n config.ini if missing
if not exist "H168n_toolkit\config.ini" if exist "H168n_toolkit\config.example.ini" copy /y "H168n_toolkit\config.example.ini" "H168n_toolkit\config.ini" >nul

REM 3. Build H168n Rust CLI if missing
set "H168N_CLI=H168n_toolkit\target\release\h168n-cli.exe"
where cargo >nul 2>nul
if errorlevel 1 goto skip_h168n_build
if not exist "%H168N_CLI%" (
    echo [BUILD] Compiling H168n_toolkit Rust CLI...
    cargo build --release --manifest-path "H168n_toolkit\Cargo.toml"
)
:skip_h168n_build

REM 4. Free ports 8081 and 8082
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8081" ^| findstr "LISTENING"') do taskkill /f /pid %%a >nul 2>nul
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8082" ^| findstr "LISTENING"') do taskkill /f /pid %%a >nul 2>nul

echo ========================================================
echo   ZTE ZXHN H168N V3.1 - Web Management Dashboard
echo ========================================================
if exist "%H168N_CLI%" (
    echo [DIAG] Detecting H168N router on network adapters...
    "%H168N_CLI%" detect
    echo.
    start "H168N TLS 1.0 Proxy" /min "%H168N_CLI%" proxy --port 8081
)

echo [START] Launching H168N Web Dashboard at http://127.0.0.1:8082 ...
"%PYTHON_EXE%" web_app.py 8082 --mode h168n

echo.
echo H168N Dashboard stopped.
pause
