@echo off
setlocal
title ZTE ZXHN H188A Management Dashboard

cd /d "%~dp0app" 2>nul || cd /d "%~dp0ZTE_H188A_WAN_Toolkit" 2>nul || cd /d "%~dp0"

set "PYTHON_EXE="
if exist "C:\Program Files\Python311\python.exe" set "PYTHON_EXE=C:\Program Files\Python311\python.exe"
if "%PYTHON_EXE%"=="" where python >nul 2>nul && set "PYTHON_EXE=python"
if "%PYTHON_EXE%"=="" where py >nul 2>nul && set "PYTHON_EXE=py"

if "%PYTHON_EXE%"=="" (
    echo [ERROR] Python was not found on your system.
    echo Please install Python 3.10 or newer from python.org.
    echo.
    pause
    exit /b 1
)

:: Free port 8080 if an old background instance is holding it
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8080" ^| findstr "LISTENING"') do (
    taskkill /f /pid %%a >nul 2>nul
)

echo ========================================================
echo   ZTE ZXHN H188A - Web Management Dashboard
echo   Starting server at http://127.0.0.1:8080 ...
echo ========================================================

"%PYTHON_EXE%" web_app.py

echo.
echo Dashboard stopped.
pause
