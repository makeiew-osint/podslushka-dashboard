@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ==========================================
echo   Podslushka Bot - Launcher
echo ==========================================

if not exist "venv\Scripts\python.exe" (
    echo [...] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create venv. Make sure Python is installed.
        pause
        exit /b 1
    )
    echo [OK] venv created
) else (
    echo [OK] venv already exists
)

echo [...] Installing dependencies...
venv\Scripts\python.exe -m pip install -q aiogram pydantic-settings aiosqlite
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo [OK] Dependencies installed

echo [...] Starting bot...
echo.
venv\Scripts\python.exe bot.py

echo.
echo [INFO] Bot stopped.
pause
