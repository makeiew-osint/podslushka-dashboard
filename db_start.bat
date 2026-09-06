@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ==========================================
echo   Podslushka - Database Viewer
echo ==========================================
if not exist "podslushka.db" (
    echo [ERROR] podslushka.db not found.
    pause
    exit /b 1
)

echo [OK] Starting local database dashboard...
echo [INFO] Open http://127.0.0.1:8765/
venv\Scripts\python.exe db_viewer.py
pause
