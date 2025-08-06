@echo off
echo Advanced Virus Scanner - Setup
echo ==============================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://python.org
    echo.
    pause
    exit /b 1
)

echo Python found. Checking version...
python --version

echo.
echo Checking required modules...

REM Check tkinter
python -c "import tkinter" 2>nul
if errorlevel 1 (
    echo ERROR: tkinter module not found
    echo Please install tkinter or use a complete Python installation
    pause
    exit /b 1
)

echo All required modules are available.
echo.

REM Create backup directory
if not exist "backup" mkdir backup
if not exist "quarantine" mkdir quarantine

echo Setup complete!
echo.
echo To run the virus scanner:
echo 1. Double-click run_scanner.bat
echo 2. Or run: python virus_scanner.py
echo.
pause
