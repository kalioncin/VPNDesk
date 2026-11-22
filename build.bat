@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title VPNDesk - Build

if not exist "main.py" (
  echo [ERROR] main.py was not found. Extract the complete project archive.
  pause
  exit /b 1
)
if not exist "vpn_desk\app.py" (
  echo [ERROR] vpn_desk\app.py was not found.
  pause
  exit /b 1
)
if not exist "requirements.txt" (
  echo [ERROR] requirements.txt was not found.
  pause
  exit /b 1
)

set "PY_CMD="
where py >nul 2>nul
if not errorlevel 1 set "PY_CMD=py -3"
if not defined PY_CMD (
  where python >nul 2>nul
  if not errorlevel 1 set "PY_CMD=python"
)
if not defined PY_CMD (
  echo [ERROR] Python 3.11 or newer was not found.
  echo Install Python from https://www.python.org/downloads/windows/
  pause
  exit /b 1
)

%PY_CMD% -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
if errorlevel 1 (
  echo [ERROR] Python 3.11 or newer is required.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/5] Creating virtual environment...
  %PY_CMD% -m venv .venv
  if errorlevel 1 goto :fail
)
set "VENV_PY=%CD%\.venv\Scripts\python.exe"
if not exist "%VENV_PY%" goto :fail
"%VENV_PY%" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
if errorlevel 1 (
  echo [ERROR] Existing .venv uses Python older than 3.11.
  echo Delete the .venv folder and run build.bat again.
  pause
  exit /b 1
)

echo [2/5] Updating pip...
"%VENV_PY%" -m pip install --upgrade pip
if errorlevel 1 goto :fail

echo [3/5] Installing project dependencies...
"%VENV_PY%" -m pip install -r requirements.txt
if errorlevel 1 goto :fail

echo [4/5] Installing PyInstaller...
"%VENV_PY%" -m pip install pyinstaller
if errorlevel 1 goto :fail

echo [5/5] Building VPNDesk...
"%VENV_PY%" -m PyInstaller --noconfirm --clean --windowed --name VPNDesk --collect-all PySide6 --collect-all keyring --hidden-import=keyring.backends.Windows main.py
if errorlevel 1 goto :fail

if not exist "dist\VPNDesk\VPNDesk.exe" goto :fail
echo.
echo [OK] Build completed: dist\VPNDesk\VPNDesk.exe
pause
exit /b 0

:fail
echo.
echo [ERROR] Build failed. Exit code: %errorlevel%
echo Check the error messages above. Do not close this window before reading them.
pause
exit /b 1
