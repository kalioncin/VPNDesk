@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title VPNDesk - Run

if not exist "main.py" (
  echo [ERROR] main.py was not found. Extract the complete project archive.
  pause
  exit /b 1
)
if not exist "vpn_desk\app.py" (
  echo [ERROR] vpn_desk\app.py was not found. The application source package is missing.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo [INFO] Virtual environment not found. Run build.bat first, or install dependencies manually.
  call build.bat
  if errorlevel 1 exit /b 1
)
"%CD%\.venv\Scripts\python.exe" main.py
if errorlevel 1 (
  echo.
  echo [ERROR] VPNDesk exited with an error. Review the traceback above.
  pause
  exit /b 1
)
exit /b 0
