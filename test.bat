@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found. Run build.bat first.
  pause
  exit /b 1
)
"%CD%\.venv\Scripts\python.exe" -m unittest discover -s tests -v
if errorlevel 1 (
  echo [ERROR] Tests failed.
  pause
  exit /b 1
)
echo [OK] All tests passed.
pause
