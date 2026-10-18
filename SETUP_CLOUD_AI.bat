@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 (
  echo Install Python 3.10+ first.
  pause
  exit /b 1
)
py -3 configure_cloud_ai.py
pause
