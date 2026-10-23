@echo off
setlocal
cd /d "%~dp0"
set "BLACKBOX_DEPLOY_MODE=local-hybrid"
set "BLACKBOX_PUBLIC_HOST="
set "BLACKBOX_SIGNUP_INVITE_CODE="
title BLACKBOX Investigator - Local App
echo.
echo  BLACKBOX ^| Login or Demo
echo  Opening BLACKBOX automatically. Keep this window open.
echo.
if not exist ".venv\Scripts\python.exe" (
  where py >nul 2>&1
  if errorlevel 1 (echo Python 3.10 or newer is required. & pause & exit /b 1)
  py -3 -m venv .venv
  if errorlevel 1 (echo Unable to create Python environment. & pause & exit /b 1)
)
if not exist ".venv\blackbox-requirements-installed.txt" (
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 (echo Failed to install dependencies. & pause & exit /b 1)
  copy /y requirements.txt ".venv\blackbox-requirements-installed.txt" >nul
) else (
  fc /B ".venv\blackbox-requirements-installed.txt" requirements.txt >nul
  if errorlevel 1 (
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 (echo Failed to update dependencies. & pause & exit /b 1)
    copy /y requirements.txt ".venv\blackbox-requirements-installed.txt" >nul
  )
)
".venv\Scripts\python.exe" seed_local_gallery.py
if errorlevel 1 (echo Failed to initialize demo cases. & pause & exit /b 1)
start "" /B ".venv\Scripts\python.exe" "open_browser_when_ready.py"
".venv\Scripts\python.exe" run.py
if errorlevel 1 (echo Server exited with an error. & pause & exit /b 1)
endlocal
