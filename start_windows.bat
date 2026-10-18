@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 goto missing
if not exist ".venv\Scripts\python.exe" py -3 -m venv .venv
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto fail
start "" http://127.0.0.1:8765
.venv\Scripts\python.exe run.py
pause
exit /b 0
:missing
echo Python 3.10 or newer is required. Install Python from python.org and select Add to PATH.
goto fail
:fail
echo BLACKBOX could not start. See the messages above and README.md.
pause
exit /b 1
