@echo off
setlocal EnableExtensions
where git >nul 2>nul
if errorlevel 1 (
  echo Git for Windows is required: https://git-scm.com/download/win
  pause & exit /b 1
)
set "ROOT=%~dp0"
set "WORK=%TEMP%\blackbox-auth-update-%RANDOM%-%RANDOM%"
echo Cloning current BLACKBOX repository...
git clone --depth 1 https://github.com/ikramsalhi/BLACKBOX-investigator.git "%WORK%"
if errorlevel 1 ( echo Cannot clone repository. & pause & exit /b 1 )
for %%F in (README.md VERSION compose.yaml deploy.env.example deploy_bootstrap.sh) do copy /Y "%ROOT%%%F" "%WORK%\%%F" >nul
for %%F in (accounts.py main.py) do copy /Y "%ROOT%blackbox\%%F" "%WORK%\blackbox\%%F" >nul
for %%F in (app.js auth.css index.html replay.js) do copy /Y "%ROOT%static\%%F" "%WORK%\static\%%F" >nul
copy /Y "%ROOT%tests\test_v19_auth.py" "%WORK%\tests\test_v19_auth.py" >nul
cd /d "%WORK%"
git add README.md VERSION compose.yaml deploy.env.example deploy_bootstrap.sh blackbox/accounts.py blackbox/main.py static/app.js static/auth.css static/index.html static/replay.js tests/test_v19_auth.py
echo.
echo Review the exact authentication changes before pushing:
git diff --cached --stat
set /p CONFIRM=Push these changes to GitHub? Type YES to confirm: 
if /I not "%CONFIRM%"=="YES" (echo Cancelled. & pause & exit /b 0)
git commit -m "Add BLACKBOX v1.9 secure browser authentication and hybrid gallery"
if errorlevel 1 (echo Commit failed. & pause & exit /b 1)
git push origin main
if errorlevel 1 (echo Push failed. Review repository access or remote changes. & pause & exit /b 1)
echo Published successfully: https://github.com/ikramsalhi/BLACKBOX-investigator
echo Then configure BLACKBOX_DEPLOY_MODE=hybrid and secrets in Railway.
pause
