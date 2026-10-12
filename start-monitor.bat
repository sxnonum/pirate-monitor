@echo off
setlocal
cd /d "%~dp0"

rem Re-launch as Administrator if needed (full registry/process visibility).
net session >nul 2>&1
if errorlevel 1 (
    echo Asking for Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "PY=python"
where py >nul 2>&1 && set "PY=py -3"

echo Installing / checking requirements...
%PY% -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
    echo.
    echo Could not install the requirements. Is Python 3.9+ installed and on PATH?
    pause
    exit /b 1
)

%PY% -m pirate_monitor %*
echo.
pause
