@echo off
rem MULTI-OSINT-TOOL launcher for Windows.
rem Creates a private Python environment inside this folder (no system-wide changes), then starts the app.
setlocal
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (where python >nul 2>nul && set "PY=python")
if not defined PY goto nopython
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if errorlevel 1 goto nopython

if not exist ".mot_venv\Scripts\python.exe" (
  echo Creating a private environment in .mot_venv ^(no network needed^) ...
  %PY% -m venv .mot_venv
  if errorlevel 1 (
    echo Could not create the environment.
    goto fail
  )
)

rem mot_main.py installs missing packages (offline bundle first, with integrity check), then runs the app.
rem It keeps the window open itself, so no second prompt here.
".mot_venv\Scripts\python.exe" mot_main.py %*
endlocal
exit /b %errorlevel%

:nopython
echo Python 3.10 or newer is required. Install it from https://www.python.org/downloads/
:fail
echo.
set /p "_=Press Enter to exit..."
endlocal
exit /b 1
