@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title CyberSentinel launcher

set "ROOT=%~dp0"
set "PYTHON=%ROOT%.venv\Scripts\python.exe"
set "REQUIREMENTS_HASH="
set "SAVED_REQUIREMENTS_HASH="
set "OPENBLAS_NUM_THREADS=1"
set "OMP_NUM_THREADS=1"
set "MKL_NUM_THREADS=1"

if not exist "%PYTHON%" (
    echo [1/4] Checking for Python...
    python --version >nul 2>nul
    if errorlevel 1 goto python_missing

    python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
    if errorlevel 1 goto python_version

    echo [2/4] Creating the project Python environment...
    python -m venv "%ROOT%.venv"
    if errorlevel 1 goto venv_failed
)

if not exist "%PYTHON%" goto venv_failed

for /f "delims=" %%H in ('powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath 'requirements.txt').Hash" 2^>nul') do set "REQUIREMENTS_HASH=%%H"
if not defined REQUIREMENTS_HASH goto hash_failed

if exist "%ROOT%.venv\requirements.sha256" set /p SAVED_REQUIREMENTS_HASH=<"%ROOT%.venv\requirements.sha256"
if /i not "%REQUIREMENTS_HASH%"=="%SAVED_REQUIREMENTS_HASH%" (
    echo [3/4] Installing or updating project dependencies...
    "%PYTHON%" -m pip install -r "%ROOT%requirements.txt"
    if errorlevel 1 goto dependencies_failed
    >"%ROOT%.venv\requirements.sha256" echo %REQUIREMENTS_HASH%
)

echo [4/4] Starting CyberSentinel services...

curl.exe -fsS --max-time 2 "http://127.0.0.1:8765/" -o NUL >nul 2>nul
if errorlevel 1 start "CyberSentinel landing page" /D "%ROOT%landing_page" "%PYTHON%" server.py

curl.exe -fsS --max-time 2 "http://127.0.0.1:8000/docs" -o NUL >nul 2>nul
if errorlevel 1 start "CyberSentinel API" /D "%ROOT%" "%PYTHON%" -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000

curl.exe -fsS --max-time 2 "http://127.0.0.1:8501/_stcore/health" -o NUL >nul 2>nul
if errorlevel 1 start "CyberSentinel dashboard" /D "%ROOT%" "%PYTHON%" -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false

echo Waiting for the landing page at http://localhost:8765 ...
call :wait_for_url "http://127.0.0.1:8765/"
if errorlevel 1 goto landing_failed

echo Waiting for the API at http://localhost:8000/docs ...
call :wait_for_url "http://127.0.0.1:8000/docs"
if errorlevel 1 goto api_failed

echo Waiting for the dashboard at http://localhost:8501 ...
call :wait_for_url "http://127.0.0.1:8501/_stcore/health"
if errorlevel 1 goto dashboard_failed

echo.
echo CyberSentinel is ready:
echo   Landing page: http://localhost:8765/
echo   Dashboard:    http://localhost:8501/
echo   API docs:     http://localhost:8000/docs
echo.
start "" "http://localhost:8765/"
exit /b 0

:wait_for_url
for /L %%I in (1,1,90) do (
    curl.exe -fsS --max-time 2 "%~1" -o NUL >nul 2>nul
    if not errorlevel 1 exit /b 0
    ping.exe -n 2 -w 1000 127.0.0.1 >nul
)
exit /b 1

:python_missing
echo ERROR: Python 3.10 or newer was not found on PATH.
echo Install Python from https://www.python.org/downloads/ and enable "Add Python to PATH".
goto failed

:python_version
echo ERROR: Python 3.10 or newer is required.
goto failed

:venv_failed
echo ERROR: Could not create the project virtual environment.
goto failed

:hash_failed
echo ERROR: Could not check requirements.txt. PowerShell is required by this launcher.
goto failed

:dependencies_failed
echo ERROR: Dependency installation failed. Check the Python output above and try again.
goto failed

:landing_failed
echo ERROR: The landing page did not start. Check its service window for details.
goto failed

:api_failed
echo ERROR: The API did not start. Check its service window for details.
goto failed

:dashboard_failed
echo ERROR: The dashboard did not start. Check its service window for details.
goto failed

:failed
echo.
pause
exit /b 1
