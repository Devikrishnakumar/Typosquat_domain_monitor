@echo off
setlocal EnableExtensions
title CyberSentinel - One Click Launch
cd /d "%~dp0"

if not exist "%~dp0run_project.bat" (
    echo ERROR: Keep this launcher inside the CyberSentinel project folder.
    echo Missing file: run_project.bat
    pause
    exit /b 1
)

call "%~dp0run_project.bat"
exit /b %errorlevel%
