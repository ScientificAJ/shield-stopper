@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting Administrator elevation...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b %errorlevel%
)

where py >nul 2>&1
if %errorlevel% equ 0 (
  set "PYTHON_LAUNCHER=py -3"
) else (
  set "PYTHON_LAUNCHER=python"
)

if "%~1"=="" (
  echo Opening Shield Stopper GUI...
  %PYTHON_LAUNCHER% "%~dp0shield_launcher.py" gui --config "%~dp0config.json"
  set "EXIT_CODE=%errorlevel%"
  exit /b %EXIT_CODE%
)

echo Running Shield Stopper mode: %*
%PYTHON_LAUNCHER% "%~dp0shield_launcher.py" %*
set "EXIT_CODE=%errorlevel%"

if not "%EXIT_CODE%"=="0" (
  echo Shield Stopper exited with code %EXIT_CODE%.
  pause
)

exit /b %EXIT_CODE%
