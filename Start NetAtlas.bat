@echo off
chcp 65001 >nul
cd /d "%~dp0"
title NetAtlas
where python >nul 2>nul
if errorlevel 1 (
  where py >nul 2>nul
  if errorlevel 1 (
    echo Python was not found. Install Python 3 from https://www.python.org/downloads/ - tick "Add python.exe to PATH" - and start again.
    echo Python hittades inte. Installera Python 3 från https://www.python.org/downloads/ - kryssa i "Add python.exe to PATH" - och starta igen.
  ) else (
    py netatlas-helper.py %*
  )
) else (
  python netatlas-helper.py %*
)
pause
