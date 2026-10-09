@echo off
chcp 65001 >nul
cd /d "%~dp0"
title NetAtlas
where python >nul 2>nul
if errorlevel 1 (
  where py >nul 2>nul
  if errorlevel 1 (
    echo Python hittades inte. Installera Python från https://www.python.org och starta igen.
  ) else (
    py netatlas-helper.py %*
  )
) else (
  python netatlas-helper.py %*
)
pause
