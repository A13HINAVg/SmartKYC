@echo off
cd /d "%~dp0"
where python >nul 2>nul && (python scripts\dev.py) || (py scripts\dev.py)
pause
