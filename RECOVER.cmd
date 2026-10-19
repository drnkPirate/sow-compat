@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0sow_compat.ps1" -Recover
set "RESULT=%errorlevel%"
pause
exit /b %RESULT%
