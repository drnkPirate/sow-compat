@echo off
setlocal
"%~dp0SowCompat.exe"
set "RESULT=%errorlevel%"
if not "%RESULT%"=="0" pause
exit /b %RESULT%
