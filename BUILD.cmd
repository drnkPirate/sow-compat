@echo off
setlocal
pushd "%~dp0"

set "ANALYZE_SWITCH="
if /i "%~1"=="--analyze" set "ANALYZE_SWITCH=/analyze"

if not defined VCVARS set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if exist "%VCVARS%" goto vcvars_found
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VCVARS=%%I\VC\Auxiliary\Build\vcvars64.bat"
:vcvars_found
if not exist "%VCVARS%" (
  echo Visual Studio x64 C++ Build Tools were not found.
  popd
  exit /b 2
)

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo The .NET Framework C# compiler was not found.
  popd
  exit /b 3
)

if not exist "build" mkdir "build"
call "%VCVARS%" >nul
set "BUILD_RESULT=%errorlevel%"
if not "%BUILD_RESULT%"=="0" goto build_done

cl /nologo /std:c++17 /permissive- /W4 /WX /EHsc /DUNICODE /D_UNICODE /Brepro %ANALYZE_SWITCH% ^
  sow_compat_gate.cpp /Fo:build\ /Fe:build\g.exe ^
  /link /SUBSYSTEM:WINDOWS /ENTRY:wmainCRTStartup /Brepro
set "BUILD_RESULT=%errorlevel%"
if not "%BUILD_RESULT%"=="0" goto build_done

"%CSC%" /nologo /target:winexe /platform:x64 /optimize+ /warn:4 /warnaserror+ ^
  /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll ^
  /out:build\SowCompat.exe sow_compat_gui.cs
set "BUILD_RESULT=%errorlevel%"
if not "%BUILD_RESULT%"=="0" goto build_done

build\g.exe --self-test
set "BUILD_RESULT=%errorlevel%"
if not "%BUILD_RESULT%"=="0" goto build_done

start "" /wait "%CD%\build\SowCompat.exe" --self-test-root "%CD%"
set "BUILD_RESULT=%errorlevel%"
if not "%BUILD_RESULT%"=="0" goto build_done

powershell.exe -NoProfile -Command "Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1'); Get-FileHash -Algorithm SHA256 -LiteralPath '.\build\g.exe','.\build\SowCompat.exe' | ForEach-Object { Write-Host ($_.Path + '  ' + $_.Hash) }"
set "BUILD_RESULT=%errorlevel%"

:build_done
popd
exit /b %BUILD_RESULT%
