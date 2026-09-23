@echo off
setlocal
REM ---------------------------------------------------------------------
REM Builds the two tiny capture targets with the MSVC x64 toolset.
REM Run from anywhere:  examples\tiny\build.bat
REM ---------------------------------------------------------------------

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo error: vswhere.exe not found; is Visual Studio installed?
    exit /b 1
)

REM vswhere lives under "Program Files (x86)", and the ")" in that path closes
REM a for /f (...) block early -- so route the answer through a temp file
REM rather than fighting cmd's quoting rules.
set "VSPATH="
set "VSTMP=%TEMP%\vspath_atropos.txt"
"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%VSTMP%"
if exist "%VSTMP%" set /p VSPATH=<"%VSTMP%"
del "%VSTMP%" 2>nul

if not defined VSPATH (
    echo error: no MSVC x64 toolset found
    exit /b 1
)

echo [build] toolset: %VSPATH%
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1

cd /d "%~dp0"

REM -- (a) no CRT ------------------------------------------------------
REM /Od      optimisations off, so the loop survives verbatim
REM /GS-     no stack cookie (__security_check_cookie lives in the CRT)
REM /Gs...   no stack probes (__chkstk likewise)
REM link:    custom entry, no default libraries, kernel32 only
echo [build] tiny_nocrt.exe
cl /nologo /c /Od /GS- /Gs1000000 /Fotiny_nocrt.obj tiny_nocrt.c
if errorlevel 1 exit /b 1
link /nologo /SUBSYSTEM:CONSOLE /ENTRY:start /NODEFAULTLIB /OUT:tiny_nocrt.exe tiny_nocrt.obj kernel32.lib
if errorlevel 1 exit /b 1

REM -- (b) default dynamic CRT -----------------------------------------
echo [build] tiny_crt.exe
cl /nologo /Od /MD /Fetiny_crt.exe /Fotiny_crt.obj tiny_crt.c /link /SUBSYSTEM:CONSOLE
if errorlevel 1 exit /b 1

echo [build] ok
exit /b 0
