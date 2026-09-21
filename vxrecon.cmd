@echo off
REM VXRecon launcher for cmd.exe / PowerShell fallback.
REM Prefers a globally installed `vxrecon` console script, otherwise runs the
REM local source tree via the bundled bootstrap script.
REM
REM IMPORTANT: We must ignore any `vxrecon` that resolves to THIS file,
REM otherwise `where vxrecon` would find us and recurse forever.

setlocal
set "SCRIPT_DIR=%~dp0"
set "SELF=%~f0"

set "GLOBAL_CMD="
for /f "delims=" %%I in ('where vxrecon 2^>nul') do (
    if /I not "%%~fI"=="%SELF%" (
        if not defined GLOBAL_CMD set "GLOBAL_CMD=%%I"
    )
)

if defined GLOBAL_CMD (
    "%GLOBAL_CMD%" %*
    exit /b %ERRORLEVEL%
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%vxrecon.ps1" %*
exit /b %ERRORLEVEL%
