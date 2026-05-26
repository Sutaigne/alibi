@echo off
REM ========================================================================
REM  PC Forensic Check - Launcher
REM
REM  Double-click this file to run the scan.
REM  The scan will request admin permission (UAC prompt) for full coverage.
REM  Output: ONE timestamped .txt file on your Desktop.
REM
REM  This launcher does three things:
REM    1. Checks for admin privilege; re-launches itself elevated if needed
REM    2. Runs forensic-scan.ps1 (in the same folder as this .bat)
REM    3. Keeps the window open at the end so you can see the result path
REM
REM  Author: Bread
REM  Contributor: Drownmw
REM ========================================================================

REM --- Self-elevate if not already admin ----------------------------------
NET SESSION >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo  Requesting administrator permission for full scan coverage...
    echo  Please approve the UAC prompt.
    echo.
    powershell.exe -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM --- We're elevated. Run the scan. --------------------------------------
echo.
echo  Starting PC Forensic Check (elevated)...
echo.

REM Find forensic-scan.ps1 next to this .bat (using %~dp0 for portability)
set "SCRIPT=%~dp0forensic-scan.ps1"

if not exist "%SCRIPT%" (
    echo.
    echo  ERROR: forensic-scan.ps1 not found in the same folder as this .bat
    echo  Expected: %SCRIPT%
    echo.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"

echo.
echo  Press any key to close this window.
pause >nul
