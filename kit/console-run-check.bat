@echo off
REM ========================================================================
REM  Alibi (console-rig mode) - Launcher
REM
REM  Use this if a PC is part of your console gaming rig (capture-card host,
REM  second monitor, streaming PC, etc.) and you want to demonstrate that
REM  PC is not being used to help cheat at console games.
REM
REM  If there is no PC connected to your console, this is not the right
REM  tool - use console-setup-checklist.html instead.
REM
REM  Double-click this file to run the scan.
REM  The scan will request admin permission (UAC prompt) for full coverage.
REM  Output: ONE timestamped .txt file on your Desktop (AlibiRigReport_*.txt).
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
echo  Starting Alibi (console-rig mode) (elevated)...
echo.

REM Find console-rig-audit.ps1 next to this .bat (using %~dp0 for portability)
set "SCRIPT=%~dp0console-rig-audit.ps1"

if not exist "%SCRIPT%" (
    echo.
    echo  ERROR: console-rig-audit.ps1 not found in the same folder as this .bat
    echo  Expected: %SCRIPT%
    echo.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"

echo.
echo  Press any key to close this window.
pause >nul
