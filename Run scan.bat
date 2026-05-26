@echo off
setlocal EnableDelayedExpansion
REM ========================================================================
REM  Alibi - Launcher
REM
REM  Runs the full scan suite (PC scan + console-rig scan), auto-generates
REM  HTML companions, and shows a consolidated final summary on screen.
REM
REM  Author: Bread
REM  Contributor: Drownmw
REM ========================================================================

REM --- Clear any stale summary files from a previous run ---
del "%TEMP%\alibi-pc.summary" 2>nul
del "%TEMP%\alibi-console.summary" 2>nul

REM --- Require admin. Self-elevate if needed; fail clean if declined. ---
NET SESSION >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo   This scan needs administrator permission.
    echo   A Windows UAC prompt will appear in a moment.
    echo   Please click YES to continue.
    echo.
    powershell.exe -NoProfile -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop } catch { exit 1 }"
    if !errorLevel! NEQ 0 (
        echo.
        echo   ============================================================
        echo    Admin permission was declined.
        echo   ============================================================
        echo.
        echo   The scan requires admin to access several Windows forensic
        echo   sources. Without admin most come back as "Access denied"
        echo   and the resulting report is too incomplete to be useful.
        echo.
        echo   To run the scan: close this window, RIGHT-CLICK
        echo   "Run scan.bat" and pick "Run as administrator".
        echo.
        pause
    )
    exit /b
)

set "KIT=%~dp0scanner"

cls
echo.
echo   ============================================================
echo    Alibi  -  Full Scan Suite
echo    Total time: about 2-3 minutes. Window will stay open.
echo   ============================================================
echo.
echo   [Phase 1 of 2]  Alibi
echo   ------------------------------------------------------------
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT%\forensic-scan.ps1"

echo.
echo   ============================================================
echo   [Phase 2 of 2]  Alibi (console-rig mode)
echo   ------------------------------------------------------------
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT%\console-rig-audit.ps1"

REM --- Read summary files written by each .ps1 ---
set "PC_VERDICT=(scan did not complete)"
set "PC_TXT="
set "PC_CHEAT=0"
set "PC_INPUT=0"
set "PC_MED=0"
if exist "%TEMP%\alibi-pc.summary" (
    for /f "usebackq tokens=1-5 delims=|" %%a in ("%TEMP%\alibi-pc.summary") do (
        set "PC_VERDICT=%%a"
        set "PC_TXT=%%b"
        set "PC_CHEAT=%%c"
        set "PC_INPUT=%%d"
        set "PC_MED=%%e"
    )
)

set "CONSOLE_VERDICT=(scan did not complete)"
set "CONSOLE_TXT="
set "CONSOLE_CHEAT=0"
set "CONSOLE_INPUT=0"
set "CONSOLE_MED=0"
if exist "%TEMP%\alibi-console.summary" (
    for /f "usebackq tokens=1-5 delims=|" %%a in ("%TEMP%\alibi-console.summary") do (
        set "CONSOLE_VERDICT=%%a"
        set "CONSOLE_TXT=%%b"
        set "CONSOLE_CHEAT=%%c"
        set "CONSOLE_INPUT=%%d"
        set "CONSOLE_MED=%%e"
    )
)

echo.
echo.
echo   ############################################################
echo   ##                                                        ##
echo   ##              FINAL SCAN SUMMARY                        ##
echo   ##                                                        ##
echo   ############################################################
echo.
echo    Alibi
echo    --------------------------------------------------------
echo      Verdict:        !PC_VERDICT!
echo      Cheat HIGH:     !PC_CHEAT!
echo      Input HIGH:     !PC_INPUT!
echo      MEDIUM total:   !PC_MED!
echo      Report:         !PC_TXT!
echo.
echo    Alibi (console-rig mode)
echo    --------------------------------------------------------
echo      Verdict:        !CONSOLE_VERDICT!
echo      Cheat HIGH:     !CONSOLE_CHEAT!
echo      Input HIGH:     !CONSOLE_INPUT!
echo      MEDIUM total:   !CONSOLE_MED!
echo      Report:         !CONSOLE_TXT!
echo.
echo   ------------------------------------------------------------
echo    Each .txt has a matching _visual.html on your Desktop.
echo    Send the .txt (or the .html) to whoever asked.
echo   ============================================================
echo.
echo    Press any key to close this window.
pause >nul
