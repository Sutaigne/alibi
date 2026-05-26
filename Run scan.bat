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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT%\forensic-scan.ps1" -SkipBrowserOpen

echo.
echo   ============================================================
echo   [Phase 2 of 2]  Alibi (console-rig mode)
echo   ------------------------------------------------------------
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT%\console-rig-audit.ps1" -SkipBrowserOpen

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

REM --- Derive HTML companion paths (one per .txt) ---
set "PC_HTML="
set "CONSOLE_HTML="
if defined PC_TXT      set "PC_HTML=!PC_TXT:.txt=_visual.html!"
if defined CONSOLE_TXT set "CONSOLE_HTML=!CONSOLE_TXT:.txt=_visual.html!"

echo.
echo.
echo   ############################################################
echo   ##                                                        ##
echo   ##              FINAL SCAN SUMMARY                        ##
echo   ##                                                        ##
echo   ############################################################
echo.
echo    Alibi  (PC mode)
echo    --------------------------------------------------------
echo      Verdict:        !PC_VERDICT!
echo      Cheat HIGH:     !PC_CHEAT!     Input HIGH: !PC_INPUT!     MEDIUM: !PC_MED!
echo      .txt report:    !PC_TXT!
echo      .html visual:   !PC_HTML!
echo.
echo    Alibi  (console-rig mode)
echo    --------------------------------------------------------
echo      Verdict:        !CONSOLE_VERDICT!
echo      Cheat HIGH:     !CONSOLE_CHEAT!     Input HIGH: !CONSOLE_INPUT!     MEDIUM: !CONSOLE_MED!
echo      .txt report:    !CONSOLE_TXT!
echo      .html visual:   !CONSOLE_HTML!
echo.

REM --- Auto-open the PC-mode HTML in the default browser.
REM     Only one tab to avoid spam; the console-rig file is right next to it.
if defined PC_HTML (
    if exist "!PC_HTML!" (
        start "" "!PC_HTML!"
    )
)

REM --- Copy all four paths to the clipboard so the user can paste
REM     straight into Discord / email / a ticket comment. ---
(
    echo Alibi scan report ^(!PC_VERDICT! / !CONSOLE_VERDICT!^)
    echo.
    if defined PC_TXT   echo PC .txt:        !PC_TXT!
    if defined PC_HTML  echo PC .html:       !PC_HTML!
    if defined CONSOLE_TXT  echo Console .txt:  !CONSOLE_TXT!
    if defined CONSOLE_HTML echo Console .html: !CONSOLE_HTML!
    echo.
    echo Verify the kit at: https://github.com/Sutaigne/alibi
    echo                    Reviewer guide: docs/for-reviewers.md
    echo                    Kit integrity:  HASHES.txt
) | clip

echo   ============================================================
echo    WHAT TO DO NEXT
echo   ============================================================
echo.
echo     1. Your PC-mode report just opened in your browser.
echo        The console-rig .html is on your Desktop next to it.
echo.
echo     2. The four file paths above are now on your CLIPBOARD.
echo        Paste anywhere (Discord, email, ticket) to share them.
echo        Or drag the files themselves from your Desktop.
echo.
echo     3. Tell the reviewer to verify the kit before trusting
echo        the report: github.com/Sutaigne/alibi/blob/main/HASHES.txt
echo        Reviewer guide: docs/for-reviewers.md in the same repo.
echo.
echo   ============================================================
echo.
echo    Press any key to close this window.
pause >nul
