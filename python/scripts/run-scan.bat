@echo off
REM Unified launcher — runs Alibi + Alibi (console-rig mode) back-to-back,
REM then reads the %TEMP% summary files for a consolidated final screen.
REM Mirrors ready-to-flash\Run scan.bat from the PowerShell distribution.

setlocal ENABLEDELAYEDEXPANSION

REM Self-elevate via UAC if not already admin.
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    powershell.exe -NoProfile -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
cd ..

echo.
echo  ========================================
echo   Alibi ^(Python parity^) - unified launcher
echo  ========================================
echo.

REM Verify Python is on PATH.
where python >nul 2>&1
if %errorlevel% NEQ 0 (
    echo.
    echo  ERROR: Python is not on PATH.
    echo  Install Python 3.10+ from python.org and re-run this script.
    echo.
    pause
    exit /b 1
)

echo  [1/2] Running Alibi...
python -m alibi --no-open-browser
echo.

echo  [2/2] Running Alibi (console-rig mode)...
python -m alibi.console_rig_audit --skip-loldrivers --no-open-browser
echo.

setlocal EnableDelayedExpansion

REM --- Parse summary files into variables ---
set "PC_VERDICT=(scan did not complete)"
set "PC_TXT="
set "PC_CHEAT=0"
set "PC_INPUT=0"
set "PC_MED=0"
if exist "%TEMP%\alibi-pc.summary" (
    for /f "usebackq tokens=1,2,3,4,5 delims=|" %%a in ("%TEMP%\alibi-pc.summary") do (
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
    for /f "usebackq tokens=1,2,3,4,5 delims=|" %%a in ("%TEMP%\alibi-console.summary") do (
        set "CONSOLE_VERDICT=%%a"
        set "CONSOLE_TXT=%%b"
        set "CONSOLE_CHEAT=%%c"
        set "CONSOLE_INPUT=%%d"
        set "CONSOLE_MED=%%e"
    )
)

set "PC_HTML="
set "CONSOLE_HTML="
if defined PC_TXT      set "PC_HTML=!PC_TXT:.txt=_visual.html!"
if defined CONSOLE_TXT set "CONSOLE_HTML=!CONSOLE_TXT:.txt=_visual.html!"

echo.
echo  ==================== FINAL SCAN SUMMARY ====================
echo.
echo   Alibi  (PC mode)
echo   --------------------------------------------------------
echo     Verdict:        !PC_VERDICT!
echo     Cheat HIGH:     !PC_CHEAT!     Input HIGH: !PC_INPUT!     MEDIUM: !PC_MED!
echo     .txt report:    !PC_TXT!
echo     .html visual:   !PC_HTML!
echo.
echo   Alibi  (console-rig mode)
echo   --------------------------------------------------------
echo     Verdict:        !CONSOLE_VERDICT!
echo     Cheat HIGH:     !CONSOLE_CHEAT!     Input HIGH: !CONSOLE_INPUT!     MEDIUM: !CONSOLE_MED!
echo     .txt report:    !CONSOLE_TXT!
echo     .html visual:   !CONSOLE_HTML!
echo.

REM --- Auto-open the PC-mode HTML in the default browser. ---
REM     Using explorer.exe (not `start ""`) so an existing browser process
REM     can take the file even if we're running elevated.
if defined PC_HTML (
    if exist "!PC_HTML!" (
        explorer.exe "!PC_HTML!"
    )
)

REM --- Copy all four paths to the clipboard. ---
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

echo  ============================================================
echo   WHAT TO DO NEXT
echo  ============================================================
echo.
echo    1. Your PC-mode report just opened in your browser.
echo       The console-rig .html is on your Desktop next to it.
echo.
echo    2. The four file paths above are now on your CLIPBOARD.
echo       Paste anywhere (Discord, email, ticket) to share them.
echo       Or drag the files themselves from your Desktop.
echo.
echo    3. Tell the reviewer to verify the kit before trusting
echo       the report: github.com/Sutaigne/alibi/blob/main/HASHES.txt
echo       Reviewer guide: docs/for-reviewers.md in the same repo.
echo.
echo  ============================================================
echo.
pause
endlocal
