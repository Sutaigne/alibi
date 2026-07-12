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

REM --- Black-box run log on the Desktop. If this window ever closes early,
REM     this file shows exactly how far the launcher got. ---
set "RUNLOG=%USERPROFILE%\Desktop\alibi-run.log"
>"%RUNLOG%" echo [start] %DATE% %TIME%
>>"%RUNLOG%" echo [start] self=%~f0
>>"%RUNLOG%" echo [start] cwd=%CD%

REM --- Clear any stale summary files from a previous run ---
del "%TEMP%\alibi-pc.summary" 2>nul
del "%TEMP%\alibi-console.summary" 2>nul
>>"%RUNLOG%" echo [step] cleared stale summaries

REM --- Require admin. We do NOT silently self-elevate any more: that hidden
REM     re-launch (Start-Process -Verb RunAs) closed this window to open a new
REM     one, which is exactly the "appeared and vanished" behavior. Instead we
REM     detect non-admin and show a clear message that STAYS on screen. ---
net session >nul 2>&1
set "ADMINRC=!errorLevel!"
>>"%RUNLOG%" echo [admin] net-session-errorlevel=!ADMINRC!  0-means-admin
if "!ADMINRC!" NEQ "0" (
    cls
    echo.
    echo   ============================================================
    echo     Alibi needs to run as administrator
    echo   ============================================================
    echo.
    echo     This window is NOT elevated, so the scan cannot read the
    echo     Windows forensic sources it needs.
    echo.
    echo     To fix it ^(about 5 seconds^):
    echo       1.  Close this window.
    echo       2.  RIGHT-CLICK   "Run scan.bat"
    echo       3.  Choose   "Run as administrator"
    echo       4.  Click YES on the Windows prompt.
    echo.
    echo     The window will then stay open and show live progress.
    echo.
    echo   ============================================================
    echo.
    >>"%RUNLOG%" echo [admin] NOT elevated - showed instructions, exiting cleanly
    echo     Press any key to close this window.
    pause >nul
    exit /b
)
>>"%RUNLOG%" echo [admin] elevated OK - proceeding to scan

set "KIT=%~dp0alibi-engine\scanner"

REM --- Tell the scanners the launcher is hosting them so they don't clear
REM     the screen (which erased the "[ 1 of 2 ] / [ 2 of 2 ]" progress
REM     context and made scan 2 look like scan 1 restarting). ---
set "ALIBI_LAUNCHER=1"

REM --- Optional online driver-safety check. Asked ONCE here, up front, with a
REM     10-second auto-skip, so the scan itself never blocks on a hidden prompt. ---
set "LOL=-SkipLOLDrivers"
cls
echo.
echo   ============================================================
echo     Optional:  online driver-safety check
echo   ============================================================
echo.
echo     Alibi can also cross-check your drivers against a public
echo     list of known-vulnerable / malicious drivers (loldrivers.io).
echo     This is the ONE optional network call. It sends NOTHING about
echo     your PC - it only downloads a public list.
echo.
echo     The scan produces a valid report either way.
echo     Skips automatically in 10 seconds if you do nothing.
echo.
choice /C YN /N /T 10 /D N /M "   Include the online driver check?  [Y/N]: "
if errorlevel 2 ( set "LOL=-SkipLOLDrivers" ) else ( set "LOL=-FetchLOLDrivers" )
>>"%RUNLOG%" echo [choice] LOL=!LOL!

cls
echo.
echo   ============================================================
echo     ALIBI IS RUNNING  -  you did everything right
echo   ============================================================
echo.
echo     [ OK ]  Launched as administrator
echo     [ OK ]  Scanner files found
echo     [ OK ]  Scan started
echo.
echo     What happens now:
echo       - Two scans run back to back: first this PC, then the
echo         console-rig side.
echo       - This takes about 1 to 3 minutes total.
echo       - Steps print below as they run. It is normal for a
echo         step to pause for a few seconds - it is NOT frozen.
echo       - KEEP THIS WINDOW OPEN. It will clearly say when it is
echo         finished and list your files.
echo.
echo   ============================================================
echo     [ 1 of 2 ]  Scanning this PC ...   (please wait)
echo   ------------------------------------------------------------
echo.
>>"%RUNLOG%" echo [scan1] launching forensic-scan.ps1 %LOL%
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT%\forensic-scan.ps1" %LOL% -SkipBrowserOpen
>>"%RUNLOG%" echo [scan1] forensic-scan.ps1 returned !errorLevel!
echo.
if exist "%TEMP%\alibi-pc.summary" (
    echo     [ OK ]  PC scan finished.
) else (
    echo     [FAIL]  PC scan did not finish - details are above.
)

echo.
echo   ============================================================
echo     [ 2 of 2 ]  Scanning the console-rig side ...   (please wait)
echo   ------------------------------------------------------------
echo.
>>"%RUNLOG%" echo [scan2] launching console-rig-audit.ps1 %LOL%
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT%\console-rig-audit.ps1" %LOL% -SkipBrowserOpen
>>"%RUNLOG%" echo [scan2] console-rig-audit.ps1 returned !errorLevel!
echo.
if exist "%TEMP%\alibi-console.summary" (
    echo     [ OK ]  Console-rig scan finished.
) else (
    echo     [FAIL]  Console-rig scan did not finish - details are above.
)

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
set "ALL_OK=1"
if not exist "%TEMP%\alibi-pc.summary" set "ALL_OK=0"
if not exist "%TEMP%\alibi-console.summary" set "ALL_OK=0"
if "!ALL_OK!"=="1" (
    echo   ############################################################
    echo   ##                                                        ##
    echo   ##      [ OK ]   SCAN COMPLETE  -  everything worked      ##
    echo   ##                                                        ##
    echo   ############################################################
) else (
    echo   ############################################################
    echo   ##                                                        ##
    echo   ##   [FAIL]  FINISHED WITH PROBLEMS - read details above  ##
    echo   ##                                                        ##
    echo   ############################################################
)
echo.
echo   ------------------------- SUMMARY --------------------------
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
REM     Use explorer.exe (not `start ""`) so Chrome/Edge happily attach to an
REM     existing non-admin browser process even though we're elevated — `start`
REM     can leak the admin token to a new browser window and confuse things.
if defined PC_HTML (
    if exist "!PC_HTML!" (
        explorer.exe "!PC_HTML!"
    )
)

REM --- Copy all four paths to the clipboard so the user can paste straight
REM     into Discord / email / a ticket. We build the text in a temp file and
REM     pipe THAT to clip: piping a ( ) block that contains `if defined`
REM     triggers a cmd parse error ("echo was unexpected at this time"). ---
set "CLIPTMP=%TEMP%\alibi-clip.txt"
> "%CLIPTMP%" echo Alibi scan report - !PC_VERDICT! / !CONSOLE_VERDICT!
>>"%CLIPTMP%" echo.
if defined PC_TXT       >>"%CLIPTMP%" echo PC .txt:        !PC_TXT!
if defined PC_HTML      >>"%CLIPTMP%" echo PC .html:       !PC_HTML!
if defined CONSOLE_TXT  >>"%CLIPTMP%" echo Console .txt:   !CONSOLE_TXT!
if defined CONSOLE_HTML >>"%CLIPTMP%" echo Console .html:  !CONSOLE_HTML!
>>"%CLIPTMP%" echo.
>>"%CLIPTMP%" echo Verify the kit at: https://github.com/Sutaigne/alibi
>>"%CLIPTMP%" echo                    Reviewer guide: alibi-engine/docs/for-reviewers.md
>>"%CLIPTMP%" echo                    Kit integrity:  HASHES.txt
clip < "%CLIPTMP%"
del "%CLIPTMP%" 2>nul

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
echo        Reviewer guide: alibi-engine/docs/for-reviewers.md in the same repo.
echo.
echo   ============================================================
>>"%RUNLOG%" echo [end] reached final summary - run complete
echo.
echo    Press any key to close this window.
pause >nul
