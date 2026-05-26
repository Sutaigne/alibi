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

echo.
echo  ==================== FINAL SCAN SUMMARY ====================
if exist "%TEMP%\alibi-pc.summary" (
    for /f "tokens=1,2,3,4,5 delims=|" %%a in (%TEMP%\alibi-pc.summary) do (
        echo  PC verdict:        %%a
        echo  PC report:         %%b
        echo    cheat HIGH: %%c  input HIGH: %%d  MEDIUM: %%e
    )
)
echo.
if exist "%TEMP%\alibi-console.summary" (
    for /f "tokens=1,2,3,4,5 delims=|" %%a in (%TEMP%\alibi-console.summary) do (
        echo  Console verdict:   %%a
        echo  Console report:    %%b
        echo    cheat HIGH: %%c  input HIGH: %%d  MEDIUM: %%e
    )
)
echo  ============================================================
echo.

REM --- Auto-open the PC-mode HTML in the default browser. ---
if exist "%TEMP%\alibi-pc.summary" (
    for /f "tokens=2 delims=|" %%a in (%TEMP%\alibi-pc.summary) do (
        set "PC_HTML=%%a"
        setlocal EnableDelayedExpansion
        set "PC_HTML=!PC_HTML:.txt=_visual.html!"
        if exist "!PC_HTML!" (
            echo  Opening your PC-mode report in the default browser...
            start "" "!PC_HTML!"
            echo.
        )
        endlocal
    )
)

pause
