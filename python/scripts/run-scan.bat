@echo off
REM Unified launcher — runs PC Forensic Check + Console Rig Audit back-to-back,
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
echo   PC Check ^(Python parity^) - unified launcher
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

echo  [1/2] Running PC Forensic Check...
python -m pc_check
echo.

echo  [2/2] Running Console Rig Audit...
python -m pc_check.console_rig_audit --skip-loldrivers
echo.

echo.
echo  ==================== FINAL SCAN SUMMARY ====================
if exist "%TEMP%\pc-check-pc.summary" (
    for /f "tokens=1,2,3,4,5 delims=|" %%a in (%TEMP%\pc-check-pc.summary) do (
        echo  PC verdict:        %%a
        echo  PC report:         %%b
        echo    cheat HIGH: %%c  input HIGH: %%d  MEDIUM: %%e
    )
)
echo.
if exist "%TEMP%\pc-check-console.summary" (
    for /f "tokens=1,2,3,4,5 delims=|" %%a in (%TEMP%\pc-check-console.summary) do (
        echo  Console verdict:   %%a
        echo  Console report:    %%b
        echo    cheat HIGH: %%c  input HIGH: %%d  MEDIUM: %%e
    )
)
echo  ============================================================
echo.
pause
