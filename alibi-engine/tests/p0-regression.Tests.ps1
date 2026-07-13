<#
  alibi v4.3 P0 regression tests — pure-function checks for the trust-first fixes.

  These lock in the false-positive fixes drawn from two real reports:
    - 4070PC / lj031  -> CHEATS DETECTED against alibi's own dev/intel file
    - DESKTOP-F3SN84F -> INPUT DEVICES DETECTED buried under FP noise

  Run:  pwsh -File alibi-engine/tests/p0-regression.Tests.ps1
  (Pure-logic only — no Windows cmdlets invoked, so this runs on PS7/Linux CI too.)

  Verified passing on PowerShell 7.4.6 at authoring time (14/14).
#>
$ErrorActionPreference = 'Stop'
$engine = Join-Path $PSScriptRoot '..\scanner\forensic-common.ps1'
. $engine

$pass = 0; $fail = 0
function Check($name, $cond) {
    if ($cond) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor Green }
    else       { $script:fail++; Write-Host "  FAIL  $name" -ForegroundColor Red }
}

Write-Host '== P0-1 self-immunity (the CHEATS-DETECTED-on-itself fix) =='
Check 'flags dev/intel/extract-known-tokens.ps1 (the exact FP source)' (Test-IsAlibiOwnPath 'C:\Users\lj031\Downloads\alibi-main (2)\alibi-main\dev\intel\extract-known-tokens.ps1')
Check 'flags engine tree file'          (Test-IsAlibiOwnPath 'C:\Users\x\Downloads\alibi\alibi-engine\scanner\forensic-common.ps1')
Check 'flags alibi-main zip subtree'    (Test-IsAlibiOwnPath 'C:\stuff\alibi-main\README.md')
Check 'flags dev/scripts helper'        (Test-IsAlibiOwnPath 'C:\p\alibi-main\dev\scripts\build-release.ps1')
Check 'does NOT flag a real user cheat' (-not (Test-IsAlibiOwnPath 'C:\Users\x\Downloads\aimbot-loader\loader.ps1'))
Check 'does NOT flag unrelated ps1'     (-not (Test-IsAlibiOwnPath 'C:\Users\x\Documents\notes.ps1'))

Write-Host '== Match-Keyword bounded (P0-4 injector free-text) =='
Check 'bounded: inject does NOT match inside a larger word' (-not (Match-Keyword 'reinjection subsystem' @('inject') -Bounded))
Check 'bounded: exact token matches'    ([bool](Match-Keyword 'manual inject now' @('inject') -Bounded))
Check 'unbounded brand still matches'   ([bool](Match-Keyword 'myengineowningloader' @('engineowning')))

Write-Host '== Classify-PathRisk (P0-2 / P0-3 dependency) =='
Check 'AppData Local -> user-writable'  ((Classify-PathRisk 'C:\Users\lj031\AppData\Local\Programs\Opera GX\opera.exe') -eq 'user-writable')
Check 'System32 -> standard'            ((Classify-PathRisk 'C:\WINDOWS\system32\drivers\afd.sys') -eq 'standard')
Check 'Program Files -> typical'        ((Classify-PathRisk 'C:\Program Files\x\y.exe') -eq 'typical')

Write-Host '== Match-Allowlist (P0-2 allowlist expansion) =='
Check 'opera now allowlisted'           ([bool](Match-Allowlist 'C:\Users\lj031\AppData\Local\Programs\Opera GX\opera.exe opera.exe'))
Check 'random appdata NOT allowlisted'  (-not (Match-Allowlist 'C:\Users\x\AppData\Local\Temp\qwzx.exe qwzx.exe'))

Write-Host ''
Write-Host ("RESULT: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
