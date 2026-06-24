<#
.SYNOPSIS
    Dump every cheat/brand keyword alibi already knows, for pulse de-duplication.

.DESCRIPTION
    The monthly cheat-intel pulse (see PULSE-RUNBOOK.md) discovers candidate
    brands in the wild, then must answer "is this already covered?" before
    proposing it. This script is the source of truth for that check: it
    dot-sources the live engine and prints the union of all intel-relevant
    keyword arrays — so the dedupe corpus can never drift from what actually
    ships.

    Allowlist / known-good arrays ($DriverPublisher_Allowlist, $KnownGood) are
    deliberately EXCLUDED — those are legitimate vendors, not cheat tokens.

.OUTPUTS
    Sorted, lower-cased, unique token list to stdout (one per line). Pipe to a
    file for the pulse: extract-known-tokens.ps1 > known-tokens.txt

.NOTES
    Run:  powershell -File dev\intel\extract-known-tokens.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # this script is dev/intel/
$engine   = Join-Path $repoRoot 'alibi-engine\scanner\forensic-common.ps1'
if (-not (Test-Path $engine)) { throw "Engine not found: $engine" }

# Dot-source defines the arrays without running any scan (Invoke-AllScans is
# only called by the driver scripts, never on dot-source).
. $engine

# Intel-relevant arrays only. Name patterns auto-pick up future additions
# (e.g. a new $CheatBrands_<Game>) so this never silently goes stale.
$includePatterns = @(
    'CheatBrands_*', '*Spoofer*', 'DMA_*', 'VisionAimbot_*', 'CheatFeature_*',
    'InputDevices', 'NetworkAttack_*', 'LuaCheat_*', 'DLLInjector_*',
    'DualUse_Tools', 'CheatMarketplaceDomains', 'ScriptContent_*', 'AppDataPatterns'
)
$exclude = @('DriverPublisher_Allowlist', 'KnownGood', 'KnownCheatHashes')

$tokens = [System.Collections.Generic.HashSet[string]]::new()
foreach ($pat in $includePatterns) {
    Get-Variable -Name $pat -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name -in $exclude) { return }
        foreach ($v in @($_.Value)) {
            if ($v -is [string] -and $v.Trim()) { [void]$tokens.Add($v.Trim().ToLower()) }
        }
    }
}

$sorted = $tokens | Sort-Object
$sorted
[Console]::Error.WriteLine("`n  $($sorted.Count) unique known tokens across intel arrays.")
