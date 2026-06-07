<#
.SYNOPSIS
    Alibi (console-rig mode) - Visual Companion driver.

.DESCRIPTION
    Thin shim that dot-sources the shared dark-tactical renderer in
    visual-companion-common.ps1 and invokes Render-AlibiHtml with the
    console-mode coverage block.

    Console-mode scans look for the MITM stack used to layer mouse-and-
    keyboard cheats onto a console rig: vision aimbots running on the
    feeder PC, HID emulators (vJoy / ViGEmBus / ScpToolkit / DS4Windows),
    capture-card software (Elgato / AVerMedia / OBS / Streamlabs), and
    input-device configurators (XIM / Cronus / ReaSnow / Titan / KMBox /
    reWASD). Verdict tiers: MITM CHEAT STACK DETECTED / CAPTURE STACK
    PRESENT / UNSURE / CLEAN.

    The previous v3.x cream/serif implementation lived directly in this
    file (~800 lines of embedded HTML). It was replaced in v4.2 by the
    shared renderer that mirrors python/src/alibi/visual_companion.py
    byte-for-byte.

.NOTES
    Author: Bread
    Contributor: Drownmw
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$InputPath,
    [string]$OutputPath
)

if (-not (Test-Path $InputPath)) {
    Write-Host "ERROR: Input not found: $InputPath" -ForegroundColor Red
    exit 1
}

if (-not $OutputPath) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($InputPath)
    $dir  = [System.IO.Path]::GetDirectoryName($InputPath)
    if (-not $dir) { $dir = $PWD }
    $OutputPath = Join-Path $dir "${base}_visual.html"
}

. (Join-Path $PSScriptRoot 'visual-companion-common.ps1')

$coverage = @(
    'Console-side state is invisible to this scan - this PC must be the feeder rig, not the console itself.',
    'DMA cheats running on the console are out of scope. PC-side DMA development artifacts are flagged.',
    'A capture-card stack alone is normal for streamers; the verdict only escalates when paired with cheat/input/spoofer artifacts.',
    'Input devices configured on a separate machine leave no trace on this PC.',
    'Keyword matching only. Sophisticated cleaners can wipe most of these artifacts.',
    'A clean result is necessary but not sufficient.'
)

Render-AlibiHtml -InputPath $InputPath -OutputPath $OutputPath -ModeLabel 'console-mode' -CoverageLimitations $coverage
