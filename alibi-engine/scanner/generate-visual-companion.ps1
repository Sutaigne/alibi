<#
.SYNOPSIS
    Alibi (PC mode) - Visual Companion driver.

.DESCRIPTION
    Thin shim that dot-sources the shared dark-tactical renderer in
    visual-companion-common.ps1 and invokes Render-AlibiHtml with the
    PC-mode coverage block.

    The previous v3.x cream/serif implementation lived directly in this
    file (~950 lines of embedded HTML). It was replaced in v4.2 by the
    shared renderer in visual-companion-common.ps1, eliminating the
    keyword-array and HTML-template drift flagged in docs/handoff.md.

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
    'DMA cheats cannot be detected at runtime by design - no PC-side footprint. This scan flags DMA development artifacts only.',
    'Input devices configured on a separate machine leave no trace on this PC.',
    'Session duration is recorded in SRUM and requires an ESE database parser. Not extracted here.',
    'Keyword matching only. Sophisticated cleaners can wipe most of these artifacts.',
    'A clean result is necessary but not sufficient.'
)

Render-AlibiHtml -InputPath $InputPath -OutputPath $OutputPath -ModeLabel 'pc-mode' -CoverageLimitations $coverage
