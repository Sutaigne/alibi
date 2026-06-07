<#
.SYNOPSIS
    Build the clean, distributable Alibi kit as dist/alibi.zip.

.DESCRIPTION
    The repo keeps developer/other-tool folders (python/, scripts/, netcheck/)
    that users do NOT need. GitHub's "Download ZIP" cannot exclude them, so the
    canonical download is THIS built artifact, not the raw repo zip.

    The produced zip extracts to a single top folder "alibi/" containing only:
        alibi/
          Run scan.bat        <- the only thing a user runs
          START HERE.txt
          HASHES.txt
          alibi-engine/       <- scanner engine + docs (tucked away)

    Files are copied byte-for-byte (CRLF preserved) so SHA256s match HASHES.txt.

.NOTES
    Run:  powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1
#>
[CmdletBinding()]
param(
    [string]$OutDir
)
$ErrorActionPreference = 'Stop'

$root  = Split-Path -Parent $PSScriptRoot          # repo root (scripts/ is one level down)
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }

# Staging dir: <temp>\alibi-build\alibi  (so the zip's top folder is "alibi")
$buildBase = Join-Path $env:TEMP 'alibi-build'
$stage     = Join-Path $buildBase 'alibi'
if (Test-Path $buildBase) { Remove-Item $buildBase -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# --- Allowlist: exactly what ships ---
Copy-Item -LiteralPath (Join-Path $root 'Run scan.bat')   -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'START HERE.txt') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'HASHES.txt')     -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'alibi-engine')   -Destination $stage -Recurse

# Drop any stray scan outputs that might sit in the tree
Get-ChildItem -Path $stage -Recurse -Include 'AlibiReport_*','AlibiRigReport_*' -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

# --- Zip it ---
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$zip = Join-Path $OutDir 'alibi.zip'
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path $stage -DestinationPath $zip

# --- Report ---
$fileCount = (Get-ChildItem -Path $stage -Recurse -File).Count
Write-Host ''
Write-Host "  Built: $zip" -ForegroundColor Green
Write-Host "  Top folder: alibi\   ($fileCount files)" -ForegroundColor DarkGray
Write-Host "  Excluded:   python\, scripts\, netcheck\, .git*, .github\" -ForegroundColor DarkGray
Write-Host ''
Write-Host "  Distribute THIS zip (not the GitHub 'Download ZIP')." -ForegroundColor Yellow
