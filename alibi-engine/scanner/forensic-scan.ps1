<#
.SYNOPSIS
    Alibi v3.5 - all-in-one scanner with verdict + AI handoff.

.DESCRIPTION
    Read-only inspection of Windows forensic artifacts. Produces a single
    timestamped .txt file on the current user's Desktop.

    This is the PC-MODE driver. Most of the actual scanning logic lives in
    forensic-common.ps1, which is dot-sourced below. This file is responsible
    for:
      - Output path resolution (handles OneDrive Desktop redirection)
      - Initializing the shared $Findings list
      - PC-mode verdict computation (4 tiers: Cheats / Input / Unsure / Clean)
      - The QUICK READ block at the top of the report
      - Writing the report to disk
      - Optional visual-companion launch

    See forensic-common.ps1 for: keyword arrays, all 17 Scan-* functions,
    utility functions (Match-Keyword, Add-Finding, Score-Item, etc.),
    process / service snapshots, and the known-hash database.

.NOTES
    Author: Bread
    Contributor: Drownmw
#>

[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$SkipLOLDrivers,    # opt-out of the LOLDrivers (loldrivers.io) network fetch
    [switch]$FetchLOLDrivers,   # opt-IN without prompting (launcher asks once up-front)
    [switch]$SkipBrowserOpen    # don't auto-open the HTML companion at end (unified
                                # launcher passes this so we don't spam two tabs)
)

# ============================================================================
# Output path resolution (handles OneDrive Desktop redirection)
# ============================================================================
if (-not $OutputPath) {
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktop) -or -not (Test-Path $desktop)) {
        $candidates = @(
            (Join-Path $env:OneDrive 'Desktop'),
            (Join-Path $env:OneDriveConsumer 'Desktop'),
            (Join-Path $env:OneDriveCommercial 'Desktop'),
            (Join-Path $env:USERPROFILE 'Desktop'),
            $env:USERPROFILE
        ) | Where-Object { $_ -and (Test-Path $_) }
        if ($candidates.Count -gt 0) { $desktop = $candidates[0] }
        else {
            $desktop = $env:USERPROFILE
            try { New-Item -ItemType Directory -Force -Path $desktop | Out-Null } catch {}
        }
    }
    $OutputPath = Join-Path $desktop "AlibiReport_${stamp}.txt"
}
$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path $parent)) {
    try { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    catch { $OutputPath = Join-Path $env:USERPROFILE ([System.IO.Path]::GetFileName($OutputPath)) }
}

# ============================================================================
# Initialize shared state and load engine
# ============================================================================
$Findings = [System.Collections.Generic.List[pscustomobject]]::new()

# Dot-source the shared engine. Defines all Scan-* functions, utility
# functions, base keyword arrays, allowlists, and the hash database.
. "$PSScriptRoot\forensic-common.ps1"

# PC-mode composite keyword arrays. (Console mode adds VisionAimbots etc.)
# v3.8: pull in the game-specific brand arrays + PC-side AI vision aimbots
# into the HIGH-cheat composite. Low-confidence/single-source items go into
# Medium so they show up but never bump the verdict alone.
$Keywords_High_Cheats = $CheatBrands_COD + $Spoofer_Brands + $CheatFeature_Names + $DMA_Indicators `
    + $CheatBrands_CS2 + $CheatBrands_Apex + $CheatBrands_Tarkov + $CheatBrands_Rust `
    + $CheatBrands_R6 + $CheatBrands_MarvelRivals + $VisionAimbot_AI_PC
$Keywords_High_Input  = $InputDevices
$Keywords_Medium      = $DMA_DualUse + $DualUse_Tools + $CheatBrands_LowConfidence
$Keywords_ScriptHigh  = $ScriptContent_HighRisk
$Keywords_MouseMacro  = $ScriptContent_MouseMacro

# ============================================================================
# Banner
# ============================================================================
# When the unified launcher hosts us it shows "[ 1 of 2 ] / [ 2 of 2 ]"
# progress context; clearing the screen here erased it and made the second
# scan look like the first one restarting. Only clear when run standalone.
if (-not $env:ALIBI_LAUNCHER) { Clear-Host }
Write-Host ''
Write-Host '  Alibi v4.3.0 (PC mode)' -ForegroundColor Cyan
Write-Host '  =======================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Host:   $env:COMPUTERNAME"
Write-Host "  User:   $env:USERNAME"
if (Test-IsAdmin) { Write-Host '  Admin:  Yes' -ForegroundColor Green }
else { Write-Host '  Admin:  No (run as admin for full coverage)' -ForegroundColor Yellow }
Write-Host ''
Write-Host '  This will take 30-90 seconds. Please wait...' -ForegroundColor DarkGray
Write-Host ''

# ============================================================================
# Optional LOLDrivers BYOVD cross-reference (opt-in network call)
# ============================================================================
# $LOLDb is read by Scan-Drivers from parent scope. Setting it to $null
# (the default if user declines or -SkipLOLDrivers is passed) disables the
# cross-reference; Scan-Drivers still runs its keyword + unsigned checks.
$LOLDb = Resolve-LOLDriversDB -SkipLOLDrivers:$SkipLOLDrivers -FetchLOLDrivers:$FetchLOLDrivers

# ============================================================================
# Run the standard scan sequence (defined in forensic-common.ps1)
# ============================================================================
Write-Host '  [Phase 1/3] Cheat trace scan' -ForegroundColor Cyan
Invoke-AllScans

Write-Host ''
Write-Host '  [Phase 2/3] Process snapshot' -ForegroundColor Cyan
$processes = @(Get-ProcessSnapshot)

Write-Host ''
Write-Host '  [Phase 3/3] Service snapshot' -ForegroundColor Cyan
$services = @(Get-ServiceSnapshot)

# ============================================================================
# Recency decay (v3.8) - findings older than $RecencyThresholdDays (180d
# default) stay in the report but get demoted so they don't bump the verdict.
# ============================================================================
Apply-RecencyDecay

# ============================================================================
# Verdict computation (PC tiers)
# Filters: Metadata.RecencyClass -ne 'historical' so demoted-by-age findings
# do not contribute to verdict counts. They DO remain visible in the report.
# ============================================================================
$highCheats = @($Findings | Where-Object { $_.Severity -eq 'HIGH' -and $_.Kind -eq 'cheat' -and $_.Metadata.RecencyClass -ne 'historical' })
$highInput  = @($Findings | Where-Object { $_.Severity -eq 'HIGH' -and $_.Kind -eq 'input' -and $_.Metadata.RecencyClass -ne 'historical' })
$mediumAny  = @($Findings | Where-Object { $_.Severity -eq 'MEDIUM' -and $_.Metadata.RecencyClass -ne 'historical' })

# Historical findings - logged but excluded from verdict per the >180d rule
$historicalFindings = @($Findings | Where-Object { $_.Metadata.RecencyClass -eq 'historical' })
$historicalHigh     = @($historicalFindings | Where-Object { $_.Metadata.OriginalSeverity -eq 'HIGH' })

$procHighCheats = @($processes | Where-Object { $_.Score -eq 'HIGH' -and $_.Kind -eq 'cheat' })
$procHighInput  = @($processes | Where-Object { $_.Score -eq 'HIGH' -and $_.Kind -eq 'input' })
$procMedium     = @($processes | Where-Object { $_.Score -eq 'MEDIUM' })

$svcHighCheats = @($services | Where-Object { $_.Score -eq 'HIGH' -and $_.Kind -eq 'cheat' })
$svcHighInput  = @($services | Where-Object { $_.Score -eq 'HIGH' -and $_.Kind -eq 'input' })
$svcMedium     = @($services | Where-Object { $_.Score -eq 'MEDIUM' })

$totalCheatHigh = $highCheats.Count + $procHighCheats.Count + $svcHighCheats.Count
$totalInputHigh = $highInput.Count + $procHighInput.Count + $svcHighInput.Count
$totalMedium    = $mediumAny.Count + $procMedium.Count + $svcMedium.Count

$verdict = if ($totalCheatHigh -gt 0) { 'CHEATS DETECTED' }
           elseif ($totalInputHigh -gt 0) { 'INPUT DEVICES DETECTED' }
           elseif ($totalMedium -gt 0) { 'UNSURE' }
           else { 'CLEAN' }

$namedCheats = Get-Named-Items $Findings $processes $services 'cheat' 'HIGH'
$namedInput  = Get-Named-Items $Findings $processes $services 'input' 'HIGH'

# ============================================================================
# Compose output file
# ============================================================================
$lines = [System.Collections.Generic.List[string]]::new()

# QUICK READ block
$lines.Add('================================================================')
$lines.Add('  QUICK READ - START HERE')
$lines.Add('================================================================')
$lines.Add('')
$lines.Add("  VERDICT: $verdict")
$lines.Add('')

switch ($verdict) {
    'CHEATS DETECTED' {
        $lines.Add('  This scan found HIGH-confidence indicators of cheat software,')
        $lines.Add('  HWID spoofers, or DMA-cheat development artifacts on this machine.')
        $lines.Add('')
        $lines.Add('  Named items (cheat-confidence):')
        foreach ($n in $namedCheats) { $lines.Add("    - $n") }
        if ($namedInput.Count -gt 0) {
            $lines.Add('')
            $lines.Add('  Also detected (input devices - separate category):')
            foreach ($n in $namedInput) { $lines.Add("    - $n") }
        }
    }
    'INPUT DEVICES DETECTED' {
        $lines.Add('  No cheat brands or HWID spoofers were detected, but this scan')
        $lines.Add('  found HIGH-confidence indicators of input-device software.')
        $lines.Add('  (XIM, Cronus, ReaSnow, KMBox, Titan, etc.)')
        $lines.Add('')
        $lines.Add('  These are commercial mouse/keyboard adapters. Some games treat')
        $lines.Add('  them as bannable; some do not. Context is required.')
        $lines.Add('')
        $lines.Add('  Named items:')
        foreach ($n in $namedInput) { $lines.Add("    - $n") }
    }
    'UNSURE' {
        $lines.Add('  No HIGH-confidence cheat or input-device matches were detected.')
        $lines.Add("  However, $totalMedium MEDIUM finding(s) require human review.")
        $lines.Add('  These are typically dual-use tools or binaries running from')
        $lines.Add('  user-writable locations that the allowlist does not recognize.')
        $lines.Add('')
        $lines.Add('  ----------------------------------------------------------------')
        $lines.Add('  AI HANDOFF - copy the block below into any AI chat with web')
        $lines.Add('  access (ChatGPT, Claude, Gemini, etc.), then attach this .txt')
        $lines.Add('  file or paste its full contents where indicated.')
        $lines.Add('  ----------------------------------------------------------------')
        $lines.Add('')
        $lines.Add('>>> PROMPT START >>>')
        $lines.Add('')
        $lines.Add('You are reviewing a forensic scan report from a Windows PC. The')
        $lines.Add('report flagged some items at MEDIUM confidence but no HIGH-confidence')
        $lines.Add('cheat or input-device matches. I need your help determining whether')
        $lines.Add('the MEDIUM items are benign software or warrant further investigation.')
        $lines.Add('')
        $lines.Add('Your task:')
        $lines.Add('1. Read the attached/pasted log between the LOG START and LOG END markers below.')
        $lines.Add('2. For each MEDIUM finding, MEDIUM-scored process, and MEDIUM-scored service,')
        $lines.Add('   look up the binary name, service name, or product name using web search.')
        $lines.Add('3. Classify each as one of:')
        $lines.Add('     - LIKELY BENIGN (well-known legitimate software, publisher verifiable)')
        $lines.Add('     - WORTH REVIEWING (legitimate but capable of misuse, dual-use, or')
        $lines.Add('       installed in an unusual location for its category)')
        $lines.Add('     - SUSPICIOUS (associated with cheating, malware, hacking tools, or')
        $lines.Add('       has no clear legitimate use case)')
        $lines.Add('4. Cite the source URL for any classification you make.')
        $lines.Add('5. Produce a final summary plus a one-sentence recommendation.')
        $lines.Add('')
        $lines.Add('Constraints:')
        $lines.Add('  - Do NOT speculate beyond what the log content and web searches support.')
        $lines.Add('  - Do NOT make claims about the user. Only classify the software.')
        $lines.Add('  - Do NOT recommend deletion, modification, or further scans.')
        $lines.Add('  - The scan report is the only data source.')
        $lines.Add('')
        $lines.Add('Context for interpretation:')
        $lines.Add('  - This log was produced by Alibi v4.3.0, a read-only forensic')
        $lines.Add('    scan that matches Windows artifact data against a research-confirmed')
        $lines.Add('    keyword database of cheat software, HWID spoofers, DMA-cheat artifacts,')
        $lines.Add('    and commercial input devices (XIM, Cronus, ReaSnow, etc.).')
        $lines.Add('  - HIGH = unambiguous keyword match. MEDIUM = dual-use tool or binary')
        $lines.Add('    running from a user-writable location not on the allowlist.')
        $lines.Add('')
        $lines.Add('<<< LOG START >>>')
        $lines.Add('')
        $lines.Add('[Paste the full contents of the AlibiReport_*.txt file here,')
        $lines.Add(' OR upload the file as an attachment.]')
        $lines.Add('')
        $lines.Add('<<< LOG END >>>')
        $lines.Add('')
        $lines.Add('<<< PROMPT END <<<')
    }
    'CLEAN' {
        $lines.Add('  No RECENT HIGH or MEDIUM matches against the cheat / input-device /')
        $lines.Add('  dual-use keyword database (within the last ' + $RecencyThresholdDays + ' days).')
        $lines.Add('')
        $lines.Add('  Scope of this scan:')
        $lines.Add("    Cheat-trace findings checked : $($Findings.Count) total artifacts")
        $lines.Add("    Running processes scored     : $($processes.Count)")
        $lines.Add("    Services scored              : $($services.Count)")
        $lines.Add('')
        $lines.Add('  This is necessary but not sufficient evidence. See limitations')
        $lines.Add('  section at the bottom of this report for what this scan cannot')
        $lines.Add('  detect (DMA cheats at runtime, separately-paired input devices,')
        $lines.Add('  professionally cleaned machines, etc).')
    }
}

# v3.8: historical findings (>180d) - always surfaced in QUICK READ, but
# AFTER the verdict block so they don't get conflated with current evidence.
if ($historicalFindings.Count -gt 0) {
    $lines.Add('')
    $lines.Add('  ----------------------------------------------------------------')
    $lines.Add("  HISTORICAL findings (logged, did NOT affect verdict)")
    $lines.Add('  ----------------------------------------------------------------')
    $lines.Add("  $($historicalFindings.Count) finding(s) older than $RecencyThresholdDays days were demoted by the")
    $lines.Add('  recency-decay rule. These are visible below in the full report but')
    $lines.Add('  did not count toward the verdict above. Old artifacts from games or')
    $lines.Add('  tools the user has long since stopped using should not make a')
    $lines.Add('  currently-clean machine look dirty.')
    if ($historicalHigh.Count -gt 0) {
        $lines.Add('')
        $lines.Add("  Of these, $($historicalHigh.Count) were originally HIGH-severity cheat or input matches.")
        $lines.Add('  The most-recent timestamps and AgeDays are recorded per finding.')
    }
}

$lines.Add('')
$lines.Add('================================================================')
$lines.Add('')

# Standard report body
$bannerTitle = 'ALIBI v4.3.0 - CONSOLIDATED REPORT'
$lines.Add('================================================================')
$lines.Add("  $bannerTitle")
    $lines.Add('================================================================')
    $lines.Add('')
    $lines.Add("  Generated:  $(Get-Date)")
    $lines.Add("  Hostname:   $env:COMPUTERNAME")
    $lines.Add("  Username:   $env:USERNAME")
    $lines.Add("  OS:         $([System.Environment]::OSVersion.VersionString)")
    $lines.Add("  Admin mode: $(Test-IsAdmin)")
    $lines.Add("  Verdict:    $verdict")
    $lines.Add('')
    $netLine = if ($LOLDb) {
        '  Read-only scan. No system state was modified. One outbound network call (loldrivers.io, opt-in).'
    } else {
        '  Read-only scan. No system state was modified. No network calls.'
    }
    $lines.Add($netLine)
    $lines.Add('================================================================')
    $lines.Add('')

    # Section 1 - split into RECENT (verdict-contributing) and HISTORICAL
    # (logged-only) per v3.8 recency-decay rule.
    $recentFindings     = @($Findings | Where-Object { $_.Metadata.RecencyClass -ne 'historical' })
    $historicalSection1 = @($Findings | Where-Object { $_.Metadata.RecencyClass -eq 'historical' })

    $high = @($recentFindings | Where-Object Severity -eq 'HIGH')
    $medium = @($recentFindings | Where-Object Severity -eq 'MEDIUM')
    $warn = @($recentFindings | Where-Object Severity -eq 'WARN')
    $info = @($recentFindings | Where-Object Severity -eq 'INFO')

    $lines.Add('================================================================')
    $lines.Add('  SECTION 1 OF 3 - CHEAT TRACE SCAN')
    $lines.Add('================================================================')
    $lines.Add('')
    $lines.Add("  Summary (recent, within last $RecencyThresholdDays days - verdict-relevant):")
    $lines.Add("    HIGH    findings : $($high.Count)")
    $lines.Add("    MEDIUM  findings : $($medium.Count)")
    $lines.Add("    INFO    items    : $($info.Count)")
    $lines.Add("    WARN    (access) : $($warn.Count)")
    if ($historicalSection1.Count -gt 0) {
        $lines.Add('')
        $lines.Add("  Summary (historical, >$RecencyThresholdDays days old - logged but did NOT affect verdict):")
        $lines.Add("    Demoted historical findings : $($historicalSection1.Count)")
        $lines.Add("    (Originally HIGH-severity   : $(($historicalSection1 | Where-Object { $_.Metadata.OriginalSeverity -eq 'HIGH' }).Count))")
    }
    $lines.Add('')

    if ($Findings.Count -eq 0) {
        $lines.Add('  No findings.'); $lines.Add('')
    } else {
        # Render RECENT findings first.
        foreach ($f in ($recentFindings | Sort-Object @{E={
            switch ($_.Severity) { 'HIGH' {1} 'MEDIUM' {2} 'WARN' {3} 'INFO' {4} default {5} }
        }}, Category)) {
            $lines.Add("  [$($f.Severity)/$($f.Kind)] [$($f.Category)] $($f.Detail)")
            $lines.Add("        Source: $($f.Source)")
            foreach ($k in $f.Metadata.Keys) {
                $v = $f.Metadata[$k]
                if ($v -ne $null -and $v -ne '') { $lines.Add("        $k`: $v") }
            }
            $lines.Add('')
        }

        # Render HISTORICAL findings after a clear divider.
        if ($historicalSection1.Count -gt 0) {
            $lines.Add('  ------------------------------------------------------------')
            $lines.Add("  HISTORICAL FINDINGS (>$RecencyThresholdDays days old, did NOT affect verdict)")
            $lines.Add('  ------------------------------------------------------------')
            $lines.Add('')
            foreach ($f in ($historicalSection1 | Sort-Object @{E={ -([int]$_.Metadata.AgeDays) }}, Category)) {
                $orig = if ($f.Metadata.OriginalSeverity) { "was $($f.Metadata.OriginalSeverity)" } else { 'demoted' }
                $age = if ($f.Metadata.AgeDays) { "$($f.Metadata.AgeDays)d old" } else { 'age unknown' }
                $lines.Add("  [$($f.Severity)/$($f.Kind)] [$($f.Category)] [HISTORICAL $orig, $age] $($f.Detail)")
                $lines.Add("        Source: $($f.Source)")
                foreach ($k in $f.Metadata.Keys) {
                    $v = $f.Metadata[$k]
                    if ($v -ne $null -and $v -ne '') { $lines.Add("        $k`: $v") }
                }
                $lines.Add('')
            }
        }
    }

    # Section 2
    $procHigh = @($processes | Where-Object Score -eq 'HIGH')
    $procMed = @($processes | Where-Object Score -eq 'MEDIUM')
    $procLow = @($processes | Where-Object Score -eq 'LOW')
    $procClean = @($processes | Where-Object Score -eq 'CLEAN')

    $lines.Add('================================================================')
    $lines.Add('  SECTION 2 OF 3 - RUNNING PROCESSES (scored)')
    $lines.Add('================================================================')
    $lines.Add('')
    $lines.Add("  Total processes captured: $($processes.Count)")
    $lines.Add("    HIGH:   $($procHigh.Count)")
    $lines.Add("    MEDIUM: $($procMed.Count)")
    $lines.Add("    LOW:    $($procLow.Count)")
    $lines.Add("    CLEAN:  $($procClean.Count)")
    $lines.Add('')

    if ($procHigh.Count -gt 0 -or $procMed.Count -gt 0) {
        $lines.Add('  HIGH and MEDIUM processes (full detail):')
        $lines.Add('')
        foreach ($p in (@($procHigh) + @($procMed))) {
            $lines.Add("    [$($p.Score)/$($p.Kind)] $($p.Name) (PID $($p.ProcessId))")
            $lines.Add("        Path:    $($p.ExecutablePath)")
            $lines.Add("        Cmd:     $($p.CommandLine)")
            $lines.Add("        Reason:  $($p.Reason)")
            if ($p.Pattern) { $lines.Add("        Pattern: $($p.Pattern)") }
            $lines.Add('')
        }
    }

    if ($processes.Count -gt 0) {
        $lines.Add('  Full process table (sorted by suspicion score):')
        $lines.Add('')
        $procTable = $processes | Select-Object Score, ProcessId, ParentProcessId, Name, Started, ExecutablePath, CommandLine |
            Format-Table -AutoSize -Wrap | Out-String -Width 500
        $lines.Add($procTable)
    }

    # Section 3
    $svcHigh = @($services | Where-Object Score -eq 'HIGH')
    $svcMed = @($services | Where-Object Score -eq 'MEDIUM')
    $svcLow = @($services | Where-Object Score -eq 'LOW')
    $svcClean = @($services | Where-Object Score -eq 'CLEAN')

    $lines.Add('================================================================')
    $lines.Add('  SECTION 3 OF 3 - SERVICES (scored)')
    $lines.Add('================================================================')
    $lines.Add('')
    $lines.Add("  Total services captured: $($services.Count)")
    $lines.Add("    HIGH:   $($svcHigh.Count)")
    $lines.Add("    MEDIUM: $($svcMed.Count)")
    $lines.Add("    LOW:    $($svcLow.Count)")
    $lines.Add("    CLEAN:  $($svcClean.Count)")
    $lines.Add('')

    if ($svcHigh.Count -gt 0 -or $svcMed.Count -gt 0) {
        $lines.Add('  HIGH and MEDIUM services (full detail):')
        $lines.Add('')
        foreach ($s in (@($svcHigh) + @($svcMed))) {
            $lines.Add("    [$($s.Score)/$($s.Kind)] $($s.Name) ($($s.State))")
            $lines.Add("        Display: $($s.DisplayName)")
            $lines.Add("        Path:    $($s.PathName)")
            $lines.Add("        Mode:    $($s.StartMode)")
            $lines.Add("        Reason:  $($s.Reason)")
            if ($s.Pattern) { $lines.Add("        Pattern: $($s.Pattern)") }
            $lines.Add('')
        }
    }

    if ($services.Count -gt 0) {
        $lines.Add('  Full service table (sorted by suspicion score):')
        $lines.Add('')
        $svcTable = $services | Select-Object Score, Name, DisplayName, State, StartMode, PathName |
            Format-Table -AutoSize -Wrap | Out-String -Width 500
        $lines.Add($svcTable)
    }

    # Limitations
    $lines.Add('================================================================')
    $lines.Add('  COVERAGE LIMITATIONS')
    $lines.Add('================================================================')
    $lines.Add('')
    $lines.Add('  - DMA cheats cannot be detected at runtime by design (no PC-side')
    $lines.Add('    footprint). This scan flags DMA development artifacts only.')
    $lines.Add('  - Input devices configured on a separate machine leave no trace')
    $lines.Add('    on this PC.')
    $lines.Add('  - Session duration is recorded in SRUM and requires an ESE')
    $lines.Add('    database parser. Not extracted here.')
    $lines.Add('  - Keyword matching only. Sophisticated cleaners can wipe most')
    $lines.Add('    of these artifacts.')
    $lines.Add('  - A clean result is necessary but not sufficient.')
    $lines.Add('')
    $lines.Add("  Report generated: $(Get-Date)")
    $lines.Add('')

# Write
$lines | Set-Content -Path $OutputPath -Encoding UTF8

# Console summary
Write-Host ''
Write-Host '  ============================================================' -ForegroundColor Green
Write-Host '  Scan complete.' -ForegroundColor Green
Write-Host ''
$vcolor = switch ($verdict) {
    'CHEATS DETECTED'        { 'Red' }
    'INPUT DEVICES DETECTED' { 'Red' }
    'UNSURE'                 { 'Yellow' }
    'CLEAN'                  { 'Green' }
}
Write-Host "  VERDICT: $verdict" -ForegroundColor $vcolor
Write-Host ''
Write-Host "  Cheat HIGH:    $totalCheatHigh"
Write-Host "  Input HIGH:    $totalInputHigh"
Write-Host "  MEDIUM total:  $totalMedium"
Write-Host "  Procs scored:  $($processes.Count)"
Write-Host "  Svcs scored:   $($services.Count)"
Write-Host ''
Write-Host "  Saved to: $OutputPath" -ForegroundColor Cyan
Write-Host '  ============================================================' -ForegroundColor Green
Write-Host ''

# ============================================================================
# Auto-generate visual HTML companion (no user prompt)
# ============================================================================
$visualScript = Join-Path $PSScriptRoot 'generate-visual-companion.ps1'
$htmlPath = $null
if (Test-Path $visualScript) {
    Write-Host '  Generating visual HTML companion...' -ForegroundColor Cyan
    try {
        & $visualScript -InputPath $OutputPath
        $base = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
        $dir  = [System.IO.Path]::GetDirectoryName($OutputPath)
        $htmlPath = Join-Path $dir "${base}_visual.html"
        if (Test-Path $htmlPath) {
            Write-Host "  HTML visual saved: $htmlPath" -ForegroundColor Cyan
        } else {
            $htmlPath = $null
        }
    } catch {
        Write-Host "  Visual generation failed: $_" -ForegroundColor Red
        $htmlPath = $null
    }
}

# Auto-open the visual report in the user's default browser. The unified
# Run scan.bat passes -SkipBrowserOpen so we don't spam two tabs (it opens
# just the PC-mode report at the very end of the run instead).
#
# Note: we go through explorer.exe rather than Start-Process directly so the
# browser launches at medium integrity even when this script is elevated.
# A direct Start-Process from an admin PowerShell can fail to attach to an
# existing non-admin browser process and either pop a separate window or
# silently no-op on some configurations.
if ($htmlPath -and -not $SkipBrowserOpen) {
    try {
        Write-Host "  Opening report in your default browser..." -ForegroundColor Cyan
        Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$htmlPath`"" -ErrorAction Stop
    } catch {
        Write-Host "  Could not auto-open the browser. Open this file manually: $htmlPath" -ForegroundColor Yellow
    }
}
Write-Host ''

# Write a tiny summary file the launcher .bat can read to show a
# consolidated end-of-run summary across both scans.
try {
    $sum = "$verdict|$OutputPath|$totalCheatHigh|$totalInputHigh|$totalMedium"
    [System.IO.File]::WriteAllText("$env:TEMP\alibi-pc.summary", $sum, (New-Object System.Text.UTF8Encoding($false)))
} catch {}
