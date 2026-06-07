<#
.SYNOPSIS
    Alibi (console-rig mode) v1.1 - scans a PC sitting next to a console for
    cheat-MITM software stacks.

.DESCRIPTION
    Use case: a console player wants to demonstrate that the PC connected
    to their console rig (capture-card host, second monitor, streaming PC,
    or shared desktop) is NOT being used to help them cheat at console
    games. They run this script, send the report to a reviewer.

    The console itself is a black box - this script cannot scan it. It can
    only scan the Windows PC that is part of the gaming setup. If there is
    no PC in the loop, this script is not the right tool - use the visual
    setup checklist (console-setup-checklist.html) instead.

    This is the CONSOLE-MODE driver. The actual scanning logic lives in
    forensic-common.ps1, which is dot-sourced below. This file adds the
    three console-specific keyword arrays (vision aimbots, HID emulators,
    capture-card software) and supplies the console-mode verdict tiers:
      - MITM Cheat Stack Detected : vision aimbot or input-adapter
                                    configurator present at HIGH
      - Capture Stack Present     : capture-card or HID-emulator software
                                    found alone (likely a legit streamer)
      - Unsure                    : other MEDIUM matches
      - Clean                     : no HIGH and no MEDIUM matches

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
    $OutputPath = Join-Path $desktop "AlibiRigReport_${stamp}.txt"
}
$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path $parent)) {
    try { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    catch { $OutputPath = Join-Path $env:USERPROFILE ([System.IO.Path]::GetFileName($OutputPath)) }
}

# ============================================================================
# CONSOLE-SPECIFIC keyword extras (not in forensic-common.ps1)
# ============================================================================

# Vision-aimbot software: PC apps that watch a capture-card feed and inject
# input. The defining tool of the console-MITM cheat stack. HIGH cheat.
$VisionAimbots = @(
    'aimmmo','aim mmo','aim_mmo',
    'aimsync','aim sync','aim_sync',
    'aimflux','aim flux','aim_flux',
    'norecoilz','no recoil z','no_recoil_z',
    'divisionx','division x','division_x',
    'predator aim','predatoraim','predator-aim',
    'looplus','loop plus','loop+',
    'apox aim','apoxaim','apox-aim',
    'aimkey','aim key',
    'aimx','aim-x','aim_x',
    'kernaim','kernel aim','kernel-aim',
    'colorbot','color bot','color-bot',
    'pixelbot','pixel bot','pixel-bot',
    'ml aim','ml-aim','machine learning aim',
    'ai aimbot','ai-aimbot','ai_aimbot',
    'vision aimbot','vision-aimbot',
    'screen aimbot','screen-aimbot'
)

# HID emulation drivers: make a PC pretend to be a controller. Dual-use
# (Steam + DS4Windows use them legitimately) - MEDIUM, but also a component
# of the console-MITM cheat stack.
$HidEmulators = @(
    'vigembus','vigem bus','vigem-bus','vigemclient',
    'vjoy','v-joy',
    'scptoolkit','scp toolkit','scp-toolkit',
    'ds4windows','ds4 windows'
)

# Capture-card software: dual-use (streamers vs. MITM rigs). MEDIUM alone.
# The verdict logic uses it to choose between CAPTURE STACK PRESENT and
# UNSURE - capture-card-only is a separate, less-suspicious tier.
$CaptureCardSoftware = @(
    'elgato game capture','elgato 4k capture','elgato_gamecapture','gamecapture',
    'avermedia','recentral','rec central',
    'obs studio','obs-studio','obs64','obs32',
    'streamlabs','streamlabs obs',
    'xsplit','x-split',
    'magewell'
)

# ============================================================================
# Initialize shared state and load engine
# ============================================================================
$Findings = [System.Collections.Generic.List[pscustomobject]]::new()

# Dot-source the shared engine.
. "$PSScriptRoot\forensic-common.ps1"

# Console-mode composite keyword arrays. Extends PC base with the three
# console-specific lists above. v3.8 pulls in the new game-specific brand
# arrays + PC-side AI vision aimbots (relevant on a console-rig PC too).
$Keywords_High_Cheats = $CheatBrands_COD + $Spoofer_Brands + $CheatFeature_Names + $DMA_Indicators + $VisionAimbots `
    + $CheatBrands_CS2 + $CheatBrands_Apex + $CheatBrands_Tarkov + $CheatBrands_Rust `
    + $CheatBrands_R6 + $CheatBrands_MarvelRivals + $VisionAimbot_AI_PC
$Keywords_High_Input  = $InputDevices
$Keywords_Medium      = $DMA_DualUse + $DualUse_Tools + $HidEmulators + $CaptureCardSoftware + $CheatBrands_LowConfidence
$Keywords_ScriptHigh  = $ScriptContent_HighRisk
$Keywords_MouseMacro  = $ScriptContent_MouseMacro

# ============================================================================
# Banner
# ============================================================================
Clear-Host
Write-Host ''
Write-Host '  Alibi v4.0 (console-rig mode)' -ForegroundColor Cyan
Write-Host '  =======================' -ForegroundColor Cyan
Write-Host ''
Write-Host "  Host:   $env:COMPUTERNAME"
Write-Host "  User:   $env:USERNAME"
if (Test-IsAdmin) { Write-Host '  Admin:  Yes' -ForegroundColor Green }
else { Write-Host '  Admin:  No (run as admin for full coverage)' -ForegroundColor Yellow }
Write-Host ''
Write-Host '  Scanning this PC for console-cheat MITM software.' -ForegroundColor DarkGray
Write-Host '  This will take 30-90 seconds.' -ForegroundColor DarkGray
Write-Host ''

# ============================================================================
# Optional LOLDrivers BYOVD cross-reference (opt-in network call)
# ============================================================================
# Reused by Scan-Drivers from parent scope. Cached for 1h so running PC scan
# + console-rig scan back-to-back only prompts once.
$LOLDb = Resolve-LOLDriversDB -SkipLOLDrivers:$SkipLOLDrivers -FetchLOLDrivers:$FetchLOLDrivers

# ============================================================================
# Run the scan
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
# Console verdict logic
# Filters: Metadata.RecencyClass -ne 'historical' so demoted-by-age findings
# do not contribute to verdict counts. They remain visible in the report.
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

# Are MEDIUM hits all from capture-card or HID-emulator lists? If yes,
# that's a legitimate-streamer signal, not a generic "unsure".
function Test-IsCaptureOrHidPattern {
    param([string]$Pattern)
    if (-not $Pattern) { return $false }
    $p = $Pattern.ToLower()
    foreach ($k in ($CaptureCardSoftware + $HidEmulators)) {
        if ($p -match [regex]::Escape($k.ToLower())) { return $true }
    }
    return $false
}

$captureOrHidMediumCount = 0
$otherMediumCount = 0
foreach ($f in $mediumAny) {
    if (Test-IsCaptureOrHidPattern $f.Metadata.Pattern) { $captureOrHidMediumCount++ }
    else { $otherMediumCount++ }
}
foreach ($p in $procMedium) {
    if (Test-IsCaptureOrHidPattern $p.Pattern) { $captureOrHidMediumCount++ }
    else { $otherMediumCount++ }
}
foreach ($s in $svcMedium) {
    if (Test-IsCaptureOrHidPattern $s.Pattern) { $captureOrHidMediumCount++ }
    else { $otherMediumCount++ }
}

$verdict = if ($totalCheatHigh -gt 0 -or $totalInputHigh -gt 0) { 'MITM CHEAT STACK DETECTED' }
           elseif ($captureOrHidMediumCount -gt 0 -and $otherMediumCount -eq 0) { 'CAPTURE STACK PRESENT' }
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
    'MITM CHEAT STACK DETECTED' {
        $lines.Add('  This scan found HIGH-confidence indicators that this PC is part')
        $lines.Add('  of a console-MITM cheat stack. One or more of these is present:')
        $lines.Add('    - Vision-aimbot software (watches capture-card feed, auto-aims)')
        $lines.Add('    - Input-adapter configurator (XIM, Cronus, ReaSnow, KMBox,')
        $lines.Add('      Titan, reWASD - the PC-side software for the hardware')
        $lines.Add('      adapters that translate mouse+keyboard into console input)')
        $lines.Add('    - Traditional PC cheat brands or DMA-cheat artifacts')
        $lines.Add('')
        $lines.Add('  On a PC connected to a console rig, none of these has a')
        $lines.Add('  legitimate purpose. The report below names exactly what was')
        $lines.Add('  found and where.')
        $lines.Add('')
        if ($namedCheats.Count -gt 0) {
            $lines.Add('  Named items (aimbot / cheat-confidence):')
            foreach ($n in $namedCheats) { $lines.Add("    - $n") }
            $lines.Add('')
        }
        if ($namedInput.Count -gt 0) {
            $lines.Add('  Named items (input-adapter configurator software):')
            foreach ($n in $namedInput) { $lines.Add("    - $n") }
        }
    }
    'CAPTURE STACK PRESENT' {
        $lines.Add('  No vision-aimbot software, input-adapter configurator, or')
        $lines.Add('  traditional PC cheats were detected. However, this scan found')
        $lines.Add('  capture-card software and/or HID-emulation drivers.')
        $lines.Add('')
        $lines.Add('  These have legitimate uses (streaming, recording, controller')
        $lines.Add('  remapping via Steam or DS4Windows). They are disclosed here')
        $lines.Add('  because they are also components of console-MITM cheat stacks.')
        $lines.Add('  Their presence alone is not evidence of cheating.')
        $lines.Add('')
        $lines.Add('  Reviewer note: if you are auditing for cheat behavior, the')
        $lines.Add('  absence of any aimbot or adapter software alongside the')
        $lines.Add('  capture-card stack is the relevant finding.')
        $lines.Add('')
        $lines.Add('  Named items:')
        foreach ($f in $mediumAny) {
            if ($f.Metadata.Pattern) {
                $lines.Add("    - [$($f.Category)] $($f.Metadata.Pattern) - $($f.Detail)")
            }
        }
        foreach ($p in $procMedium) {
            $lines.Add("    - [Process] $($p.Pattern) - $($p.Name) (PID $($p.ProcessId))")
        }
        foreach ($s in $svcMedium) {
            $lines.Add("    - [Service] $($s.Pattern) - $($s.Name) ($($s.State))")
        }
    }
    'UNSURE' {
        $lines.Add('  No HIGH-confidence cheat or input-device matches were detected.')
        $lines.Add("  However, $totalMedium MEDIUM finding(s) require human review.")
        $lines.Add('  These are typically dual-use tools or binaries running from')
        $lines.Add('  user-writable locations that the allowlist does not recognize.')
        $lines.Add('')
        $lines.Add('  AI HANDOFF: paste the full contents of this .txt file into')
        $lines.Add('  any AI chat (ChatGPT, Claude, Gemini) and ask it to classify')
        $lines.Add('  each MEDIUM finding as benign / worth-reviewing / suspicious')
        $lines.Add('  with cited sources.')
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
        $lines.Add('  section at the bottom of this report.')
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
    $lines.Add('  did not count toward the verdict above.')
    if ($historicalHigh.Count -gt 0) {
        $lines.Add('')
        $lines.Add("  Of these, $($historicalHigh.Count) were originally HIGH-severity cheat or input matches.")
    }
}

$lines.Add('')
$lines.Add('================================================================')
$lines.Add('')

# Standard report body
$lines.Add('================================================================')
$lines.Add('  ALIBI v4.0 (CONSOLE-RIG MODE) - CONSOLIDATED REPORT')
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
$lines.Add('  - The CONSOLE itself cannot be scanned. This script can only see')
$lines.Add('    the Windows PC connected to the rig. A pure console + TV setup')
$lines.Add('    with no PC in the loop cannot be audited this way - use the')
$lines.Add('    visual setup checklist (console-setup-checklist.html) instead.')
$lines.Add('  - DMA cheats cannot be detected at runtime by design (no PC-side')
$lines.Add('    footprint). This scan flags DMA development artifacts only.')
$lines.Add('  - Input devices configured on a separate machine and used purely')
$lines.Add('    as pass-through leave no trace on this PC.')
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
    'MITM CHEAT STACK DETECTED' { 'Red' }
    'CAPTURE STACK PRESENT'     { 'Yellow' }
    'UNSURE'                    { 'Yellow' }
    'CLEAN'                     { 'Green' }
}
Write-Host "  VERDICT: $verdict" -ForegroundColor $vcolor
Write-Host ''
Write-Host "  Cheat HIGH:    $totalCheatHigh"
Write-Host "  Input HIGH:    $totalInputHigh"
Write-Host "  MEDIUM total:  $totalMedium  (capture/HID: $captureOrHidMediumCount, other: $otherMediumCount)"
Write-Host "  Procs scored:  $($processes.Count)"
Write-Host "  Svcs scored:   $($services.Count)"
Write-Host ''
Write-Host "  Saved to: $OutputPath" -ForegroundColor Cyan
Write-Host '  ============================================================' -ForegroundColor Green
Write-Host ''

# ============================================================================
# Auto-generate visual HTML companion (no user prompt)
# ============================================================================
$visualScript = Join-Path $PSScriptRoot 'generate-visual-companion-console.ps1'
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

if ($htmlPath -and -not $SkipBrowserOpen) {
    # explorer.exe relay so the browser launches at medium IL even when this
    # script is elevated (Start-Process direct can fail to attach to an
    # existing non-admin browser process).
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
    Set-Content -Path "$env:TEMP\alibi-console.summary" -Value $sum -Encoding UTF8 -ErrorAction Stop
} catch {}
