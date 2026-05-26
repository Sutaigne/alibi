<#
.SYNOPSIS
    Alibi - Visual Companion (threat triage edition).

.DESCRIPTION
    Renders a confidence-scored HTML report from an AlibiReport_*.txt.
    Every visualization relates back to one question:

        "How confident am I this machine has no cheat or cheat-related
         software running or installed?"

    Scoring (applied to every running process and registered service):

        HIGH    - Binary path, command line, or service name matches a
                  research-confirmed cheat or input-device keyword.
        MEDIUM  - Image runs from a user-writable / non-standard location
                  (AppData, user profile, ProgramData, Temp) and is not
                  in the known-good vendor allowlist.
        LOW     - Image runs from a non-System32 but typical location
                  (Program Files, Windows other) with no keyword match.
        CLEAN   - Image runs from a standard system location
                  (System32, SysWOW64, signed Windows paths).

.NOTES
    Author: Bread
    Contributor: Drownmw
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$InputPath,
    [string]$OutputPath
)

if (-not (Test-Path $InputPath)) { Write-Host "ERROR: Input not found: $InputPath" -ForegroundColor Red; exit 1 }
if (-not $OutputPath) {
    $base = [System.IO.Path]::GetFileNameWithoutExtension($InputPath)
    $dir  = [System.IO.Path]::GetDirectoryName($InputPath); if (-not $dir) { $dir = $PWD }
    $OutputPath = Join-Path $dir "${base}_visual.html"
}

# ============================================================================
# KEYWORD DATABASE (mirrors forensic-scan.ps1 exactly)
# ============================================================================

$CheatBrands_COD = @(
    'engineowning','engine owning','phantomoverlay','phantom overlay','lavicheats','lavi cheats',
    'skycheats','sky cheats','iwantcheats','i want cheats','x22cheats','x22 cheats','golden gun',
    'tateware','gcaimx','hdcheat','securecheats','overlord spoofer','zhexcheats','zhex cheats'
)
$Spoofer_Brands = @(
    'sync spoofer','syncspoofer','tracex','slothytech','pokespoof','overlord.exe','overlord_',
    'hidhide','hid hide','hidhideclient','hidhidecli','hidhidedrv'
)
$CheatFeature_Names = @(
    'aimbot','wallhack','wall_hack','wall-hack','triggerbot','trigger_bot','norecoil','no-recoil','no_recoil',
    'hwidspoofer','hwid_spoof','hwid-spoof','hwidchanger','macspoof','mac_spoof'
)
$InputDevices = @(
    'xim manager','ximmanager','xim apex','xim matrix','xim4','cronus','cronuszen','zen studio',
    'gpcscript','cronusmax','reasnow','reasnow s1','kmbox','km-box','km_box','titan two','titan.two',
    'gtuner','consoletuner',
    'rewasd','rewasdengine','rewasd engine','rewasd.exe'
)
$DMA_Indicators = @(
    'pcileech','pcileech-fpga','pcileech_fpga','pcileech_squirrel','pcileech_enigma','pcileech_zdma',
    'pcileech_screamer','pcileech_leetdma','pcileech_captaindma','pcileech_hackdma','pcileech_lurker',
    'pcileech_mvp','pcileech_macku','_top.bin'
)
$DMA_DualUse = @('vivado','xilinx vivado','arbor','dma-cfw','dma_cfw')
$DualUse_Tools = @(
    'bleachbit','privazer','rbcleaner','cheatengine','cheat engine','processhacker','process hacker',
    'ollydbg','x64dbg','x32dbg','reclass','reclass.net','ida.exe','ida64.exe','ida pro'
)

# Lua-script cheat keywords, named DLL injectors, and DDoS tools.
# Mirrors the v3.6 additions in forensic-common.ps1.
$LuaCheat_Keywords = @(
    'aimbot','aim_bot','aim-bot','triggerbot','trigger_bot','wallhack','wall_hack',
    'esp','norecoil','no_recoil','no-recoil','bhop','bunny_hop','bunnyhop',
    'spinbot','spin_bot','radar_hack','radarhack','speedhack','speed_hack',
    'skinchanger','skin_changer','injector','bypass','anticheat','anti_cheat',
    'cheat','hack','exploit','undetected','ud_','loader','ldr_',
    'engineowning','phantomoverlay','lavicheats','skycheats'
)
$DLLInjector_Names = @(
    'injector','inject','xenos','xenos64','extreme_injector','extremeinjector',
    'gdinjector','manual_map','manualmap','loadlibrary_injector',
    'process_hollowing','processhollowing','dllinjector','dll_inject',
    'syringe','chimera','shtreload','winject','winject64',
    'remoteinjection','remoteinjector','shellcode','shellcode_inject'
)
$NetworkAttack_High = @(
    'loic','low orbit ion cannon','hoic','high orbit ion cannon',
    'slowloris','pyloris','goldeneye','goldeneyetool','torshammer','tor hammer',
    'hulk.py','hulk_ddos','rudy','r-u-dead-yet','ufonet','xerxes','andosid',
    'byob_ddos','ddos_attack','ddos_tool','ddostool','booter_client','stresser_client'
)
$NetworkAttack_Medium = @(
    'hping','hping3','masscan','zmap','ostinato','iperf3','tshark'
)

# v3.8 additions - game-specific cheat brands + AI vision PC aimbots.
$CheatBrands_CS2 = @(
    'neverlose','memesense','fatality.win','primordial.cc','skeet.cc',
    'gamesense.pub','onetap','aimware','axion-cs2'
)
$CheatBrands_Apex = @('kernaim','cosmocheats apex','apex_hacksuite')
$CheatBrands_Tarkov = @('phantom eft','cheatvault eft','ownage software','ownage_eft')
$CheatBrands_Rust = @('cobracheat','cobra rust','atomic rust','cheater.ninja','cobrasn')
$CheatBrands_R6 = @('hyperforcecheats','cheatvault r6')
$CheatBrands_MarvelRivals = @('marvel maxim','elocarry','elocarry rivals')
$CheatBrands_LowConfidence = @(
    'midnight cs2','predator cs2','anyx.gg','eucheats','siegex',
    'rainbowsixcheats','wh-satano','proofcore','chamscheats',
    'deprimereshop','sternclient.biz','hackvshack','madchad.net',
    'gulfcheats','moddingassociation'
)
$VisionAimbot_AI_PC = @(
    'aimmy','sunone_aimbot','rootkit_aimbot','aimahead','zelesisneo',
    'reflex_aimbot','aimi_yolov3','yolov8_aimbot','aim_bot_yolo','unibot',
    'ardoras','embedded_aim_assist','csmacro'
)

$Keywords_High = $CheatBrands_COD + $Spoofer_Brands + $CheatFeature_Names + $InputDevices + $DMA_Indicators `
    + $LuaCheat_Keywords + $DLLInjector_Names + $NetworkAttack_High `
    + $CheatBrands_CS2 + $CheatBrands_Apex + $CheatBrands_Tarkov + $CheatBrands_Rust `
    + $CheatBrands_R6 + $CheatBrands_MarvelRivals + $VisionAimbot_AI_PC
$Keywords_Medium = $DMA_DualUse + $DualUse_Tools + $NetworkAttack_Medium + $CheatBrands_LowConfidence

# Known-good vendor name fragments for user-writable locations
$KnownGood = @(
    'microsoft','windows','onedrive','teams','office','edgewebview','msedge',
    'google','chrome','update','slack','discord','zoom','signal','spotify',
    'dropbox','adobe','nvidia','amd','intel','realtek','razer','logitech',
    'corsair','steelseries','dell','hp','lenovo','asus','asustek','msi',
    'steam','epic','battle.net','riot','origin','ubisoft','rockstar',
    'github','vscode','code.exe','jetbrains','notion','postman','docker',
    'python','node','npm','git','antigravity'
)

# ============================================================================
# PARSER
# ============================================================================

$raw = Get-Content $InputPath -Raw -Encoding UTF8
$raw = $raw -replace "^\xEF\xBB\xBF", ''
$lines = $raw -split "`r?`n"

$generated = $hostname = $username = $admin = ''
foreach ($l in $lines[0..20]) {
    if ($l -match '^\s*Generated:\s*(.+)$')  { $generated = $matches[1].Trim() }
    if ($l -match '^\s*Hostname:\s*(.+)$')   { $hostname = $matches[1].Trim() }
    if ($l -match '^\s*Username:\s*(.+)$')   { $username = $matches[1].Trim() }
    if ($l -match '^\s*Admin mode:\s*(.+)$') { $admin = $matches[1].Trim() }
}

$idx_sec1 = $idx_sec2 = $idx_sec3 = $idx_limit = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match 'SECTION 1 OF 3')     { $idx_sec1 = $i }
    elseif ($lines[$i] -match 'SECTION 2 OF 3') { $idx_sec2 = $i }
    elseif ($lines[$i] -match 'SECTION 3 OF 3') { $idx_sec3 = $i }
    elseif ($lines[$i] -match 'COVERAGE LIMITATIONS') { $idx_limit = $i; break }
}

# Parse cheat trace findings
$findings = [System.Collections.Generic.List[hashtable]]::new()
$current = $null
$sec1End = if ($idx_sec2 -gt 0) { $idx_sec2 } else { $lines.Count }
for ($i = $idx_sec1; $i -lt $sec1End; $i++) {
    $line = $lines[$i]
    # v3.2 format: [SEVERITY/kind] or legacy [SEVERITY]
    if ($line -match '^\s*\[(HIGH|MEDIUM|WARN|INFO)(?:/([a-z-]+))?\]\s+\[([^\]]+)\]\s+(.*)$') {
        if ($current) { [void]$findings.Add($current) }
        $current = @{
            Severity = $matches[1]
            Kind = if ($matches[2]) { $matches[2] } else { '' }
            Category = $matches[3]
            Detail = $matches[4].Trim()
            Source = ''; Metadata = @{}
        }
        continue
    }
    if (-not $current) { continue }
    if ($line -match '^\s*Source:\s*(.+)$') { $current.Source = $matches[1].Trim(); continue }
    if ($line -match '^\s{6,}([A-Za-z][A-Za-z0-9_]*):\s*(.*)$') { $current.Metadata[$matches[1]] = $matches[2].Trim() }
}
if ($current) { [void]$findings.Add($current) }

# Generic Format-Table parser
function Parse-FormatTable {
    param([string[]]$Block)
    $sepIdx = -1
    for ($i = 0; $i -lt $Block.Count; $i++) {
        if ($Block[$i] -match '^[\s-]+$' -and $Block[$i] -match '---') { $sepIdx = $i; break }
    }
    if ($sepIdx -lt 1) { return @() }
    $header = $Block[$sepIdx - 1]; $sep = $Block[$sepIdx]
    $dashStarts = [System.Collections.Generic.List[int]]::new()
    $inDash = $false
    for ($i = 0; $i -lt $sep.Length; $i++) {
        $c = $sep[$i]
        if ($c -eq '-' -and -not $inDash) { [void]$dashStarts.Add($i); $inDash = $true }
        elseif ($c -ne '-' -and $inDash) { $inDash = $false }
    }
    $cols = [System.Collections.Generic.List[hashtable]]::new()
    for ($i = 0; $i -lt $dashStarts.Count; $i++) {
        $s = $dashStarts[$i]
        $e = if ($i + 1 -lt $dashStarts.Count) { $dashStarts[$i + 1] } else { 99999 }
        $n = if ($s -lt $header.Length) {
            $eh = [math]::Min($e, $header.Length); $header.Substring($s, $eh - $s).Trim()
        } else { '' }
        [void]$cols.Add(@{ Start = $s; End = $e; Name = $n })
    }
    if ($cols.Count -eq 0) { return @() }
    $rows = [System.Collections.Generic.List[hashtable]]::new()
    for ($i = $sepIdx + 1; $i -lt $Block.Count; $i++) {
        $line = $Block[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -match '^={5,}') { break }
        if ($cols[0].Start -ge $line.Length) { continue }
        $fe = [math]::Min($cols[0].End, $line.Length)
        if ([string]::IsNullOrWhiteSpace($line.Substring($cols[0].Start, $fe - $cols[0].Start))) { continue }
        $row = @{}
        foreach ($c in $cols) {
            $row[$c.Name] = if ($c.Start -lt $line.Length) {
                $ce = [math]::Min($c.End, $line.Length); $line.Substring($c.Start, $ce - $c.Start).Trim()
            } else { '' }
        }
        [void]$rows.Add($row)
    }
    return $rows
}

$processes = if ($idx_sec2 -gt 0 -and $idx_sec3 -gt $idx_sec2) {
    Parse-FormatTable ($lines[$idx_sec2..($idx_sec3 - 1)])
} else { @() }

$services = if ($idx_sec3 -gt 0) {
    $endIdx = if ($idx_limit -gt $idx_sec3) { $idx_limit } else { $lines.Count }
    Parse-FormatTable ($lines[$idx_sec3..($endIdx - 1)])
} else { @() }

Write-Host "Parsed: $($findings.Count) findings, $($processes.Count) processes, $($services.Count) services" -ForegroundColor Cyan

# ============================================================================
# SCORING
# ============================================================================

function Match-Keyword {
    param([string]$Text, [string[]]$Patterns)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $lc = $Text.ToLower()
    foreach ($p in $Patterns) {
        if ($lc -match [regex]::Escape($p.ToLower())) { return $p }
    }
    return $null
}

function Match-Allowlist {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $lc = $Text.ToLower()
    foreach ($g in $KnownGood) {
        if ($lc -match [regex]::Escape($g)) { return $true }
    }
    return $false
}

function Classify-PathRisk {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'unknown' }
    $p = $Path.ToLower().Trim('"').Trim()
    if ($p -match '^([^"]+\.exe)') { $p = $matches[1] }
    if ($p -match '^c:\\windows\\system32') { return 'standard' }
    if ($p -match '^c:\\windows\\syswow64') { return 'standard' }
    if ($p -match '^c:\\windows\\systemapps') { return 'standard' }
    if ($p -match '^c:\\windows\\microsoft\.net') { return 'standard' }
    if ($p -match '^c:\\windows\\servicing') { return 'standard' }
    if ($p -match '^c:\\windows\\') { return 'standard' }
    if ($p -match '^c:\\program files \(x86\)\\') { return 'typical' }
    if ($p -match '^c:\\program files\\') { return 'typical' }
    if ($p -match '^c:\\programdata\\') { return 'user-writable' }
    if ($p -match '\\appdata\\local\\') { return 'user-writable' }
    if ($p -match '\\appdata\\roaming\\') { return 'user-writable' }
    if ($p -match '\\appdata\\locallow\\') { return 'user-writable' }
    if ($p -match '\\temp\\') { return 'user-writable' }
    if ($p -match '^c:\\users\\') { return 'user-writable' }
    return 'unknown'
}

function Score-Item {
    param([string]$Name, [string]$Path, [string]$Extra = '')
    $combined = "$Name $Path $Extra"
    $hit = Match-Keyword $combined $Keywords_High
    if ($hit) { return @{ Score = 'HIGH'; Reason = "matches '$hit' keyword"; Pattern = $hit } }
    $hit = Match-Keyword $combined $Keywords_Medium
    if ($hit) { return @{ Score = 'MEDIUM'; Reason = "matches '$hit' (dual-use tool)"; Pattern = $hit } }
    $bucket = Classify-PathRisk $Path
    if ($bucket -eq 'user-writable') {
        if (Match-Allowlist "$Path $Name") {
            return @{ Score = 'CLEAN'; Reason = 'user-writable location but known-good vendor'; Pattern = '' }
        }
        return @{ Score = 'MEDIUM'; Reason = 'runs from user-writable location, no allowlist match'; Pattern = '' }
    }
    if ($bucket -eq 'unknown') { return @{ Score = 'LOW'; Reason = 'image path not recorded or non-standard'; Pattern = '' } }
    if ($bucket -eq 'typical') { return @{ Score = 'LOW'; Reason = 'runs from Program Files or similar'; Pattern = '' } }
    return @{ Score = 'CLEAN'; Reason = 'standard system location, no keyword match'; Pattern = '' }
}

$procScored = [System.Collections.Generic.List[hashtable]]::new()
foreach ($p in $processes) {
    $s = Score-Item -Name $p.Name -Path $p.ExecutablePath -Extra $p.CommandLine
    [void]$procScored.Add(@{
        ProcessId = $p.ProcessId; Name = $p.Name; Started = $p.Started
        Path = $p.ExecutablePath; CommandLine = $p.CommandLine
        Score = $s.Score; Reason = $s.Reason; Pattern = $s.Pattern
    })
}

$svcScored = [System.Collections.Generic.List[hashtable]]::new()
foreach ($s in $services) {
    $sc = Score-Item -Name $s.Name -Path $s.PathName -Extra $s.DisplayName
    [void]$svcScored.Add(@{
        Name = $s.Name; DisplayName = $s.DisplayName; State = $s.State
        StartMode = $s.StartMode; Path = $s.PathName
        Score = $sc.Score; Reason = $sc.Reason; Pattern = $sc.Pattern
    })
}

$procByScore = @{ HIGH=0; MEDIUM=0; LOW=0; CLEAN=0 }
foreach ($p in $procScored) { $procByScore[$p.Score]++ }
$svcByScore = @{ HIGH=0; MEDIUM=0; LOW=0; CLEAN=0 }
foreach ($s in $svcScored) { $svcByScore[$s.Score]++ }

# v3.8 - split findings into recent (verdict-relevant) and historical
# (logged-only, >180d). The .txt parser captures Metadata.RecencyClass and
# Metadata.OriginalSeverity per finding; use those to bucket.
$recentFindings     = @($findings | Where-Object { $_.Metadata.RecencyClass -ne 'historical' })
$historicalFindings = @($findings | Where-Object { $_.Metadata.RecencyClass -eq 'historical' })

$findingsByScore = @{ HIGH=0; MEDIUM=0; WARN=0; INFO=0 }
foreach ($f in $recentFindings) { $findingsByScore[$f.Severity]++ }

$historicalByOrig = @{ HIGH=0; MEDIUM=0 }
foreach ($f in $historicalFindings) {
    $orig = if ($f.Metadata.OriginalSeverity) { $f.Metadata.OriginalSeverity } else { $f.Severity }
    if ($historicalByOrig.ContainsKey($orig)) { $historicalByOrig[$orig]++ }
}

$totalHigh = $findingsByScore.HIGH + $procByScore.HIGH + $svcByScore.HIGH
$totalMed  = $findingsByScore.MEDIUM + $procByScore.MEDIUM + $svcByScore.MEDIUM
$verdict = if ($totalHigh -gt 0) { 'HIGH-CONFIDENCE INDICATORS PRESENT' }
           elseif ($totalMed -gt 0) { 'REVIEW NEEDED' }
           else { 'NO CHEAT INDICATORS DETECTED' }
$verdictClass = if ($totalHigh -gt 0) { 'verdict-high' }
                elseif ($totalMed -gt 0) { 'verdict-med' }
                else { 'verdict-clean' }

# ============================================================================
# RENDER
# ============================================================================

$COLOR_HIGH = '#6B1E1E'
$COLOR_MED  = '#8A6914'
$COLOR_LOW  = '#2E3A4A'
$COLOR_CLEAN = '#1F3F2E'

function Score-Color {
    param([string]$Score)
    switch ($Score) {
        'HIGH'   { return $COLOR_HIGH }
        'MEDIUM' { return $COLOR_MED }
        'LOW'    { return $COLOR_LOW }
        'CLEAN'  { return $COLOR_CLEAN }
        default  { return '#8A857C' }
    }
}

function Escape-Xml {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

function Render-StackedBar {
    param([hashtable]$Counts, [int]$Total)
    if ($Total -eq 0) { return '<div class="empty">No data.</div>' }
    $svg = "<svg viewBox='0 0 880 60' xmlns='http://www.w3.org/2000/svg'>"
    $x = 0; $width = 880
    foreach ($k in @('HIGH','MEDIUM','LOW','CLEAN')) {
        $c = $Counts[$k]
        if ($c -eq 0) { continue }
        $w = [math]::Round(($c / $Total) * $width, 1)
        $color = Score-Color $k
        $svg += "<rect x='$x' y='10' width='$w' height='32' fill='$color' opacity='0.9'/>"
        if ($w -gt 50) {
            $tx = $x + $w / 2
            $svg += "<text x='$tx' y='30' font-family='IBM Plex Mono' font-size='11' font-weight='600' fill='#FBF9F4' text-anchor='middle'>$k</text>"
            $svg += "<text x='$tx' y='44' font-family='IBM Plex Mono' font-size='9' fill='#FBF9F4' text-anchor='middle' opacity='0.85'>$c</text>"
        }
        $x += $w
    }
    $svg += "</svg>"
    return $svg
}

function Render-ScoreLegend {
    param([hashtable]$Counts, [int]$Total)
    $h = '<div class="score-legend">'
    foreach ($k in @('HIGH','MEDIUM','LOW','CLEAN')) {
        $c = $Counts[$k]
        $pct = if ($Total -gt 0) { [math]::Round(($c / $Total) * 100, 1) } else { 0 }
        $color = Score-Color $k
        $h += "<div class='legend-row'><span class='legend-dot' style='background:$color'></span><span class='legend-label score-$($k.ToLower())'>$k</span><span class='legend-value'>$c ($pct%)</span></div>"
    }
    $h += '</div>'
    return $h
}

function Render-SuspectTable {
    param($Items)
    $filtered = $Items | Where-Object { $_.Score -in @('HIGH','MEDIUM') }
    $filtered = $filtered | Sort-Object @{E={ switch ($_.Score) { 'HIGH' {1} 'MEDIUM' {2} } }}, Name
    if (-not $filtered) { return "<tr><td colspan='5' class='empty'>No items at HIGH or MEDIUM confidence.</td></tr>" }
    $rows = ''
    foreach ($p in $filtered) {
        $color = Score-Color $p.Score
        $shortPath = $p.Path
        if ($shortPath.Length -gt 80) { $shortPath = $shortPath.Substring(0, 77) + '...' }
        $pidOrState = if ($p.ProcessId) { "PID $($p.ProcessId)" } else { $p.State }
        $rows += "<tr><td class='score-cell'><span class='score-badge' style='background:$color'>$($p.Score)</span></td><td class='lbl'>$(Escape-Xml $p.Name)</td><td class='dt'>$(Escape-Xml $pidOrState)</td><td class='path'>$(Escape-Xml $shortPath)</td><td class='reason'>$(Escape-Xml $p.Reason)</td></tr>"
    }
    return $rows
}

# ============================================================================
# TIMELINE: extract dated events and render SVG
# ============================================================================

function Parse-FlexibleDate {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text) -or $Text -eq 'unknown') { return $null }
    $formats = @(
        "yyyy-MM-ddTHH:mm:ss", "yyyy-MM-ddTHH:mm:ss.fff",
        "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd",
        "M/d/yyyy h:mm:ss tt", "MM/dd/yyyy HH:mm:ss"
    )
    foreach ($fmt in $formats) {
        try { return [datetime]::ParseExact($Text, $fmt, [System.Globalization.CultureInfo]::InvariantCulture) } catch {}
    }
    try { return [datetime]::Parse($Text) } catch {}
    return $null
}

function Get-TimelineEvents {
    param($Findings, $ProcessesScored)
    $events = [System.Collections.Generic.List[hashtable]]::new()

    $timeFields = @(
        @{ Key='InstallDate';   Shape='diamond'; Label='install' },
        @{ Key='FirstInstall';  Shape='diamond'; Label='first install' },
        @{ Key='LastExecution'; Shape='circle';  Label='last execution' },
        @{ Key='LastArrival';   Shape='circle';  Label='USB arrival' },
        @{ Key='LastRemoval';   Shape='circle';  Label='USB removal' },
        @{ Key='FirstSeen';     Shape='circle';  Label='first seen' },
        @{ Key='LastModified';  Shape='circle';  Label='last modified' },
        @{ Key='LastWrite';     Shape='circle';  Label='last write' },
        @{ Key='OldestWrite';   Shape='circle';  Label='oldest write' },
        @{ Key='NewestWrite';   Shape='circle';  Label='newest write' },
        @{ Key='Created';       Shape='circle';  Label='created' }
    )

    foreach ($f in $Findings) {
        if ($f.Severity -notin @('HIGH','MEDIUM')) { continue }
        $m = $f.Metadata
        if (-not $m) { continue }
        $track = if ($m.Pattern) { $m.Pattern.ToLower() }
                 elseif ($m.Label) { $m.Label.ToLower() }
                 else { $f.Category.ToLower() }
        $itemLabel = if ($m.Pattern) { $m.Pattern } elseif ($m.Label) { $m.Label } else { $f.Category }
        foreach ($spec in $timeFields) {
            $val = $m[$spec.Key]
            if (-not $val) { continue }
            $dt = Parse-FlexibleDate $val
            if ($dt -and $dt.Year -gt 1990 -and $dt.Year -lt 2100) {
                [void]$events.Add(@{
                    Date = $dt; Track = $track; Label = $itemLabel
                    Kind = $spec.Label; Shape = $spec.Shape
                    Severity = $f.Severity; Category = $f.Category
                })
            }
        }
    }

    foreach ($p in $ProcessesScored) {
        if ($p.Score -notin @('HIGH','MEDIUM')) { continue }
        $dt = Parse-FlexibleDate $p.Started
        if ($dt -and $dt.Year -gt 1990 -and $dt.Year -lt 2100) {
            $track = if ($p.Pattern) { $p.Pattern.ToLower() } else { $p.Name.ToLower() }
            [void]$events.Add(@{
                Date = $dt; Track = $track; Label = $p.Name
                Kind = 'process start'; Shape = 'circle'
                Severity = $p.Score; Category = 'Process'
            })
        }
    }

    return $events
}

function Render-Timeline {
    param($Events)
    if (-not $Events -or $Events.Count -eq 0) { return $null }

    $byTrack = @{}
    foreach ($e in $Events) {
        if (-not $byTrack.ContainsKey($e.Track)) { $byTrack[$e.Track] = [System.Collections.Generic.List[hashtable]]::new() }
        [void]$byTrack[$e.Track].Add($e)
    }
    $trackOrder = @($byTrack.Keys | Sort-Object {
        ($byTrack[$_] | ForEach-Object { $_.Date } | Sort-Object | Select-Object -First 1)
    })
    if ($trackOrder.Count -gt 8) {
        $keep = @($trackOrder | Select-Object -First 7)
        $merge = @($trackOrder | Select-Object -Skip 7)
        $other = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($t in $merge) {
            foreach ($e in $byTrack[$t]) { [void]$other.Add($e) }
            $byTrack.Remove($t)
        }
        $byTrack['other'] = $other
        $trackOrder = $keep + @('other')
    }

    $allDates = @($Events | ForEach-Object { $_.Date })
    $minDate = ($allDates | Sort-Object | Select-Object -First 1)
    $maxDate = ($allDates | Sort-Object -Descending | Select-Object -First 1)
    $rangeDays = ($maxDate - $minDate).TotalDays
    if ($rangeDays -lt 14) {
        $minDate = $minDate.AddDays(-7); $maxDate = $maxDate.AddDays(7)
    } else {
        $pad = [math]::Max(7, $rangeDays * 0.06)
        $minDate = $minDate.AddDays(-$pad); $maxDate = $maxDate.AddDays($pad)
    }
    $rangeSecs = ($maxDate - $minDate).TotalSeconds
    if ($rangeSecs -le 0) { return $null }

    $width = 880; $leftPad = 100; $rightPad = 30
    $topPad = 58; $rowHeight = 40; $bottomPad = 40
    $plotWidth = $width - $leftPad - $rightPad
    $plotHeight = $trackOrder.Count * $rowHeight
    $totalHeight = $topPad + $plotHeight + $bottomPad

    $svg = "<svg viewBox='0 0 $width $totalHeight' xmlns='http://www.w3.org/2000/svg'>"

    # Month gridlines + labels across top
    $cur = New-Object DateTime($minDate.Year, $minDate.Month, 1)
    if ($cur -lt $minDate) { $cur = $cur.AddMonths(1) }
    while ($cur -le $maxDate) {
        $offset = ($cur - $minDate).TotalSeconds
        $x = [math]::Round($leftPad + ($offset / $rangeSecs) * $plotWidth, 1)
        $svg += "<line x1='$x' y1='$topPad' x2='$x' y2='$($topPad + $plotHeight)' stroke='#E8E2D5' stroke-width='1' stroke-dasharray='2,3'/>"
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        $lbl = ($cur.ToString("MMM", $inv) + " '" + $cur.ToString("yy", $inv)).ToUpper()
        $svg += "<text x='$x' y='$($topPad - 16)' font-family='IBM Plex Mono' font-size='10' fill='#8A857C' text-anchor='middle' letter-spacing='1.5'>$lbl</text>"
        $cur = $cur.AddMonths(1)
    }

    # Top + bottom plot rules
    $svg += "<line x1='$leftPad' y1='$topPad' x2='$($leftPad + $plotWidth)' y2='$topPad' stroke='#B8B0A0' stroke-width='1'/>"
    $svg += "<line x1='$leftPad' y1='$($topPad + $plotHeight)' x2='$($leftPad + $plotWidth)' y2='$($topPad + $plotHeight)' stroke='#B8B0A0' stroke-width='1'/>"

    # Zebra row backgrounds + track labels
    for ($i = 0; $i -lt $trackOrder.Count; $i++) {
        $rowY = $topPad + $i * $rowHeight
        if ($i % 2 -eq 0) {
            $svg += "<rect x='$leftPad' y='$rowY' width='$plotWidth' height='$rowHeight' fill='#F5F2EB' opacity='0.55'/>"
        }
        $lblY = $rowY + $rowHeight / 2 + 4
        $t = $trackOrder[$i]
        $tlbl = $t.ToUpper()
        if ($tlbl.Length -gt 13) { $tlbl = $tlbl.Substring(0, 13) }
        $svg += "<text x='$($leftPad - 12)' y='$lblY' font-family='IBM Plex Mono' font-size='10' fill='#4A463E' text-anchor='end' font-weight='600' letter-spacing='1.2'>$(Escape-Xml $tlbl)</text>"
    }

    # Plot every event
    for ($i = 0; $i -lt $trackOrder.Count; $i++) {
        $rowY = $topPad + $i * $rowHeight
        $cy = $rowY + $rowHeight / 2
        foreach ($e in $byTrack[$trackOrder[$i]]) {
            $offset = ($e.Date - $minDate).TotalSeconds
            $x = [math]::Round($leftPad + ($offset / $rangeSecs) * $plotWidth, 1)
            $color = if ($e.Severity -eq 'HIGH') { '#6B1E1E' } else { '#8A6914' }
            $title = "$($e.Label) - $($e.Kind) - $($e.Date.ToString('yyyy-MM-dd HH:mm'))"
            $titleEsc = Escape-Xml $title
            if ($e.Shape -eq 'diamond') {
                $r = 6
                $pts = "$x,$($cy - $r) $($x + $r),$cy $x,$($cy + $r) $($x - $r),$cy"
                $svg += "<polygon points='$pts' fill='none' stroke='$color' stroke-width='2'><title>$titleEsc</title></polygon>"
            } else {
                $svg += "<circle cx='$x' cy='$cy' r='5' fill='$color' opacity='0.88'><title>$titleEsc</title></circle>"
            }
        }
    }

    # First / last date callouts under the plot
    $sortedAsc = @($Events | Sort-Object { $_.Date })
    $first = $sortedAsc[0]; $last = $sortedAsc[$sortedAsc.Count - 1]
    if ($first -and $last -and ($first.Date -ne $last.Date)) {
        $fx = [math]::Round($leftPad + (($first.Date - $minDate).TotalSeconds / $rangeSecs) * $plotWidth, 1)
        $lx = [math]::Round($leftPad + (($last.Date - $minDate).TotalSeconds / $rangeSecs) * $plotWidth, 1)
        $cy = $topPad + $plotHeight + 22
        $svg += "<text x='$fx' y='$cy' font-family='IBM Plex Mono' font-size='10' fill='#4A463E' text-anchor='middle'>$($first.Date.ToString('MMM d'))</text>"
        $svg += "<text x='$lx' y='$cy' font-family='IBM Plex Mono' font-size='10' fill='#4A463E' text-anchor='middle'>$($last.Date.ToString('MMM d'))</text>"
    }

    $svg += "</svg>"
    return $svg
}

$rendered = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
$totalProc = $processes.Count
$totalSvc = $services.Count

$procStackedBar = Render-StackedBar $procByScore $totalProc
$procLegend = Render-ScoreLegend $procByScore $totalProc
$svcStackedBar = Render-StackedBar $svcByScore $totalSvc
$svcLegend = Render-ScoreLegend $svcByScore $totalSvc
$procSuspectRows = Render-SuspectTable $procScored
$svcSuspectRows = Render-SuspectTable $svcScored

# Findings table (RECENT only - drives verdict)
$findingsRows = ''
$cheatFindings = @($recentFindings | Where-Object { $_.Severity -in @('HIGH','MEDIUM') } | Sort-Object @{E={ switch ($_.Severity) { 'HIGH' {1} 'MEDIUM' {2} } }}, Category)
foreach ($f in $cheatFindings) {
    $color = if ($f.Severity -eq 'HIGH') { $COLOR_HIGH } else { $COLOR_MED }
    $pattern = if ($f.Metadata.Pattern) { $f.Metadata.Pattern } else { '-' }
    $detail = $f.Detail
    if ($detail.Length -gt 120) { $detail = $detail.Substring(0, 117) + '...' }
    $findingsRows += "<tr><td class='score-cell'><span class='score-badge' style='background:$color'>$($f.Severity)</span></td><td class='lbl'>$(Escape-Xml $f.Category)</td><td class='dt'>$(Escape-Xml $pattern)</td><td class='reason'>$(Escape-Xml $detail)</td></tr>"
}
if (-not $findingsRows) {
    $findingsRows = "<tr><td colspan='4' class='empty'>No HIGH or MEDIUM recent findings.</td></tr>"
}

# v3.8 - HISTORICAL findings section (logged, did NOT affect verdict)
$historicalRows = ''
$historicalSection = ''
foreach ($f in ($historicalFindings | Sort-Object @{E={ -([int]($_.Metadata.AgeDays | ForEach-Object { if ($_) { $_ } else { 0 } })) }}, Category)) {
    $origSev = if ($f.Metadata.OriginalSeverity) { $f.Metadata.OriginalSeverity } else { '?' }
    $age = if ($f.Metadata.AgeDays) { "$($f.Metadata.AgeDays)d" } else { 'age unknown' }
    $pattern = if ($f.Metadata.Pattern) { $f.Metadata.Pattern } else { '-' }
    $detail = $f.Detail
    if ($detail.Length -gt 110) { $detail = $detail.Substring(0, 107) + '...' }
    $historicalRows += "<tr><td class='score-cell'><span class='score-badge' style='background:#5A5045'>was $origSev</span></td><td class='lbl'>$(Escape-Xml $f.Category)</td><td class='dt'>$age</td><td class='dt'>$(Escape-Xml $pattern)</td><td class='reason'>$(Escape-Xml $detail)</td></tr>"
}
if ($historicalRows) {
    $hCount = $historicalFindings.Count
    $hOrigHigh = $historicalByOrig.HIGH
    $hOrigMed  = $historicalByOrig.MEDIUM
    $historicalSection = @"
  <section>
    <h2><span class="num"># 06</span>Historical findings<span class="qual">older than 180 days &mdash; logged, did not affect verdict</span></h2>
    <div class="section-rule"></div>
    <p class="caption">$hCount finding(s) were demoted by the recency-decay rule: $hOrigHigh originally HIGH, $hOrigMed originally MEDIUM. These represent activity that occurred long ago and would inflate a current verdict if counted. They are surfaced here for full transparency &mdash; a reviewer can still see what was found and decide how much weight to give it.</p>
    <table class="findings-table">
      <thead><tr><th>Original</th><th>Category</th><th>Age</th><th>Pattern</th><th>Detail</th></tr></thead>
      <tbody>$historicalRows</tbody>
    </table>
  </section>
"@
}

# Timeline
$timelineEvents = Get-TimelineEvents $findings $procScored
$timelineSvg = Render-Timeline $timelineEvents
$timelineSection = ''
if ($timelineSvg) {
    $tlEventCount = $timelineEvents.Count
    $tlTrackCount = (@($timelineEvents | ForEach-Object { $_.Track } | Sort-Object -Unique)).Count
    $tlSorted = @($timelineEvents | Sort-Object { $_.Date })
    $tlFirst = $tlSorted[0].Date
    $tlLast = $tlSorted[$tlSorted.Count - 1].Date
    $tlSpan = [int]($tlLast - $tlFirst).TotalDays
    $tlCaption = "$tlEventCount dated HIGH or MEDIUM events plotted across $tlTrackCount track(s). Earliest: $($tlFirst.ToString('MMM d, yyyy')). Latest: $($tlLast.ToString('MMM d, yyyy')). Activity span: $tlSpan days. Circles mark execution, write, arrival, or runtime events; diamonds mark original-install dates pulled from the Windows registry. Tracks are grouped by matched keyword or category and ordered top-to-bottom by earliest activity."
    $tlCaptionEsc = Escape-Xml $tlCaption
    $timelineSection = @"
  <section>
    <h2><span class="num"># 02</span>Activity timeline<span class="qual">read left to right</span></h2>
    <div class="section-rule"></div>
    <div class="viz-frame timeline-frame">
      $timelineSvg
    </div>
    <div class="timeline-legend">
      <div class="tl-item"><span class="tl-dot" style="background:#6B1E1E"></span><span class="tl-text">HIGH event</span></div>
      <div class="tl-item"><span class="tl-dot" style="background:#8A6914"></span><span class="tl-text">MEDIUM event</span></div>
      <div class="tl-item"><span class="tl-diamond" style="border-color:#6B1E1E"></span><span class="tl-text">Install date (registry)</span></div>
    </div>
    <p class="timeline-caption">$tlCaptionEsc</p>
  </section>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Alibi - Threat Triage</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,500;1,6..72,400&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#F5F2EB;--paper:#FBF9F4;--ink:#1A1A1A;--ink-soft:#4A463E;--ink-faint:#8A857C;--rule:#D8D2C7;--rule-strong:#B8B0A0;--high:#6B1E1E;--med:#8A6914;--low:#2E3A4A;--clean:#1F3F2E;--serif:'Newsreader',Georgia,serif;--sans:'IBM Plex Sans',system-ui,sans-serif;--mono:'IBM Plex Mono',Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
html{font-size:16px}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-feature-settings:"onum" 1;line-height:1.55;padding:48px 24px;-webkit-font-smoothing:antialiased}
.page{max-width:1080px;margin:0 auto;background:var(--paper);padding:56px 64px;border:1px solid var(--rule);box-shadow:0 1px 0 var(--rule),0 4px 24px rgba(0,0,0,.04)}
.eyebrow{font-family:var(--mono);font-size:.7rem;letter-spacing:.18em;text-transform:uppercase;color:var(--high);margin-bottom:8px}
h1.title{font-family:var(--serif);font-weight:500;font-size:2.4rem;line-height:1.1;letter-spacing:-.018em;margin-bottom:6px}
.dateline{font-family:var(--mono);font-size:.74rem;color:var(--ink-faint);margin-bottom:28px;letter-spacing:.04em;line-height:1.7}
.verdict{padding:28px 32px;margin-bottom:36px;border:1px solid var(--rule);position:relative}
.verdict.verdict-high{background:rgba(107,30,30,0.06);border-left:6px solid var(--high)}
.verdict.verdict-med{background:rgba(138,105,20,0.06);border-left:6px solid var(--med)}
.verdict.verdict-clean{background:rgba(31,63,46,0.06);border-left:6px solid var(--clean)}
.verdict .label{font-family:var(--mono);font-size:.66rem;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-faint);margin-bottom:8px}
.verdict .text{font-family:var(--serif);font-size:1.7rem;font-weight:500;letter-spacing:-.01em;line-height:1.2}
.verdict.verdict-high .text{color:var(--high)}
.verdict.verdict-med .text{color:var(--med)}
.verdict.verdict-clean .text{color:var(--clean)}
.verdict .summary{font-family:var(--mono);font-size:.78rem;color:var(--ink-soft);margin-top:14px;letter-spacing:.02em}
.score-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:0;border:1px solid var(--rule);margin-bottom:48px}
.score-cell-big{padding:22px 20px;border-right:1px solid var(--rule);text-align:center}
.score-cell-big:last-child{border-right:none}
.score-cell-big .label{font-family:var(--mono);font-size:.62rem;letter-spacing:.16em;text-transform:uppercase;margin-bottom:8px}
.score-cell-big.high .label{color:var(--high)}
.score-cell-big.med .label{color:var(--med)}
.score-cell-big.low .label{color:var(--low)}
.score-cell-big.clean .label{color:var(--clean)}
.score-cell-big .value{font-family:var(--serif);font-size:2rem;font-weight:500;line-height:1;font-variant-numeric:oldstyle-nums;color:var(--ink)}
.score-cell-big .breakdown{font-family:var(--mono);font-size:.66rem;color:var(--ink-faint);margin-top:10px;line-height:1.5;letter-spacing:.02em}
section{margin-bottom:48px}
h2{font-family:var(--serif);font-weight:500;font-size:1.5rem;letter-spacing:-.01em;margin-bottom:4px;display:flex;align-items:baseline;gap:14px}
h2 .num{font-family:var(--mono);font-size:.7rem;color:var(--high);font-weight:500;letter-spacing:.1em}
h2 .qual{font-family:var(--serif);font-style:italic;font-size:1rem;color:var(--ink-faint);font-weight:400;margin-left:auto}
.section-rule{height:1px;background:var(--rule);margin:12px 0 24px 0}
h3{font-family:var(--serif);font-size:1.05rem;font-weight:500;font-style:italic;margin-bottom:14px;color:var(--ink)}
.viz-frame{border:1px solid var(--rule);padding:24px;background:var(--paper);margin-bottom:24px}
.viz-frame svg{width:100%;height:auto;display:block}
.viz-row{display:grid;grid-template-columns:1fr 280px;gap:32px;align-items:center}
.score-legend{display:flex;flex-direction:column;gap:8px}
.legend-row{display:flex;align-items:center;gap:12px;font-size:.86rem}
.legend-dot{width:14px;height:14px;border-radius:2px;flex-shrink:0}
.legend-label{font-family:var(--mono);font-weight:600;font-size:.7rem;letter-spacing:.1em;flex:1}
.legend-label.score-high{color:var(--high)}
.legend-label.score-medium{color:var(--med)}
.legend-label.score-low{color:var(--low)}
.legend-label.score-clean{color:var(--clean)}
.legend-value{font-family:var(--mono);color:var(--ink-soft);font-size:.8rem;font-variant-numeric:tabular-nums}
table.suspect{width:100%;border-collapse:collapse;font-size:.84rem;border-top:1px solid var(--rule-strong);border-bottom:1px solid var(--rule-strong)}
table.suspect th{text-align:left;font-family:var(--mono);font-size:.62rem;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-faint);padding:10px 14px 10px 0;font-weight:500;border-bottom:1px solid var(--rule-strong)}
table.suspect td{padding:11px 14px 11px 0;border-bottom:1px solid var(--rule);font-family:var(--mono);font-size:.78rem;color:var(--ink);vertical-align:top}
table.suspect td.score-cell{width:90px}
table.suspect td.lbl{font-family:var(--sans);font-weight:500;font-size:.85rem;width:160px}
table.suspect td.dt{color:var(--ink-soft);font-size:.74rem;width:90px}
table.suspect td.path{font-size:.74rem;color:var(--ink-soft);word-break:break-all}
table.suspect td.reason{font-style:italic;font-family:var(--serif);font-size:.88rem;color:var(--ink);width:280px}
table.suspect td.empty{color:var(--ink-faint);font-style:italic;text-align:center;padding:24px 0;font-family:var(--serif)}
.score-badge{display:inline-block;padding:3px 9px;font-family:var(--mono);font-size:.64rem;font-weight:600;letter-spacing:.12em;color:#FBF9F4;border-radius:2px}
.rubric{background:rgba(46,58,74,0.04);border:1px solid var(--rule);padding:20px 24px;margin-bottom:32px}
.rubric h3{margin-bottom:14px;font-style:normal;font-family:var(--sans);font-size:.72rem;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-faint);font-weight:600}
.rubric-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}
.rubric-item{padding-left:12px;border-left:3px solid}
.rubric-item.high{border-left-color:var(--high)}
.rubric-item.med{border-left-color:var(--med)}
.rubric-item.low{border-left-color:var(--low)}
.rubric-item.clean{border-left-color:var(--clean)}
.rubric-item .title{font-family:var(--mono);font-size:.7rem;letter-spacing:.12em;font-weight:600;margin-bottom:4px}
.rubric-item.high .title{color:var(--high)}
.rubric-item.med .title{color:var(--med)}
.rubric-item.low .title{color:var(--low)}
.rubric-item.clean .title{color:var(--clean)}
.rubric-item .desc{font-size:.78rem;font-family:var(--serif);color:var(--ink-soft);line-height:1.5}
.timeline-frame{padding:32px 16px 20px 16px}
.timeline-frame svg{width:100%;height:auto;display:block}
.timeline-legend{display:flex;flex-wrap:wrap;gap:24px;margin-top:18px;padding:4px 8px 0 8px}
.tl-item{display:inline-flex;align-items:center;gap:10px}
.tl-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;display:inline-block}
.tl-diamond{width:11px;height:11px;transform:rotate(45deg);border:2px solid;background:transparent;flex-shrink:0;display:inline-block}
.tl-text{font-family:var(--mono);font-size:.68rem;letter-spacing:.12em;color:var(--ink-soft);text-transform:uppercase;font-weight:600}
.timeline-caption{font-family:var(--serif);font-style:italic;color:var(--ink-soft);font-size:.94rem;line-height:1.55;margin-top:18px;padding:0 8px}
footer{margin-top:48px;padding-top:20px;border-top:1px solid var(--rule);display:flex;justify-content:space-between;font-family:var(--mono);font-size:.68rem;color:var(--ink-faint);letter-spacing:.04em}
@media (max-width:760px){
  body{padding:16px 0}
  .page{padding:36px 24px;border-left:none;border-right:none}
  h1.title{font-size:1.85rem}
  .score-strip{grid-template-columns:repeat(2,1fr)}
  .score-cell-big:nth-child(2n){border-right:none}
  .viz-row{grid-template-columns:1fr;gap:20px}
  .rubric-grid{grid-template-columns:1fr 1fr;gap:14px}
  table.suspect td.path{display:none}
}
</style>
</head>
<body>
<div class="page">

  <div class="eyebrow">Threat Triage - Alibi</div>
  <h1 class="title">Cheat detection confidence</h1>
  <p class="dateline">
    SCAN: $(Escape-Xml $generated)<br>
    HOST: $(Escape-Xml $hostname) &middot; USER: $(Escape-Xml $username) &middot; ADMIN: $(Escape-Xml $admin)<br>
    SOURCE: $(Escape-Xml ([System.IO.Path]::GetFileName($InputPath))) &middot; RENDERED: $rendered
  </p>

  <div class="verdict $verdictClass">
    <div class="label">Overall verdict</div>
    <div class="text">$verdict</div>
    <div class="summary">
      HIGH-confidence indicators: <strong>$totalHigh</strong> &nbsp;&middot;&nbsp;
      MEDIUM (review): <strong>$totalMed</strong> &nbsp;&middot;&nbsp;
      Scope: $($findings.Count) cheat-trace findings, $totalProc running processes, $totalSvc services scored
    </div>
  </div>

  <div class="score-strip">
    <div class="score-cell-big high">
      <div class="label">High</div>
      <div class="value">$totalHigh</div>
      <div class="breakdown">$($findingsByScore.HIGH) traces<br>$($procByScore.HIGH) procs<br>$($svcByScore.HIGH) svcs</div>
    </div>
    <div class="score-cell-big med">
      <div class="label">Medium</div>
      <div class="value">$totalMed</div>
      <div class="breakdown">$($findingsByScore.MEDIUM) traces<br>$($procByScore.MEDIUM) procs<br>$($svcByScore.MEDIUM) svcs</div>
    </div>
    <div class="score-cell-big low">
      <div class="label">Low</div>
      <div class="value">$($procByScore.LOW + $svcByScore.LOW)</div>
      <div class="breakdown">$($procByScore.LOW) procs<br>$($svcByScore.LOW) svcs</div>
    </div>
    <div class="score-cell-big clean">
      <div class="label">Clean</div>
      <div class="value">$($procByScore.CLEAN + $svcByScore.CLEAN)</div>
      <div class="breakdown">$($procByScore.CLEAN) procs<br>$($svcByScore.CLEAN) svcs</div>
    </div>
  </div>

  <div class="rubric">
    <h3>Scoring rubric</h3>
    <div class="rubric-grid">
      <div class="rubric-item high">
        <div class="title">HIGH</div>
        <div class="desc">Matches a research-confirmed cheat or input-device keyword in name, path, or command line.</div>
      </div>
      <div class="rubric-item med">
        <div class="title">MEDIUM</div>
        <div class="desc">Matches a dual-use tool, OR runs from a user-writable location and is not on the known-good vendor list.</div>
      </div>
      <div class="rubric-item low">
        <div class="title">LOW</div>
        <div class="desc">Runs from Program Files or a non-standard but typical location with no keyword match.</div>
      </div>
      <div class="rubric-item clean">
        <div class="title">CLEAN</div>
        <div class="desc">Runs from System32 / SysWOW64 / standard Windows paths with no keyword match.</div>
      </div>
    </div>
  </div>

  <section>
    <h2><span class="num"># 01</span>Cheat trace findings<span class="qual">$($cheatFindings.Count) at HIGH or MEDIUM</span></h2>
    <div class="section-rule"></div>
    <table class="suspect">
      <thead><tr><th>Score</th><th>Category</th><th>Keyword</th><th>Detail</th></tr></thead>
      <tbody>$findingsRows</tbody>
    </table>
  </section>

$timelineSection
  <section>
    <h2><span class="num"># 03</span>Process suspicion distribution<span class="qual">$totalProc running</span></h2>
    <div class="section-rule"></div>
    <div class="viz-frame">
      <h3>Confidence breakdown</h3>
      <div class="viz-row">
        <div>$procStackedBar</div>
        <div>$procLegend</div>
      </div>
    </div>
    <h3 style="margin-top:24px;margin-bottom:14px">Processes flagged at HIGH or MEDIUM</h3>
    <table class="suspect">
      <thead><tr><th>Score</th><th>Name</th><th>ID</th><th>Path</th><th>Reason</th></tr></thead>
      <tbody>$procSuspectRows</tbody>
    </table>
  </section>

  <section>
    <h2><span class="num"># 04</span>Service suspicion distribution<span class="qual">$totalSvc registered</span></h2>
    <div class="section-rule"></div>
    <div class="viz-frame">
      <h3>Confidence breakdown</h3>
      <div class="viz-row">
        <div>$svcStackedBar</div>
        <div>$svcLegend</div>
      </div>
    </div>
    <h3 style="margin-top:24px;margin-bottom:14px">Services flagged at HIGH or MEDIUM</h3>
    <table class="suspect">
      <thead><tr><th>Score</th><th>Name</th><th>State</th><th>Path</th><th>Reason</th></tr></thead>
      <tbody>$svcSuspectRows</tbody>
    </table>
  </section>

$historicalSection

  <footer><span>Generated by generate-visual-companion.ps1</span><span>$rendered</span></footer>

</div>
</body>
</html>
"@

$clean = -join ($html.ToCharArray() | ForEach-Object {
    if ([int][char]$_ -lt 128) { $_ } else { '?' }
})

$clean | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ''
Write-Host '================================================================' -ForegroundColor Green
Write-Host '  Threat triage visual companion generated.' -ForegroundColor Green
Write-Host ''
Write-Host "  Input:    $InputPath"
Write-Host "  Output:   $OutputPath"
Write-Host ''
Write-Host "  Verdict:  $verdict"
Write-Host "  HIGH:     $totalHigh"
Write-Host "  MEDIUM:   $totalMed"
Write-Host "  Procs:    $totalProc scored ($($procByScore.HIGH)H / $($procByScore.MEDIUM)M / $($procByScore.LOW)L / $($procByScore.CLEAN)C)"
Write-Host "  Services: $totalSvc scored ($($svcByScore.HIGH)H / $($svcByScore.MEDIUM)M / $($svcByScore.LOW)L / $($svcByScore.CLEAN)C)"
Write-Host '================================================================' -ForegroundColor Green
Write-Host ''
