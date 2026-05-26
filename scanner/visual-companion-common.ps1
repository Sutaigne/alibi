<#
.SYNOPSIS
    Shared visual-companion renderer for the Alibi PowerShell scanners.

.DESCRIPTION
    This module is a faithful PowerShell port of python/src/alibi/visual_companion.py.
    It exposes one public function:

        Render-AlibiHtml -InputPath <txt> -OutputPath <html> `
                         -ModeLabel <'pc-mode'|'console-mode'> `
                         -CoverageLimitations <string[]>

    The two driver scripts (generate-visual-companion.ps1 and
    generate-visual-companion-console.ps1) are thin shims that dot-source this
    file, supply mode-specific coverage text, and invoke Render-AlibiHtml.

    CSS and JS are loaded from $PSScriptRoot/visual_styles.css and
    $PSScriptRoot/visual_scripts.js. Those files are the SAME source of truth
    the Python renderer reads — keep them verbatim.

.NOTES
    Author: Bread
    Contributor: Drownmw

    KEEP IN PARITY with python/src/alibi/visual_companion.py. Section order,
    HTML class names, SVG coordinates, and id-slug scheme must match so that
    docs/design-handoff-2026-05/reports/*.html stays the byte-for-byte spec.
#>

# ============================================================================
# CONSTANTS — verdict mapping, lane geometry, log-scale math, recency
# ============================================================================

$script:ALIBI_VERSION = '4.2.0'

$script:VERDICT_STATE = @{
    'CHEATS DETECTED'           = 'red'
    'INPUT DEVICES DETECTED'    = 'red'
    'MITM CHEAT STACK DETECTED' = 'red'
    'CAPTURE STACK PRESENT'     = 'amber'
    'UNSURE'                    = 'amber'
    'CLEAN'                     = 'green'
}

$script:STATE_COLOUR_VAR = @{ red = '--hi'; amber = '--md'; green = '--ok' }

$script:LANE_Y = @{ HIGH = 50; MEDIUM = 86; WARN = 118; INFO = 148 }

$script:X_LIVE_LEFT  = 220
$script:X_LIVE_RIGHT = 1196
$script:LIVE_LOG_BASE = [math]::Log(181)
$script:ARCH_RIGHT_EDGE = 192

$script:STACK_DX = 9
$script:STACK_DY = 9
$script:R_MIN  = 2.8
$script:R_MAX  = 5.0
$script:R_STEP = 0.55

$script:FRESH_MAX_DAYS = 7

$script:TIMESTAMP_KEYS = @(
    'LastRun','LastExecution','LastArrival','Timestamp',
    'LastWrite','LastModified','NewestWrite',
    'Created','FirstSeen','FirstInstall','InstallDate','LastRemoval',
    'OldestWrite','MostRecentTimestamp'
)

$script:HASH_KEYS  = @('SHA256','Sha256','sha256','LOLDrivers_Id')
$script:URL_KEYS   = @('LOLDrivers_URL','Reference')
$script:BYTES_KEYS = @('SizeBytes','BlobSizeBytes')

$script:SEVERITY_ORDER = @('HIGH','MEDIUM','WARN','INFO')

$script:RECENCY_THRESHOLD_DAYS = 180

$script:VERDICT_SUBS = @{
    'CHEATS DETECTED' = 'High-confidence indicators of cheat software, HWID spoofers, or DMA-cheat development artifacts were present on this machine within the last 180 days.'
    'INPUT DEVICES DETECTED' = 'No cheat brands or HWID spoofers were detected. The scan did find high-confidence input-device adapter software (XIM / Cronus / ReaSnow / KMBox / Titan). Some games treat these as bannable; some do not.'
    'MITM CHEAT STACK DETECTED' = 'High-confidence indicators that this PC is part of a console-MITM cheat stack — vision aimbot, input-adapter configurator, or traditional PC cheats.'
    'CAPTURE STACK PRESENT' = 'No cheats or adapter software detected. Capture-card and/or HID-emulation drivers were found — legitimate for streaming and controller remapping, but also a component of console-MITM stacks.'
    'UNSURE' = 'No HIGH-confidence cheat or input-device matches. MEDIUM findings require human review — usually dual-use tools or binaries in user-writable locations not on the allowlist.'
    'CLEAN' = 'No recent HIGH or MEDIUM matches against the cheat / input-device / dual-use keyword database (within the last 180 days). This is necessary but not sufficient evidence — see limitations below.'
}

# ============================================================================
# SMALL HELPERS
# ============================================================================

function Esc-Html {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#x27;')
}

function Slug {
    param([string]$Text, [int]$MaxLen = 32)
    if ([string]::IsNullOrEmpty($Text)) { return 'x' }
    $lc = $Text.ToLower()
    $out = ($lc -replace '[^a-z0-9]+','-').Trim('-')
    if ([string]::IsNullOrEmpty($out)) { $out = 'x' }
    if ($out.Length -gt $MaxLen) { $out = $out.Substring(0,$MaxLen) }
    return $out
}

function Format-Bytes {
    param([object]$N)
    $i = 0
    if ([int]::TryParse([string]$N, [ref]$i)) {
        return ('{0:N0}' -f $i)
    }
    return (Esc-Html $N)
}

function State-For-Verdict {
    param([string]$Verdict)
    if ($script:VERDICT_STATE.ContainsKey($Verdict)) { return $script:VERDICT_STATE[$Verdict] }
    return 'amber'
}

function X-Live {
    param([double]$DaysAgo)
    if ($DaysAgo -le 0) { return [double]$script:X_LIVE_RIGHT }
    if ($DaysAgo -ge 180) { return [double]$script:X_LIVE_LEFT }
    return $script:X_LIVE_RIGHT - ($script:X_LIVE_RIGHT - $script:X_LIVE_LEFT) * [math]::Log($DaysAgo + 1) / $script:LIVE_LOG_BASE
}

function Human-Age {
    param([double]$Days)
    $d = [int][math]::Round($Days)
    if ($d -le 0)   { return 'today' }
    if ($d -eq 1)   { return '1 d ago' }
    if ($d -lt 30)  { return "$d d ago" }
    if ($d -lt 365) { return "$([int]($d / 30)) mo ago" }
    $years = $d / 365.0
    if ($years -lt 2) { return ('{0:N1} y ago' -f $years) }
    return "$([int]$years) y ago"
}

function Short-Age {
    param([double]$Days)
    $d = [int][math]::Round($Days)
    if ($d -lt 365) { return "${d}d" }
    return "$([int]($d / 365))y"
}

function Iso-Date     { param([datetime]$Dt) return $Dt.ToString('yyyy-MM-dd') }
function Iso-DateTime { param([datetime]$Dt) return $Dt.ToString('yyyy-MM-dd HH:mm:ss') }
function Now-Iso      { return (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss') }

# Format a numeric SVG coordinate. MUST use InvariantCulture — the default
# "{0:N1}" format inserts the current-culture thousand separator (e.g. "1,196.0"
# in en-US), which SVG parses as broken coordinates: circles render at x=1 and
# polygon points lists fall apart into hexagons. Bug surfaced when lifecycle
# data spanned >999px of plot width (anything past Jan 2026 on a 14-month axis).
$script:_INV_CULTURE = [System.Globalization.CultureInfo]::InvariantCulture
function FmtCoord {
    param([double]$Value)
    return [string]::Format($script:_INV_CULTURE, '{0:F1}', $Value)
}
function FmtPct {
    param([double]$Value)
    return [string]::Format($script:_INV_CULTURE, '{0:F2}', $Value)
}

function Try-Parse-Dt {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text) -or $Text -eq 'unknown') { return $null }
    $fmts = @(
        'yyyy-MM-ddTHH:mm:ss','yyyy-MM-ddTHH:mm:ss.fff',
        'yyyy-MM-dd HH:mm:ss','yyyy-MM-dd',
        'yyyy/MM/dd HH:mm:ss',
        'M/d/yyyy h:mm:ss tt','MM/dd/yyyy HH:mm:ss','M/d/yyyy'
    )
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    foreach ($f in $fmts) {
        try { return [datetime]::ParseExact($Text.Trim(), $f, $inv) } catch {}
    }
    try { return [datetime]::Parse($Text.Trim()) } catch {}
    return $null
}

function Finding-Timestamps {
    # Walk a finding's metadata; return ordered list of @{ Key=$k; Dt=$dt }
    # preferring TIMESTAMP_KEYS order. Mirrors visual_companion.py :: _finding_timestamps.
    param([hashtable]$Finding)
    $out = [System.Collections.Generic.List[hashtable]]::new()
    if (-not $Finding.Metadata) { return $out }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($key in $script:TIMESTAMP_KEYS) {
        if (-not $Finding.Metadata.ContainsKey($key)) { continue }
        $val = $Finding.Metadata[$key]
        if ($null -eq $val -or $val -eq '' -or $val -eq 'unknown') { continue }
        $dt = if ($val -is [datetime]) { $val } else { Try-Parse-Dt ([string]$val) }
        if ($null -eq $dt) { continue }
        $sig = $dt.ToString('o')
        if (-not $seen.Add($sig)) { continue }
        [void]$out.Add(@{ Key = $key; Dt = $dt })
    }
    return $out
}

# ============================================================================
# ID + cross-link key generation
# ============================================================================

function Make-Id {
    param([string]$Base, [System.Collections.Generic.HashSet[string]]$Used)
    $candidate = $Base; $i = 2
    while ($Used.Contains($candidate)) { $candidate = "${Base}-${i}"; $i++ }
    [void]$Used.Add($candidate)
    return $candidate
}

function Finding-Id {
    param([hashtable]$Finding, [System.Collections.Generic.HashSet[string]]$Used)
    $cat = Slug $Finding.Category 16
    $pat = ''
    if ($Finding.Metadata -and $Finding.Metadata.ContainsKey('Pattern')) { $pat = [string]$Finding.Metadata['Pattern'] }
    if ($pat) {
        $short = Slug $pat 16
    } else {
        $base = if ($Finding.Source) { [System.IO.Path]::GetFileName($Finding.Source) } else { '' }
        $short = Slug $base 16
    }
    return (Make-Id "f-$cat-$short" $Used)
}

function Process-Id {
    param([hashtable]$Proc, [System.Collections.Generic.HashSet[string]]$Used)
    return (Make-Id ("proc-" + (Slug $Proc.Name 24)) $Used)
}

function Service-Id {
    param([hashtable]$Svc, [System.Collections.Generic.HashSet[string]]$Used)
    return (Make-Id ("svc-" + (Slug $Svc.Name 24)) $Used)
}

function Data-Keys-For-Finding {
    param([hashtable]$Finding)
    $keys = [System.Collections.Generic.List[string]]::new()
    if ($Finding.Metadata) {
        foreach ($k in 'Pattern','FileName','ModuleName','DeviceName','ProcessName','ServiceName','Value') {
            if ($Finding.Metadata.ContainsKey($k) -and $Finding.Metadata[$k]) {
                [void]$keys.Add([string]$Finding.Metadata[$k])
            }
        }
    }
    if ($Finding.Source) { [void]$keys.Add([System.IO.Path]::GetFileName($Finding.Source)) }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($t in $keys) { if ($t) { [void]$set.Add($t) } }
    return (($set | Sort-Object) -join ' ')
}

function Data-Keys-For-Proc {
    param([hashtable]$Proc)
    $keys = @($Proc.Name)
    if ($Proc.Pattern) { $keys += $Proc.Pattern }
    if ($Proc.ExecutablePath) { $keys += [System.IO.Path]::GetFileName($Proc.ExecutablePath) }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($t in $keys) { if ($t) { [void]$set.Add($t) } }
    return (($set | Sort-Object) -join ' ')
}

function Data-Keys-For-Svc {
    param([hashtable]$Svc)
    $keys = @($Svc.Name)
    if ($Svc.Pattern) { $keys += $Svc.Pattern }
    if ($Svc.DisplayName) { $keys += $Svc.DisplayName }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($t in $keys) { if ($t) { [void]$set.Add($t) } }
    return (($set | Sort-Object) -join ' ')
}

# ============================================================================
# PARSER — read AlibiReport_*.txt / AlibiRigReport_*.txt
# ============================================================================

function Parse-FormatTableBlock {
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
        $name = ''
        if ($s -lt $header.Length) {
            $eh = [math]::Min($e, $header.Length); $name = $header.Substring($s, $eh - $s).Trim()
        }
        [void]$cols.Add(@{ Start = $s; End = $e; Name = $name })
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

function Parse-AlibiReport {
    param([string]$Path)

    $raw = Get-Content $Path -Raw -Encoding UTF8
    $raw = $raw -replace "^\xEF\xBB\xBF", ''
    $lines = $raw -split "`r?`n"

    $ctx = @{
        Generated = ''
        Hostname  = ''
        Username  = ''
        Admin     = ''
        Verdict   = ''
        Findings  = [System.Collections.Generic.List[hashtable]]::new()
        Processes = [System.Collections.Generic.List[hashtable]]::new()
        Services  = [System.Collections.Generic.List[hashtable]]::new()
        Limitations = [System.Collections.Generic.List[string]]::new()
    }

    # ---- Header ----
    $headerWindow = [math]::Min($lines.Count - 1, 40)
    for ($i = 0; $i -le $headerWindow; $i++) {
        $l = $lines[$i]
        if ($l -match '^\s*Generated:\s*(.+)$')  { $ctx.Generated = $matches[1].Trim() }
        if ($l -match '^\s*Hostname:\s*(.+)$')   { $ctx.Hostname  = $matches[1].Trim() }
        if ($l -match '^\s*Username:\s*(.+)$')   { $ctx.Username  = $matches[1].Trim() }
        if ($l -match '^\s*Admin mode:\s*(.+)$') { $ctx.Admin     = $matches[1].Trim() }
        if ($l -match '^\s*VERDICT:\s*(.+)$')    { $ctx.Verdict   = $matches[1].Trim() }
        if (-not $ctx.Verdict -and $l -match '^\s*Verdict:\s*(.+)$') { $ctx.Verdict = $matches[1].Trim() }
    }

    # ---- Section locations ----
    $idxSec1 = $idxSec2 = $idxSec3 = $idxLimit = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if     ($lines[$i] -match 'SECTION 1 OF 3') { $idxSec1 = $i }
        elseif ($lines[$i] -match 'SECTION 2 OF 3') { $idxSec2 = $i }
        elseif ($lines[$i] -match 'SECTION 3 OF 3') { $idxSec3 = $i }
        elseif ($lines[$i] -match 'COVERAGE LIMITATIONS') { $idxLimit = $i }
    }

    # ---- Findings ----
    $current = $null
    $sec1End = if ($idxSec2 -gt 0) { $idxSec2 } else { $lines.Count }
    if ($idxSec1 -ge 0) {
        for ($i = $idxSec1; $i -lt $sec1End; $i++) {
            $line = $lines[$i]
            if ($line -match '^\s*\[(HIGH|MEDIUM|WARN|INFO)(?:/([a-z-]+))?\]\s+\[([^\]]+)\]\s+(.*)$') {
                if ($current) { [void]$ctx.Findings.Add($current) }
                $current = @{
                    Severity = $matches[1]
                    Kind     = if ($matches[2]) { $matches[2] } else { 'other' }
                    Category = $matches[3]
                    Detail   = $matches[4].Trim()
                    Source   = ''
                    Metadata = @{}
                }
                continue
            }
            if (-not $current) { continue }
            if ($line -match '^\s*Source:\s*(.+)$') { $current.Source = $matches[1].Trim(); continue }
            if ($line -match '^\s{6,}([A-Za-z][A-Za-z0-9_]*):\s*(.*)$') {
                $current.Metadata[$matches[1]] = $matches[2].Trim()
            }
        }
        if ($current) { [void]$ctx.Findings.Add($current) }
    }

    # ---- Processes (Section 2) ----
    if ($idxSec2 -gt 0 -and $idxSec3 -gt $idxSec2) {
        $procRows = Parse-FormatTableBlock ($lines[$idxSec2..($idxSec3 - 1)])
        foreach ($p in $procRows) {
            [void]$ctx.Processes.Add(@{
                Name            = $p.Name
                ProcessId       = $p.ProcessId
                Started         = $p.Started
                ExecutablePath  = $p.ExecutablePath
                CommandLine     = $p.CommandLine
                Score           = ''  # set in Score-Items
                Reason          = ''
                Pattern         = ''
                Kind            = 'other'
            })
        }
    }

    # ---- Services (Section 3) ----
    if ($idxSec3 -gt 0) {
        $endIdx = if ($idxLimit -gt $idxSec3) { $idxLimit } else { $lines.Count }
        $svcRows = Parse-FormatTableBlock ($lines[$idxSec3..($endIdx - 1)])
        foreach ($s in $svcRows) {
            [void]$ctx.Services.Add(@{
                Name        = $s.Name
                DisplayName = $s.DisplayName
                State       = $s.State
                StartMode   = $s.StartMode
                PathName    = $s.PathName
                Score       = ''
                Reason      = ''
                Pattern     = ''
                Kind        = 'other'
            })
        }
    }

    # ---- Coverage limitations (after section 3) ----
    if ($idxLimit -gt 0) {
        for ($i = $idxLimit + 1; $i -lt $lines.Count; $i++) {
            $line = $lines[$i].Trim()
            if (-not $line) { continue }
            if ($line -match '^=') { continue }
            if ($line -match '^COVERAGE LIMITATIONS') { continue }
            if ($line -match '^\d+\.\s+(.+)$' -or $line -match '^[-•]\s+(.+)$') {
                [void]$ctx.Limitations.Add($matches[1].Trim())
            } elseif ($ctx.Limitations.Count -gt 0 -and $line.Length -gt 0) {
                # continuation line — append
                $last = $ctx.Limitations[$ctx.Limitations.Count - 1]
                $ctx.Limitations[$ctx.Limitations.Count - 1] = "$last $line"
            }
        }
    }

    return $ctx
}

# ============================================================================
# SCORING — produces Score / Reason / Pattern / Kind on processes & services
# ============================================================================
# Keyword arrays are MIRRORED from scanner/forensic-common.ps1. They live here
# (not in the parser output) because the visual companion historically did its
# own scoring; keeping that local scoring intact means a reviewer reading the
# HTML doesn't need to trust the source .txt's category labels alone.

$script:Keywords_High_PC = @(
    # COD brands
    'engineowning','engine owning','phantomoverlay','phantom overlay','lavicheats','lavi cheats',
    'skycheats','sky cheats','iwantcheats','i want cheats','x22cheats','x22 cheats','golden gun',
    'tateware','gcaimx','hdcheat','securecheats','overlord spoofer','zhexcheats','zhex cheats',
    # Spoofers
    'sync spoofer','syncspoofer','tracex','slothytech','pokespoof','overlord.exe','overlord_',
    'hidhide','hid hide','hidhideclient','hidhidecli','hidhidedrv',
    # Feature names
    'aimbot','wallhack','wall_hack','wall-hack','triggerbot','trigger_bot','norecoil','no-recoil','no_recoil',
    'hwidspoofer','hwid_spoof','hwid-spoof','hwidchanger','macspoof','mac_spoof',
    # Input devices
    'xim manager','ximmanager','xim apex','xim matrix','xim4','cronus','cronuszen','zen studio',
    'gpcscript','cronusmax','reasnow','reasnow s1','kmbox','km-box','km_box','titan two','titan.two',
    'gtuner','consoletuner','rewasd','rewasdengine','rewasd engine','rewasd.exe',
    # DMA
    'pcileech','pcileech-fpga','pcileech_fpga','pcileech_squirrel','pcileech_enigma','pcileech_zdma',
    'pcileech_screamer','pcileech_leetdma','pcileech_captaindma','pcileech_hackdma','pcileech_lurker',
    'pcileech_mvp','pcileech_macku','_top.bin',
    # Game-specific
    'neverlose','memesense','fatality.win','primordial.cc','skeet.cc','gamesense.pub','onetap','aimware','axion-cs2',
    'kernaim','cosmocheats apex','apex_hacksuite',
    'phantom eft','cheatvault eft','ownage software','ownage_eft',
    'cobracheat','cobra rust','atomic rust','cheater.ninja','cobrasn',
    'hyperforcecheats','cheatvault r6',
    'marvel maxim','elocarry','elocarry rivals',
    # AI vision PC aimbots
    'aimmy','sunone_aimbot','rootkit_aimbot','aimahead','zelesisneo',
    'reflex_aimbot','aimi_yolov3','yolov8_aimbot','aim_bot_yolo','unibot',
    'ardoras','embedded_aim_assist','csmacro'
)

$script:Keywords_Medium_PC = @(
    'vivado','xilinx vivado','arbor','dma-cfw','dma_cfw',
    'bleachbit','privazer','rbcleaner','cheatengine','cheat engine','processhacker','process hacker',
    'ollydbg','x64dbg','x32dbg','reclass','reclass.net','ida.exe','ida64.exe','ida pro',
    'hping','hping3','masscan','zmap','ostinato','iperf3','tshark',
    'midnight cs2','predator cs2','anyx.gg','eucheats','siegex',
    'rainbowsixcheats','wh-satano','proofcore','chamscheats',
    'deprimereshop','sternclient.biz','hackvshack','madchad.net',
    'gulfcheats','moddingassociation'
)

$script:Input_Keywords = @(
    'xim manager','ximmanager','xim apex','xim matrix','xim4','cronus','cronuszen','zen studio',
    'gpcscript','cronusmax','reasnow','reasnow s1','kmbox','km-box','km_box','titan two','titan.two',
    'gtuner','consoletuner','rewasd','rewasdengine','rewasd engine','rewasd.exe'
)

$script:Capture_Keywords = @(
    'elgato game capture','elgato 4k capture','elgato_gamecapture','gamecapture',
    'avermedia','recentral','rec central','obs studio','obs-studio','obs64','obs32',
    'streamlabs','streamlabs obs','xsplit','x-split','magewell',
    'vigembus','vigem bus','vigem-bus','vigemclient','vjoy','v-joy',
    'scptoolkit','scp toolkit','scp-toolkit','ds4windows','ds4 windows'
)

$script:KnownGood = @(
    'microsoft','windows','onedrive','teams','office','edgewebview','msedge',
    'google','chrome','update','slack','discord','zoom','signal','spotify',
    'dropbox','adobe','nvidia','amd','intel','realtek','razer','logitech',
    'corsair','steelseries','dell','hp','lenovo','asus','asustek','msi',
    'steam','epic','battle.net','riot','origin','ubisoft','rockstar',
    'github','vscode','code.exe','jetbrains','notion','postman','docker',
    'python','node','npm','git','antigravity'
)

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
    foreach ($g in $script:KnownGood) {
        if ($lc -match [regex]::Escape($g)) { return $true }
    }
    return $false
}

function Classify-PathRisk {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'unknown' }
    $p = $Path.ToLower().Trim('"').Trim()
    if ($p -match '^([^"]+\.exe)') { $p = $matches[1] }
    if ($p -match '^c:\\windows\\system32')      { return 'standard' }
    if ($p -match '^c:\\windows\\syswow64')      { return 'standard' }
    if ($p -match '^c:\\windows\\systemapps')    { return 'standard' }
    if ($p -match '^c:\\windows\\microsoft\.net'){ return 'standard' }
    if ($p -match '^c:\\windows\\servicing')     { return 'standard' }
    if ($p -match '^c:\\windows\\')              { return 'standard' }
    if ($p -match '^c:\\program files \(x86\)\\'){ return 'typical' }
    if ($p -match '^c:\\program files\\')        { return 'typical' }
    if ($p -match '^c:\\programdata\\')          { return 'user-writable' }
    if ($p -match '\\appdata\\local\\')          { return 'user-writable' }
    if ($p -match '\\appdata\\roaming\\')        { return 'user-writable' }
    if ($p -match '\\appdata\\locallow\\')       { return 'user-writable' }
    if ($p -match '\\temp\\')                    { return 'user-writable' }
    if ($p -match '^c:\\users\\')                { return 'user-writable' }
    return 'unknown'
}

function Score-Item {
    param([string]$Name, [string]$Path, [string]$Extra = '')
    $combined = "$Name $Path $Extra"
    $hit = Match-Keyword $combined $script:Keywords_High_PC
    if ($hit) {
        $kind = if (Match-Keyword $combined $script:Input_Keywords) { 'input' } else { 'cheat' }
        return @{ Score='HIGH'; Reason="matches '$hit' keyword"; Pattern=$hit; Kind=$kind }
    }
    $hit = Match-Keyword $combined $script:Keywords_Medium_PC
    if ($hit) {
        return @{ Score='MEDIUM'; Reason="matches '$hit' (dual-use tool)"; Pattern=$hit; Kind='dual-use' }
    }
    # Capture/HID emulation — MEDIUM (per console-mode rubric); PC mode still
    # surfaces them at MEDIUM as informational.
    $hit = Match-Keyword $combined $script:Capture_Keywords
    if ($hit) {
        return @{ Score='MEDIUM'; Reason="matches '$hit' (capture/HID-emulation stack)"; Pattern=$hit; Kind='dual-use' }
    }
    $bucket = Classify-PathRisk $Path
    if ($bucket -eq 'user-writable') {
        if (Match-Allowlist "$Path $Name") {
            return @{ Score='CLEAN'; Reason='user-writable location but known-good vendor'; Pattern=''; Kind='other' }
        }
        return @{ Score='MEDIUM'; Reason='runs from user-writable location, no allowlist match'; Pattern=''; Kind='other' }
    }
    if ($bucket -eq 'unknown') { return @{ Score='LOW'; Reason='image path not recorded or non-standard'; Pattern=''; Kind='other' } }
    if ($bucket -eq 'typical') { return @{ Score='LOW'; Reason='runs from Program Files or similar'; Pattern=''; Kind='other' } }
    return @{ Score='CLEAN'; Reason='standard system location, no keyword match'; Pattern=''; Kind='other' }
}

function Score-Items {
    param($Ctx)
    foreach ($p in $Ctx.Processes) {
        $s = Score-Item -Name $p.Name -Path $p.ExecutablePath -Extra $p.CommandLine
        $p.Score = $s.Score; $p.Reason = $s.Reason; $p.Pattern = $s.Pattern; $p.Kind = $s.Kind
    }
    foreach ($s in $Ctx.Services) {
        $sc = Score-Item -Name $s.Name -Path $s.PathName -Extra $s.DisplayName
        $s.Score = $sc.Score; $s.Reason = $sc.Reason; $s.Pattern = $sc.Pattern; $s.Kind = $sc.Kind
    }
}

# ============================================================================
# RENDER — sections in document order. Mirrors visual_companion.py one-to-one.
# ============================================================================

function Render-DocBar {
    param($Ctx, [bool]$LolDbUsed)
    $net = if ($LolDbUsed) { '1 outbound call to loldrivers.io (opt-in)' } else { 'no network calls' }
    $hostHtml = Esc-Html $Ctx.Hostname
    $scanIso  = Esc-Html (Now-Iso)
    $netHtml  = Esc-Html $net
    return ('<div class="docbar">' +
        "<span class=`"tool`"><b>alibi</b> $($script:ALIBI_VERSION) &middot; powershell &middot; consolidated report</span>" +
        "<span>scan <b>$hostHtml</b> &middot; $scanIso &middot; read-only &middot; $netHtml</span>" +
        '</div>')
}

function Render-Verdict {
    param($Ctx, [string]$State, [string]$SubText, [string]$ModeLabel,
          $RecentFindings, $ArchivedFindings, $Processes, $Services, $NamedItems)

    $host_  = Esc-Html $Ctx.Hostname
    $user   = Esc-Html $Ctx.Username
    $admin  = Esc-Html $Ctx.Admin
    $osStr  = Esc-Html ([System.Environment]::OSVersion.VersionString)
    $scanIso = Esc-Html $Ctx.Generated

    $sevCount = @{ HIGH=0; MEDIUM=0; WARN=0; INFO=0 }
    foreach ($f in $RecentFindings) { if ($sevCount.ContainsKey($f.Severity)) { $sevCount[$f.Severity]++ } }

    $kindCount = @{ cheat=0; input=0; 'dual-use'=0; other=0 }
    foreach ($f in $RecentFindings) {
        $k = if ($f.Kind) { $f.Kind } else { 'other' }
        if ($kindCount.ContainsKey($k)) { $kindCount[$k]++ }
    }
    foreach ($p in $Processes) {
        if ($p.Score -in 'HIGH','MEDIUM' -and $kindCount.ContainsKey($p.Kind)) { $kindCount[$p.Kind]++ }
    }
    foreach ($s in $Services) {
        if ($s.Score -in 'HIGH','MEDIUM' -and $kindCount.ContainsKey($s.Kind)) { $kindCount[$s.Kind]++ }
    }

    $segs = ''
    foreach ($pair in @(@('HIGH','b-hi'), @('MEDIUM','b-md'), @('WARN','b-wn'), @('INFO','b-info'))) {
        if ($sevCount[$pair[0]] -gt 0) {
            $segs += "<span class=`"$($pair[1])`" style=`"flex:$($sevCount[$pair[0]])`"></span>"
        }
    }
    if (-not $segs) { $segs = '<span class="b-info" style="flex:1; opacity:0.3"></span>' }

    $readoutRows = (
        "<span class=`"dot hi`"></span><span class=`"l`">HIGH</span><span class=`"n`">$($sevCount.HIGH)</span><span class=`"note`">verdict-driving</span>" +
        "<span class=`"dot md`"></span><span class=`"l`">MEDIUM</span><span class=`"n`">$($sevCount.MEDIUM)</span><span class=`"note`">dual-use signals</span>" +
        "<span class=`"dot wn`"></span><span class=`"l`">WARN</span><span class=`"n`">$($sevCount.WARN)</span><span class=`"note`">access denied</span>" +
        "<span class=`"dot info`"></span><span class=`"l`">INFO</span><span class=`"n`">$($sevCount.INFO)</span><span class=`"note`">scan summary</span>"
    )

    $archivedCount = $ArchivedFindings.Count
    $readoutFoot = (
        "<span>cheat-kind&nbsp;<b>$($kindCount.cheat)</b></span>" +
        "<span>input-kind&nbsp;<b>$($kindCount.input)</b></span>" +
        "<span>dual-use&nbsp;<b>$($kindCount['dual-use'])</b></span>" +
        "<span>archived&nbsp;<b>$archivedCount</b> <span style=`"color:var(--ink-5)`">(off-verdict)</span></span>"
    )

    $readoutClass = 'readout'
    $totalSev = 0; foreach ($k in 'HIGH','MEDIUM','WARN','INFO') { $totalSev += $sevCount[$k] }
    if ($State -eq 'green' -and $totalSev -eq 0) { $readoutClass = 'readout is-empty' }

    $subHtml = if ($SubText) { "<p class=`"v-sub`">$(Esc-Html $SubText)</p>" } else { '' }

    # Named items block
    $namedBlock = ''
    $main = $NamedItems['main']
    $also = $NamedItems['also']
    if ($main.Count -gt 0 -or $also.Count -gt 0) {
        $namedRows = ''
        foreach ($item in $main) {
            $sev = Esc-Html $item.Sev
            $tgt = Esc-Html $item.Target
            $cat = Esc-Html $item.Category
            $namedRows += "<li data-sev=`"$sev`" data-target=`"$tgt`"><span class=`"dot`"></span><span class=`"cat`">$cat</span><span class=`"text`">$($item.Html)</span><span class=`"arrow`">&uarr;</span></li>"
        }
        $alsoBlock = ''
        if ($also.Count -gt 0) {
            $alsoRows = ''
            foreach ($item in $also) {
                $cat = Esc-Html $item.Category
                $alsoRows += "<li><span class=`"dot`"></span><span class=`"cat`">$cat</span><span class=`"text`">$($item.Html)</span></li>"
            }
            $alsoBlock = "<div class=`"named-also`"><h4>Also detected &middot; input devices (separate category)</h4><ul>$alsoRows</ul></div>"
        }
        $namedBlock = (
            '<div class="named">' +
            '<div class="named-head">' +
            "<h3>Why this verdict &middot; $($main.Count) named items</h3>" +
            '<span class="rule"></span>' +
            '<span class="hint">click an item to jump &amp; pin its finding card &darr;</span>' +
            '</div>' +
            "<ul class=`"named-grid`" id=`"named-list`">$namedRows</ul>" +
            $alsoBlock +
            '</div>'
        )
    }

    $verdictEsc = Esc-Html $Ctx.Verdict
    $modeEsc    = Esc-Html $ModeLabel

    return (
        "<div class=`"verdict`" data-state=`"$State`">" +
        '<div class="verdict-grid">' +
        '<div>' +
        '<div class="v-label">Verdict</div>' +
        "<h1 class=`"v-text`">$verdictEsc</h1>" +
        $subHtml +
        '<dl class="v-meta">' +
        "<dt>host</dt><dd>$host_</dd>" +
        "<dt>user</dt><dd>$user</dd>" +
        "<dt>os</dt><dd>$osStr</dd>" +
        "<dt>admin</dt><dd>$admin</dd>" +
        "<dt>scan</dt><dd>$scanIso &middot; $modeEsc</dd>" +
        '</dl></div>' +
        "<div class=`"$readoutClass`">" +
        '<div class="v-label">Recent findings &middot; last 180d</div>' +
        "<div class=`"readout-bar`">$segs</div>" +
        "<div class=`"readout-rows`">$readoutRows</div>" +
        "<div class=`"readout-foot`">$readoutFoot</div>" +
        '</div></div>' +
        $namedBlock +
        '</div>'
    )
}

# Category priority for picking the representative finding when a pattern is
# corroborated by N scanners. Lower number = better representative.
# Mirrors python/src/alibi/visual_companion.py :: _NAMED_CAT_PRIORITY.
$script:NAMED_CAT_PRIORITY = @{
    'InstalledSoftware' = 0; 'Uninstall' = 0; 'LoLDriver' = 0; 'KnownHash' = 0
    'Driver' = 1
    'Prefetch' = 2; 'BAM' = 2; 'MUICache' = 2; 'UserAssist' = 2
    'ShimCache' = 3; 'Amcache' = 3
    'USBHistory' = 4; 'RecentFiles' = 4; 'ApplicationData' = 4
    'ProcessModule' = 4; 'DLLInjection' = 4; 'LuaScript' = 4; 'ObscuredName' = 4
    'Process' = 5; 'Service' = 6
}

function Build-NamedItems {
    # Return @{ main = [...]; also = [...] } for the "Why this verdict" block.
    # Mirrors python/src/alibi/visual_companion.py :: _build_named_items.
    #
    # Dedupe: one row per Pattern (lowercased). A pattern corroborated by N
    # scanners shows once, with the chip suffix "+(N-1)".
    #
    # Routing: input-kind findings only get split into "also" when the verdict
    # is CHEATS DETECTED. For INPUT DEVICES DETECTED / MITM CHEAT STACK
    # DETECTED / CAPTURE STACK PRESENT, those findings ARE the verdict, so
    # they belong in "main" — otherwise the header reads "0 named items"
    # while 8 items render below.
    param(
        $Recent, $Processes, $Services,
        [hashtable]$FindingIds, [hashtable]$ProcessIds, [hashtable]$ServiceIds,
        [string]$Verdict
    )

    $sepInput = ($Verdict -eq 'CHEATS DETECTED')

    # Stage 1: gather every HIGH indicator as a flat candidate list.
    $cands = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($f in $Recent) {
        if ($f.Severity -ne 'HIGH') { continue }
        if ($f.Metadata.RecencyClass -eq 'historical') { continue }
        $key = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($f)
        $target = $FindingIds[$key]
        if (-not $target) { continue }
        $pat = if ($f.Metadata.ContainsKey('Pattern')) { ([string]$f.Metadata['Pattern']).Trim() } else { '' }
        $patKey = if ($pat) { $pat.ToLower() } else { "_d:$($f.Detail.ToLower())" }
        $detailShort = $f.Detail
        if ($pat) {
            $prefix = "[$pat] "
            if ($detailShort.StartsWith($prefix)) { $detailShort = $detailShort.Substring($prefix.Length) }
        }
        if ($detailShort.Length -gt 80) { $detailShort = $detailShort.Substring(0,77) + '...' }
        $catPri = if ($script:NAMED_CAT_PRIORITY.ContainsKey($f.Category)) { $script:NAMED_CAT_PRIORITY[$f.Category] } else { 9 }
        # Precompute conditional values; PS parser rejects `if` expressions as
        # bare hashtable values (treats `if` as a command name).
        $kindVal = if ($f.Kind) { $f.Kind } else { 'other' }
        [void]$cands.Add(@{
            PatternKey = $patKey; Pattern = $pat; Category = $f.Category
            Kind = $kindVal
            Target = $target; Detail = $detailShort
            CatPri = $catPri
        })
    }

    foreach ($p in $Processes) {
        if ($p.Score -ne 'HIGH') { continue }
        $key = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($p)
        $target = $ProcessIds[$key]
        $pat = if ($p.Pattern) { ([string]$p.Pattern).Trim() } else { '' }
        $patKey = if ($pat) { $pat.ToLower() } else { "_p:$($p.Name.ToLower())" }
        $pidStr = if ($p.ProcessId) { $p.ProcessId } else { '?' }
        $patternVal = if ($pat) { $pat } else { $p.Name }
        $kindVal = if ($p.Kind) { $p.Kind } else { 'other' }
        [void]$cands.Add(@{
            PatternKey = $patKey
            Pattern = $patternVal
            Category = 'Process'; Kind = $kindVal
            Target = $target; Detail = "(PID $pidStr) running"
            CatPri = 5
        })
    }

    foreach ($s in $Services) {
        if ($s.Score -ne 'HIGH') { continue }
        $key = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($s)
        $target = $ServiceIds[$key]
        $pat = if ($s.Pattern) { ([string]$s.Pattern).Trim() } else { '' }
        $patKey = if ($pat) { $pat.ToLower() } else { "_s:$($s.Name.ToLower())" }
        $st = if ($s.State) { $s.State } else { '?' }
        $patternVal = if ($pat) { $pat } else { $s.Name }
        $kindVal = if ($s.Kind) { $s.Kind } else { 'other' }
        [void]$cands.Add(@{
            PatternKey = $patKey
            Pattern = $patternVal
            Category = 'Service'; Kind = $kindVal
            Target = $target; Detail = "service ($st)"
            CatPri = 6
        })
    }

    # Stage 2: group by PatternKey, preserving first-seen order.
    $groups = [ordered]@{}
    foreach ($c in $cands) {
        if (-not $groups.Contains($c.PatternKey)) {
            $groups[$c.PatternKey] = [System.Collections.Generic.List[hashtable]]::new()
        }
        [void]$groups[$c.PatternKey].Add($c)
    }

    # Stage 3: for each group, pick representative + build the row.
    $main = [System.Collections.Generic.List[hashtable]]::new()
    $also = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($k in $groups.Keys) {
        $group = $groups[$k]
        $rep = @($group | Sort-Object @{ E = { $_.CatPri } }, @{ E = { $_.Category.ToLower() } })[0]
        $sourcesN = $group.Count
        $catLabel = if ($sourcesN -gt 1) { "$($rep.Category) +$($sourcesN - 1)" } else { $rep.Category }
        $textHtml = if ($rep.Pattern) {
            "<b>$(Esc-Html $rep.Pattern)</b> &mdash; $(Esc-Html $rep.Detail)"
        } else {
            Esc-Html $rep.Detail
        }
        $rec = @{
            Sev = 'HIGH'; Target = $rep.Target; Category = $catLabel
            Html = $textHtml; Kind = $rep.Kind; SourcesN = $sourcesN
        }
        if ($sepInput -and $rec.Kind -eq 'input') { [void]$also.Add($rec) }
        else { [void]$main.Add($rec) }
    }

    return @{ main = $main; also = $also }
}

function Render-Timeline {
    param([string]$State, $RecentFindings, $ArchivedFindings, [hashtable]$FindingIds)

    $now = Get-Date

    # ---- (a) Build live-zone dot records ----
    $liveDots    = [System.Collections.Generic.List[hashtable]]::new()
    $archivedRec = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($f in $RecentFindings) {
        $key = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($f)
        $target = $FindingIds[$key]
        $stamps = Finding-Timestamps $f
        foreach ($ts in $stamps) {
            if ($ts.Key -eq 'MostRecentTimestamp') { continue }
            $ageDays = [int]($now - $ts.Dt).TotalDays
            if ($ageDays -lt 0) { $ageDays = 0 }
            if ($ageDays -ge 180) { continue }
            $x = X-Live $ageDays
            $lane = if ($script:LANE_Y.ContainsKey($f.Severity)) { $script:LANE_Y[$f.Severity] } else { $script:LANE_Y.INFO }
            $labelAge = if ($ageDays -eq 0) { 'today' } else { "-${ageDays}d" }
            $whenLabel = "$(Iso-Date $ts.Dt) ($labelAge)"
            # Literal middle-dot; "&middot;" would double-escape via Esc-Html below.
            $detail = "$($f.Detail) " + [char]0x00B7 + " $($ts.Key)"
            [void]$liveDots.Add(@{
                X = $x; Y = [double]$lane; R = $script:R_MAX
                Target = $target; Sev = $f.Severity; Cat = $f.Category
                WhenLabel = $whenLabel; Detail = $detail
                IsFresh = ($ageDays -le $script:FRESH_MAX_DAYS)
            })
        }
    }

    foreach ($f in $ArchivedFindings) {
        $stamps = Finding-Timestamps $f
        foreach ($ts in $stamps) {
            if ($ts.Key -eq 'MostRecentTimestamp') { continue }
            [void]$archivedRec.Add(@{ Finding = $f; Dt = $ts.Dt })
            break
        }
    }

    # ---- (b) Collision stacking per lane ----
    $byLane = @{}
    $sortedLive = @($liveDots | Sort-Object -Property X -Descending)
    foreach ($d in $sortedLive) {
        $laneKey = [string]$d.Y
        if (-not $byLane.ContainsKey($laneKey)) { $byLane[$laneKey] = [System.Collections.Generic.List[hashtable]]::new() }
        $stack = $byLane[$laneKey]
        $k = 0
        foreach ($p in $stack) { if ([math]::Abs($p.X - $d.X) -lt $script:STACK_DX) { $k++ } }
        $d.Y = $d.Y - $k * $script:STACK_DY
        $d.R = [math]::Max($script:R_MIN, $script:R_MAX - $k * $script:R_STEP)
        [void]$stack.Add($d)
    }

    # ---- (c) Stats strip ----
    function _CountWithin($findings, $days, $now) {
        $cutoff = $now.AddDays(-$days)
        $n = 0
        foreach ($f in $findings) {
            $stamps = Finding-Timestamps $f
            foreach ($ts in $stamps) {
                if ($ts.Dt -ge $cutoff) { $n++; break }
            }
        }
        return $n
    }
    $s7   = _CountWithin $RecentFindings 7   $now
    $s30  = _CountWithin $RecentFindings 30  $now
    $s180 = _CountWithin $RecentFindings 180 $now

    # ---- (d) Density wash + accent override ----
    $densityVar = $script:STATE_COLOUR_VAR[$State]
    $densityX = X-Live 7
    $densityW = $script:X_LIVE_RIGHT - $densityX
    $accentOverride = switch ($State) {
        'amber' { ' style="--accent: #f5b53a;"' }
        'green' { ' style="--accent: #4ade80;"' }
        default { '' }
    }

    # ---- (e) Axis ticks ----
    $ticks = @(
        @('today', [double]$script:X_LIVE_RIGHT),
        @('-1d',   (X-Live 1)),
        @('-3d',   (X-Live 3)),
        @('-1w',   (X-Live 7)),
        @('-2w',   (X-Live 14)),
        @('-1mo',  (X-Live 30)),
        @('-3mo',  (X-Live 90)),
        @('-6mo',  [double]$script:X_LIVE_LEFT)
    )
    $tickLines = ''
    $tickLabels = ''
    foreach ($t in $ticks) {
        $x = FmtCoord $t[1]
        $tickLines += "<line x1=`"$x`" x2=`"$x`" y1=`"20`" y2=`"170`" style=`"stroke: var(--rule-2); stroke-dasharray: 1 5;`"></line>"
        if ($t[0] -eq 'today') {
            $tickLabels += "<text x=`"$x`" y=`"184`" text-anchor=`"end`" class=`"abs`">today</text>"
        } else {
            $tickLabels += "<text x=`"$x`" y=`"184`" text-anchor=`"middle`">$($t[0])</text>"
        }
    }

    # ---- (f) Dots ----
    $dotSvg = ''
    foreach ($d in $liveDots) {
        $classes = @('dot', $d.Sev)
        if ($d.IsFresh) { $classes += 'is-fresh' }
        $cls = $classes -join ' '
        $r  = FmtCoord $d.R
        $cx = FmtCoord $d.X
        $cy = FmtCoord $d.Y
        $tgt = Esc-Html $d.Target
        $sev = Esc-Html $d.Sev
        $cat = Esc-Html $d.Cat
        $when = Esc-Html $d.WhenLabel
        $det = Esc-Html $d.Detail
        $dotSvg += "<circle class=`"$cls`" r=`"$r`" cx=`"$cx`" cy=`"$cy`" data-target=`"$tgt`" data-sev=`"$sev`" data-cat=`"$cat`" data-when=`"$when`" data-detail=`"$det`"></circle>"
    }
    $hasHigh = $false; foreach ($d in $liveDots) { if ($d.Sev -eq 'HIGH') { $hasHigh = $true; break } }
    if (-not $hasHigh) {
        $dotSvg += '<text x="708" y="54" text-anchor="middle" style="fill: var(--ink-5); font-family: ui-monospace, monospace; font-size: 10px; font-style: italic;">&mdash; no HIGH findings in any zone &mdash;</text>'
    }

    # ---- (g) Archive strip ----
    $archSorted = @($archivedRec | Sort-Object -Property @{ E = { ($now - $_.Dt).TotalDays } })
    $archiveSvg = ''
    for ($i = 0; $i -lt $archSorted.Count; $i++) {
        $x = $script:ARCH_RIGHT_EDGE - $i * 18
        if ($x -lt 48) { break }
        $rec = $archSorted[$i]
        $f = $rec.Finding
        $lane = if ($script:LANE_Y.ContainsKey($f.Severity)) { $script:LANE_Y[$f.Severity] } else { $script:LANE_Y.INFO }
        $ageDays = [int]($now - $rec.Dt).TotalDays
        $origSev = if ($f.Metadata.ContainsKey('OriginalSeverity')) { $f.Metadata['OriginalSeverity'] } else { $f.Severity }
        $sevAttr = Esc-Html $f.Severity
        $catAttr = Esc-Html "$($f.Category) (archived)"
        # Use literal middle-dot — passing "&middot;" through Esc-Html would double-escape.
        $whenAttr = Esc-Html ("$(Iso-Date $rec.Dt) (-${ageDays}d " + [char]0x00B7 + " was $origSev, demoted)")
        $detAttr = Esc-Html $f.Detail
        $shortAge = Short-Age $ageDays
        $archiveSvg += (
            '<g>' +
            "<circle class=`"dot $($f.Severity) archived stroked`" r=`"3.5`" cx=`"$x`" cy=`"$lane`" data-target=`"`" data-sev=`"$sevAttr`" data-cat=`"$catAttr`" data-when=`"$whenAttr`" data-detail=`"$detAttr`"></circle>" +
            "<text x=`"$x`" y=`"$($lane + 14)`" text-anchor=`"middle`" style=`"fill: var(--ink-5); font-family: ui-monospace, monospace; font-size: 9px;`">$shortAge</text>" +
            '</g>'
        )
    }

    $archiveCount = $archivedRec.Count
    $archiveLabel = if ($archiveCount -gt 0) { "archive &middot; $archiveCount" } else { 'archive &middot; &mdash; none &mdash;' }

    $hotClass = if ($s7 -gt 0) { 'tl-stat hot' } else { 'tl-stat' }
    $tlH = "<h3 class=`"tl-h`">Log-scale recency &middot; <span class=`"accent`">$($RecentFindings.Count) recent</span> + <span style=`"color: var(--ink-4)`">$($ArchivedFindings.Count) archived</span> findings</h3>"

    $dx = FmtCoord $densityX
    $dw = FmtCoord $densityW

    return (
        "<div class=`"tl-wrap`" id=`"timeline`"$accentOverride>" +
        '<div class="tl-head"><div class="tl-head-left">' +
        '<span class="tl-eyebrow">Forensic timeline</span>' + $tlH +
        '</div>' +
        '<div class="tl-stats">' +
        "<div class=`"$hotClass`"><span class=`"n`">$s7</span><span class=`"l`">in last 7 days</span></div>" +
        "<div class=`"tl-stat`"><span class=`"n`">$s30</span><span class=`"l`">in last 30 days</span></div>" +
        "<div class=`"tl-stat`"><span class=`"n`">$s180</span><span class=`"l`">in last 180 days</span></div>" +
        '</div></div>' +
        '<svg class="tl-svg" viewBox="0 0 1200 200" preserveAspectRatio="none" aria-label="log-scale timeline">' +
        "<rect x=`"$dx`" y=`"20`" width=`"$dw`" height=`"156`" fill=`"var($densityVar)`" opacity=`"0.06`"></rect>" +
        '<g>' +
        '<line class="lane-rule" x1="220" x2="1196" y1="50" y2="50"></line>' +
        '<line class="lane-rule" x1="220" x2="1196" y1="86" y2="86"></line>' +
        '<line class="lane-rule" x1="220" x2="1196" y1="118" y2="118"></line>' +
        '<line class="lane-rule" x1="220" x2="1196" y1="148" y2="148"></line>' +
        '</g><g>' +
        '<text class="band-label" x="1200" y="54">HIGH</text>' +
        '<text class="band-label" x="1200" y="90">MED</text>' +
        '<text class="band-label muted" x="1200" y="122">WARN</text>' +
        '<text class="band-label muted" x="1200" y="152">INFO</text>' +
        '</g>' +
        "<g class=`"axis-tick`">$tickLines$tickLabels</g>" +
        '<g class="today">' +
        '<line class="beam-glow" x1="1196" x2="1196" y1="20" y2="172"></line>' +
        '<line x1="1196" x2="1196" y1="20" y2="172"></line>' +
        '<circle class="now-dot" cx="1196" cy="20" r="3"></circle>' +
        '<circle class="pulse-ring" cx="1196" cy="20"></circle>' +
        '</g><g>' +
        '<line class="hover-line" id="tl-hover-line" x1="0" x2="0" y1="20" y2="172"></line>' +
        '<text class="hover-readout" id="tl-hover-text" x="0" y="14" text-anchor="middle"></text>' +
        '</g>' +
        '<defs>' +
        '<pattern id="foldhatch" patternUnits="userSpaceOnUse" width="6" height="6" patternTransform="rotate(45)">' +
        '<line x1="0" y1="0" x2="0" y2="6" stroke="var(--ink-5)" stroke-width="1.5" opacity="0.6"></line>' +
        '</pattern></defs>' +
        '<rect x="200" y="20" width="14" height="152" fill="url(#foldhatch)"></rect>' +
        '<line x1="200" y1="20" x2="200" y2="172" stroke="var(--ink-4)" stroke-width="1"></line>' +
        '<line x1="214" y1="20" x2="214" y2="172" stroke="var(--ink-4)" stroke-width="1"></line>' +
        "<text x=`"120`" y=`"14`" text-anchor=`"middle`" style=`"fill: var(--ink-3); font-family: ui-monospace, monospace; font-size: 10px; letter-spacing: 0.16em; text-transform: uppercase; font-weight: 700;`">$archiveLabel</text>" +
        '<g style="opacity: 0.6;">' +
        '<line class="lane-rule" x1="44" x2="196" y1="50" y2="50"></line>' +
        '<line class="lane-rule" x1="44" x2="196" y1="86" y2="86"></line>' +
        '<line class="lane-rule" x1="44" x2="196" y1="118" y2="118"></line>' +
        '<line class="lane-rule" x1="44" x2="196" y1="148" y2="148"></line>' +
        '</g>' +
        '<text x="44" y="184" text-anchor="start" class="abs">&gt; 180d</text>' +
        '<text x="122" y="184" text-anchor="middle" class="abs">log compressed &rarr;</text>' +
        $dotSvg + $archiveSvg +
        '</svg>' +
        '<div class="tl-tooltip" id="tl-tooltip"></div>' +
        '</div>'
    )
}

function Render-Lifecycle {
    # Per-keyword lifecycle ribbon. Mirrors visual_companion.py :: _render_lifecycle.
    # One horizontal track per Pattern; install date (InstallDate / FirstInstall)
    # renders as an open diamond, every other timestamp is a filled circle
    # coloured by severity. Complements the log-scale timeline by collapsing
    # "which tool, over what span" instead of "what severity, when".
    param($RecentFindings, $Processes, [hashtable]$FindingIds)

    $installKeys = @('InstallDate','FirstInstall')
    $tracks = @{}

    function _AddEvent($patLc, $display, [datetime]$dt, $kind, $sev, $target, [bool]$isInstall) {
        if (-not $tracks.ContainsKey($patLc)) {
            $tracks[$patLc] = @{ display = $display; events = [System.Collections.Generic.List[hashtable]]::new(); sev_rank = 99; sev = $sev }
        }
        $rank = switch ($sev) { 'HIGH' { 0 } 'MEDIUM' { 1 } 'WARN' { 2 } 'INFO' { 3 } default { 9 } }
        if ($rank -lt $tracks[$patLc].sev_rank) {
            $tracks[$patLc].sev_rank = $rank
            $tracks[$patLc].sev = $sev
        }
        [void]$tracks[$patLc].events.Add(@{
            dt = $dt; kind = $kind; sev = $sev; target = $target; is_install = $isInstall
        })
    }

    # Track-key fallback chain. Pattern is primary; AppData findings
    # expose Label, Installed-software findings expose DisplayName, USB
    # findings expose DeviceName. Walking this chain recovers per-tool
    # tracks (e.g. "Cronus Zen Studio", "XIM (other)") the v3.x renderer
    # plotted via the old `$m.Label` fallback.
    $trackKeyFallbacks = @('Label','DisplayName','DeviceName')

    foreach ($f in $RecentFindings) {
        if ($f.Severity -notin 'HIGH','MEDIUM') { continue }
        $pat = if ($f.Metadata.ContainsKey('Pattern')) { [string]$f.Metadata['Pattern'] } else { '' }
        $pat = $pat.Trim()
        if (-not $pat) {
            foreach ($k in $trackKeyFallbacks) {
                if ($f.Metadata.ContainsKey($k)) {
                    $v = ([string]$f.Metadata[$k]).Trim()
                    if ($v) { $pat = $v; break }
                }
            }
        }
        if (-not $pat) { continue }
        $patLc = $pat.ToLower()
        $key = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($f)
        $target = if ($FindingIds.ContainsKey($key)) { $FindingIds[$key] } else { '' }
        foreach ($ts in (Finding-Timestamps $f)) {
            if ($ts.Key -eq 'MostRecentTimestamp') { continue }
            _AddEvent $patLc $pat $ts.Dt $ts.Key $f.Severity $target ($installKeys -contains $ts.Key)
        }
    }

    foreach ($p in $Processes) {
        if ($p.Score -notin 'HIGH','MEDIUM') { continue }
        $pat = if ($p.Pattern) { [string]$p.Pattern } else { '' }
        $pat = $pat.Trim()
        if (-not $pat) { continue }
        $dt = Try-Parse-Dt ([string]$p.Started)
        if ($dt) {
            _AddEvent $pat.ToLower() $pat $dt 'process start' $p.Score '' $false
        }
    }

    if ($tracks.Count -eq 0) { return '' }

    # Sort: most severe first, then earliest activity.
    $sortedKeys = @($tracks.Keys | Sort-Object @{ E = { $tracks[$_].sev_rank } }, @{ E = { ($tracks[$_].events | ForEach-Object { $_.dt } | Sort-Object | Select-Object -First 1) } })

    $MAX_TRACKS = 8
    if ($sortedKeys.Count -gt $MAX_TRACKS) {
        $keep = $sortedKeys[0..($MAX_TRACKS - 2)]
        $mergedEvents = [System.Collections.Generic.List[hashtable]]::new()
        $mergedRank = 99; $mergedSev = 'MEDIUM'
        foreach ($k in $sortedKeys[($MAX_TRACKS - 1)..($sortedKeys.Count - 1)]) {
            foreach ($e in $tracks[$k].events) { [void]$mergedEvents.Add($e) }
            if ($tracks[$k].sev_rank -lt $mergedRank) {
                $mergedRank = $tracks[$k].sev_rank; $mergedSev = $tracks[$k].sev
            }
        }
        $tracks['__other__'] = @{ display = 'other'; events = $mergedEvents; sev_rank = $mergedRank; sev = $mergedSev }
        $sortedKeys = @($keep) + @('__other__')
    }

    # X-axis range
    $now = Get-Date
    $allDates = foreach ($k in $sortedKeys) { foreach ($e in $tracks[$k].events) { $e.dt } }
    $earliest = ($allDates | Sort-Object | Select-Object -First 1)
    $spanDays = [math]::Max(1, [int]($now - $earliest).TotalDays)
    $padDays = [math]::Max(7, $spanDays * 0.04)
    $xMin = $earliest.AddDays(-$padDays)
    $xMax = $now.AddDays($padDays * 0.5)
    $rangeSecs = ($xMax - $xMin).TotalSeconds
    if ($rangeSecs -le 0) { return '' }

    # SVG geometry
    $width = 1200; $leftPad = 180; $rightPad = 28
    $topPad = 44; $rowH = 36; $bottomPad = 38
    $plotW = $width - $leftPad - $rightPad
    $plotH = $sortedKeys.Count * $rowH
    $totalH = $topPad + $plotH + $bottomPad

    function _XFor([datetime]$dt) {
        return $leftPad + (($dt - $xMin).TotalSeconds / $rangeSecs) * $plotW
    }

    # Month gridlines
    $gridSvg = ''
    $cur = New-Object DateTime($xMin.Year, $xMin.Month, 1)
    if ($cur -lt $xMin) {
        $cur = if ($cur.Month -eq 12) { New-Object DateTime(($cur.Year + 1), 1, 1) } else { New-Object DateTime($cur.Year, ($cur.Month + 1), 1) }
    }
    while ($cur -le $xMax) {
        $x = FmtCoord (_XFor $cur)
        $y2 = $topPad + $plotH
        $gridSvg += "<line class=`"lc-axis-tick`" x1=`"$x`" x2=`"$x`" y1=`"$topPad`" y2=`"$y2`"></line>"
        $lbl = $cur.ToString("MMM ''yy", [System.Globalization.CultureInfo]::InvariantCulture).ToUpper()
        $yLbl = $topPad - 14
        $gridSvg += "<text class=`"lc-axis-label`" x=`"$x`" y=`"$yLbl`" text-anchor=`"middle`">$(Esc-Html $lbl)</text>"
        $cur = if ($cur.Month -eq 12) { New-Object DateTime(($cur.Year + 1), 1, 1) } else { New-Object DateTime($cur.Year, ($cur.Month + 1), 1) }
    }

    # Today beam
    $nowX = FmtCoord (_XFor $now)
    $yBeamTop = $topPad
    $yBeamBot = $topPad + $plotH
    $yLblTop = $topPad - 4
    $todaySvg = "<g class=`"lc-today`"><line x1=`"$nowX`" x2=`"$nowX`" y1=`"$yBeamTop`" y2=`"$yBeamBot`"></line><text x=`"$nowX`" y=`"$yLblTop`" text-anchor=`"end`">today</text></g>"

    # Tracks
    $trackSvg = ''
    $sevClass = @{ HIGH = 'hi'; MEDIUM = 'md' }
    for ($i = 0; $i -lt $sortedKeys.Count; $i++) {
        $k = $sortedKeys[$i]
        $t = $tracks[$k]
        $rowY = $topPad + $i * $rowH
        $cy = $rowY + $rowH / 2
        $cyStr = FmtCoord $cy
        $rightEdge = $leftPad + $plotW
        $trackSvg += "<line class=`"lc-lane-rule`" x1=`"$leftPad`" x2=`"$rightEdge`" y1=`"$cyStr`" y2=`"$cyStr`"></line>"
        $label = [string]$t.display
        if ($label.Length -gt 14) { $label = $label.Substring(0, 13) + '...' }
        $lblX = $leftPad - 12
        $lblY = FmtCoord ($cy + 4)
        $trackSvg += "<text class=`"lc-track-label`" x=`"$lblX`" y=`"$lblY`" text-anchor=`"end`">$(Esc-Html $label.ToUpper())</text>"
        foreach ($e in $t.events) {
            $x = _XFor $e.dt
            $xStr = FmtCoord $x
            $cls = if ($sevClass.ContainsKey($e.sev)) { $sevClass[$e.sev] } else { 'md' }
            $iso = Iso-Date $e.dt
            # Use literal middle-dot ([char]0x00B7) so html.escape leaves it alone.
            # Embedding "&middot;" here would get double-escaped to "&amp;middot;".
            $title = Esc-Html ("$($t.display) " + [char]0x00B7 + " $($e.kind) " + [char]0x00B7 + " $iso")
            $targetAttr = if ($e.target) { " data-target=`"$(Esc-Html $e.target)`"" } else { '' }
            if ($e.is_install) {
                $r = 6
                $cyTop = FmtCoord ($cy - $r)
                $cyBot = FmtCoord ($cy + $r)
                $xLeft = FmtCoord ($x - $r)
                $xRight = FmtCoord ($x + $r)
                $pts = "$xStr,$cyTop $xRight,$cyStr $xStr,$cyBot $xLeft,$cyStr"
                $trackSvg += "<polygon class=`"lc-install $cls`" points=`"$pts`"$targetAttr><title>$title</title></polygon>"
            } else {
                $trackSvg += "<circle class=`"lc-event $cls`" cx=`"$xStr`" cy=`"$cyStr`" r=`"4`"$targetAttr><title>$title</title></circle>"
            }
        }
    }

    $nTracks = $sortedKeys.Count
    $nEvents = 0
    foreach ($k in $sortedKeys) { $nEvents += $tracks[$k].events.Count }
    $sEvents = if ($nEvents -eq 1) { '' } else { 's' }
    $sTracks = if ($nTracks -eq 1) { '' } else { 's' }
    $cap = "<p class=`"lc-cap`">$nEvents dated event$sEvents across $nTracks pattern$sTracks. Diamonds are install dates from the Windows uninstall registry; circles are execution, write, USB-arrival, or run events. Hover any marker for the source field and date.</p>"

    return (
        '<section class="lifecycle">' +
        '<div class="sec-head">' +
        '<h2><span class="num">01&middot;a</span>Activity by pattern</h2>' +
        '<span class="sec-aside">linear timeline &middot; install diamond &middot; activity circle</span>' +
        '</div>' +
        "<svg class=`"lc-svg`" viewBox=`"0 0 $width $totalH`" preserveAspectRatio=`"none`" aria-label=`"per-keyword lifecycle timeline`">" +
        $gridSvg + $trackSvg + $todaySvg +
        '</svg>' +
        $cap +
        '</section>'
    )
}

function Render-CatMap {
    param($Recent)
    if (-not $Recent -or $Recent.Count -eq 0) { return '' }
    $cats = @{}
    foreach ($f in $Recent) {
        if ($f.Category -eq 'RecencyDecay') { continue }
        if (($f.Source) -and ($f.Source.Trim() -in '(scan)','(summary)')) { continue }
        if (-not $cats.ContainsKey($f.Category)) {
            $cats[$f.Category] = @{ HIGH=0; MEDIUM=0; WARN=0; INFO=0 }
        }
        $cats[$f.Category][$f.Severity] = $cats[$f.Category][$f.Severity] + 1
    }
    if ($cats.Count -eq 0) { return '' }

    # Sort: HIGH-first, then MEDIUM, WARN, others; then by total desc; then alpha
    $catList = foreach ($name in $cats.Keys) {
        $c = $cats[$name]
        $top = 3
        if     ($c.HIGH)   { $top = 0 }
        elseif ($c.MEDIUM) { $top = 1 }
        elseif ($c.WARN)   { $top = 2 }
        $total = $c.HIGH + $c.MEDIUM + $c.WARN + $c.INFO
        [pscustomobject]@{ Name=$name; Counts=$c; Top=$top; Total=$total }
    }
    $sorted = $catList | Sort-Object -Property Top, @{ E='Total'; Descending=$true }, @{ E={ $_.Name.ToLower() } }

    $tiles = ''
    foreach ($entry in $sorted) {
        $counts = $entry.Counts
        $topSev = ''
        foreach ($s in $script:SEVERITY_ORDER) { if ($counts[$s]) { $topSev = $s; break } }
        $topClass = switch ($topSev) { 'HIGH' { 'b-hi' } 'MEDIUM' { 'b-md' } 'WARN' { 'b-wn' } default { 'b-info' } }
        $topN = $counts[$topSev]
        $otherBits = @()
        foreach ($s in $script:SEVERITY_ORDER) {
            if ($s -ne $topSev -and $counts[$s]) { $otherBits += "+ $($counts[$s]) $s" }
        }
        $metaHtml = Esc-Html $topSev
        if ($otherBits.Count -gt 0) { $metaHtml += '<br>' + (Esc-Html ($otherBits -join ', ')) }
        $barHtml = "<span class=`"$topClass`" style=`"flex:$([math]::Max(1,$topN))`"></span>"
        foreach ($s in $script:SEVERITY_ORDER) {
            if ($s -eq $topSev -or -not $counts[$s]) { continue }
            $cls = switch ($s) { 'HIGH' { 'b-hi' } 'MEDIUM' { 'b-md' } 'WARN' { 'b-wn' } default { 'b-info' } }
            $barHtml += "<span class=`"$cls`" style=`"flex:$($counts[$s])`"></span>"
        }
        $dataTop = ''
        if ($topSev -in 'HIGH','MEDIUM') { $dataTop = " data-top-sev=`"$topSev`"" }
        $catEsc = Esc-Html $entry.Name
        $tiles += (
            "<button class=`"cat-tile`" data-cat=`"$catEsc`"$dataTop>" +
            "<div class=`"tile-name`">$catEsc</div>" +
            "<div class=`"tile-counts`"><span class=`"nbig`">$topN</span><span class=`"meta`">$metaHtml</span></div>" +
            "<div class=`"tile-bars`">$barHtml</div>" +
            '</button>'
        )
    }

    return (
        '<div class="catmap" style="margin-top: 16px;">' +
        '<div class="catmap-head">' +
        '<span class="l">Category signal &middot; which scanners fired</span>' +
        '<span class="r">click to filter findings &darr;</span>' +
        '</div>' +
        "<div class=`"catmap-grid`">$tiles</div>" +
        '</div>'
    )
}

function Render-Donut {
    param($Recent, $Processes, $Services)
    $counts = @{ HIGH=0; MEDIUM=0; WARN=0; INFO=0; LOW=0 }
    foreach ($f in $Recent) { if ($counts.ContainsKey($f.Severity)) { $counts[$f.Severity]++ } }
    $procHi  = 0; $procMd = 0; $procLow = 0
    foreach ($p in $Processes) {
        if     ($p.Score -eq 'HIGH')   { $procHi++ }
        elseif ($p.Score -eq 'MEDIUM') { $procMd++ }
        elseif ($p.Score -in 'LOW','CLEAN') { $procLow++ }
    }
    $svcHi = 0; $svcMd = 0; $svcLow = 0
    foreach ($s in $Services) {
        if     ($s.Score -eq 'HIGH')   { $svcHi++ }
        elseif ($s.Score -eq 'MEDIUM') { $svcMd++ }
        elseif ($s.Score -in 'LOW','CLEAN') { $svcLow++ }
    }
    $counts.HIGH   += $procHi + $svcHi
    $counts.MEDIUM += $procMd + $svcMd
    $counts.LOW    += $procLow + $svcLow

    $total = $counts.HIGH + $counts.MEDIUM + $counts.WARN + $counts.INFO + $counts.LOW
    if ($total -lt 10) { return '' }

    $gap = 0.5
    $order = @('HIGH','MEDIUM','WARN','INFO','LOW')
    $sliceSvg = ''
    $angleCursor = 0.0
    foreach ($tier in $order) {
        $pct = ($counts[$tier] / [double]$total) * 100.0
        if ($pct -le 0) { continue }
        $len = [math]::Max(0.01, $pct - $gap)
        $rest = [math]::Max(0.01, 100.0 - $len)
        $rotation = -90 + ($angleCursor * 3.6)
        $cls = switch ($tier) { 'HIGH' { 'hi' } 'MEDIUM' { 'md' } 'WARN' { 'wn' } 'INFO' { 'info' } 'LOW' { 'empty' } }
        $style = if ($tier -eq 'LOW') { ' style="stroke: var(--ink-5);"' } else { '' }
        $lenStr = FmtPct $len
        $restStr = FmtPct $rest
        $rotStr = FmtCoord $rotation
        $sliceSvg += "<circle class=`"slice $cls`" cx=`"120`" cy=`"120`" r=`"88`" pathLength=`"100`" stroke-dasharray=`"$lenStr $restStr`" transform=`"rotate($rotStr 120 120)`" data-tier=`"$tier`"$style></circle>"
        $angleCursor += $pct
    }

    $legendDesc = @{
        HIGH   = "$($counts.HIGH - $procHi - $svcHi) findings &middot; $procHi process &middot; $svcHi service"
        MEDIUM = "$($counts.MEDIUM - $procMd - $svcMd) findings &middot; $procMd process &middot; $svcMd service"
        WARN   = "$($counts.WARN) findings &middot; access denied"
        INFO   = "$($counts.INFO) scan-summary findings &middot; informational only"
        LOW    = "$procLow LOW/CLEAN processes &middot; $svcLow LOW/CLEAN services"
    }
    $rows = @(
        @('HIGH','hi','HIGH'),
        @('MEDIUM','md','MEDIUM'),
        @('WARN','wn','WARN'),
        @('INFO','info','INFO'),
        @('LOW','empty','LOW / CLEAN')
    )
    $legendRows = ''
    foreach ($r in $rows) {
        if ($counts[$r[0]] -le 0) { continue }
        $legendRows += "<div class=`"row`" data-tier=`"$($r[0])`"><span class=`"swatch $($r[1])`"></span><span class=`"lbl`">$($r[2])<span class=`"breakdown`">$($legendDesc[$r[0]])</span></span><span class=`"n`">$($counts[$r[0]])</span></div>"
    }

    $pctHi = ($counts.HIGH / [double]$total) * 100.0
    $caption = "<p class=`"indi-cap`">Each slice is one score tier across all artifact classes. <b>$($counts.HIGH) HIGH indicators ($('{0:N1}' -f $pctHi)%)</b> drive the verdict. A clean machine would show a single solid LOW/CLEAN ring &mdash; the more red and amber present, the worse the picture.</p>"

    return (
        '<section class="indi">' +
        '<div class="sec-head" style="border-bottom-color: var(--rule); margin-bottom: 14px;">' +
        '<h2><span class="num">00</span>All indicators &middot; score distribution</h2>' +
        "<span class=`"sec-aside`">findings + processes + services &middot; $total indicators</span>" +
        '</div>' +
        '<div class="indi-body">' +
        '<svg class="indi-donut" viewBox="0 0 240 240" aria-label="indicator distribution by score tier">' +
        '<circle class="ring-bg" cx="120" cy="120" r="88"></circle>' +
        $sliceSvg +
        '<text class="total-label" x="120" y="106" text-anchor="middle">total</text>' +
        "<text class=`"total-n`" x=`"120`" y=`"142`" text-anchor=`"middle`">$total</text>" +
        '<text class="total-sub" x="120" y="156" text-anchor="middle">indicators</text>' +
        '</svg>' +
        "<div class=`"indi-legend`" id=`"indi-legend`">$legendRows</div>" +
        '</div>' + $caption + '</section>'
    )
}

function Render-Filters {
    param([hashtable]$SevCounts)
    $chips = ''
    foreach ($sev in $script:SEVERITY_ORDER) {
        $pressed = if ($sev -eq 'INFO') { 'false' } else { 'true' }
        $n = $SevCounts[$sev]
        $chips += "<button class=`"chip`" data-filter=`"sev`" data-val=`"$sev`" aria-pressed=`"$pressed`">$sev<span class=`"count`">$n</span></button>"
    }
    $kindChips = ''
    foreach ($k in 'cheat','input','dual-use','other') {
        $kindChips += "<button class=`"chip`" data-filter=`"kind`" data-val=`"$k`" aria-pressed=`"true`">$(Esc-Html $k)</button>"
    }
    return (
        '<div class="filters" role="toolbar" aria-label="filter findings">' +
        '<span class="flabel">severity</span>' + $chips +
        '<span class="filters-divider"></span>' +
        '<span class="flabel">kind</span>' + $kindChips +
        '<button class="clear" id="clear-filters">reset</button>' +
        '<div class="cat-filter" id="cat-filter" hidden>' +
        '<span class="pill"><span id="cat-filter-name">&mdash;</span>' +
        '<button id="cat-filter-clear">&times;</button></span>' +
        '</div>' +
        '</div>'
    )
}

function Render-FindingCard {
    param([hashtable]$Finding, [string]$Fid)
    $stamps = Finding-Timestamps $Finding
    $primary = $null
    foreach ($t in $stamps) {
        if ($t.Key -in 'LastWrite','LastModified','LastRemoval','NewestWrite','LastRun','LastExecution','LastArrival','Timestamp','Created') {
            $primary = $t; break
        }
    }
    if (-not $primary -and $stamps.Count -gt 0) { $primary = $stamps[0] }

    $whenHtml = ''
    if ($primary) {
        $labelMap = @{
            LastWrite='last write'; LastModified='last modified'; LastRemoval='last removal';
            NewestWrite='newest write'; LastRun='last run'; LastExecution='last run';
            LastArrival='last arrival'; Created='created'; FirstSeen='first seen';
            FirstInstall='first install'; InstallDate='installed'; Timestamp=''
        }
        $word = if ($labelMap.ContainsKey($primary.Key)) { $labelMap[$primary.Key] } else { '' }
        $ageDays = [int]((Get-Date) - $primary.Dt).TotalDays
        $ago = Human-Age $ageDays
        $prefix = if ($word) { "$word " } else { '' }
        $iso = Iso-Date $primary.Dt
        $whenHtml = "<time class=`"finding-when`" datetime=`"$iso`">$(Esc-Html $prefix)$iso <span class=`"ago`">&middot; $(Esc-Html $ago)</span></time>"
    }

    $sev = Esc-Html $Finding.Severity
    $kind = if ($Finding.Kind) { $Finding.Kind } else { 'other' }
    $kindEsc = Esc-Html $kind
    $catEsc = Esc-Html $Finding.Category
    $head = "<div class=`"finding-head`"><span class=`"sev-tag`" data-sev=`"$sev`">$sev</span><span class=`"kind-tag`">$kindEsc</span><span class=`"cat-tag`" data-cat=`"$catEsc`">$catEsc</span>$whenHtml</div>"

    $pattern = if ($Finding.Metadata.ContainsKey('Pattern')) { [string]$Finding.Metadata['Pattern'] } else { '' }
    $patHtml = if ($pattern) { "<span class=`"pat`">$(Esc-Html $pattern)</span>" } else { '' }
    $title = "<div class=`"finding-title`">$patHtml$(Esc-Html $Finding.Detail)</div>"

    $srcPath = $Finding.Source
    $copyBtn = ''
    if ($srcPath -and ($srcPath -match '[\\\/]' -or $srcPath -match '^HK')) {
        $copyBtn = "<button class=`"copy-btn`" data-copy=`"$(Esc-Html $srcPath)`">copy</button>"
    }
    $srcBlock = "<div class=`"finding-source`"><span class=`"src-label`">source</span><code class=`"src-path`">$(Esc-Html $srcPath)</code>$copyBtn</div>"

    $metaItems = [System.Collections.Generic.List[object]]::new()
    if ($Finding.Metadata) {
        $hidden = @('RecencyClass','OriginalSeverity','AgeDays','MostRecentTimestamp')
        foreach ($k in $Finding.Metadata.Keys) {
            if ($k -in $hidden) { continue }
            $v = $Finding.Metadata[$k]
            if ($null -eq $v -or $v -eq '') { continue }
            [void]$metaItems.Add(@{ K = $k; V = $v })
        }
    }

    $metaParts = ''
    $extraCount = 0
    for ($i = 0; $i -lt $metaItems.Count; $i++) {
        $k = $metaItems[$i].K; $v = $metaItems[$i].V
        $ddCls = ''
        if ($k -in $script:HASH_KEYS) { $ddCls = ' class="hash"' }
        elseif ($k -eq 'IsSigned') {
            $sv = ([string]$v).ToLower()
            if ($sv -in 'true','1','yes') { $ddCls = ' class="true"' }
            elseif ($sv -in 'false','0','no') { $ddCls = ' class="false"' }
        }
        if ($i -ge 4) { $clsAttr = 'kv hidden'; $extraCount++ } else { $clsAttr = 'kv' }
        if (($k -in $script:URL_KEYS) -and ([string]$v).StartsWith('http')) {
            $shortUrl = [string]$v
            $ellipsis = ''
            if ($shortUrl.Length -gt 60) { $shortUrl = $shortUrl.Substring(0,60); $ellipsis = '&hellip;' }
            $ddInner = "<a href=`"$(Esc-Html $v)`" rel=`"noopener noreferrer`">$(Esc-Html $shortUrl)$ellipsis</a>"
            $ddCls = ' class="url"'
        } elseif ($k -in $script:BYTES_KEYS) {
            $ddInner = Format-Bytes $v
        } else {
            $ddInner = Esc-Html $v
        }
        $metaParts += "<div class=`"$clsAttr`"><dt>$(Esc-Html $k)</dt><dd$ddCls>$ddInner</dd></div>"
    }

    $metaBlock = ''
    if ($metaParts) {
        $collapsed = if ($extraCount -gt 0) { ' data-collapsed="4"' } else { '' }
        $single = if (($extraCount -eq 0) -and ($metaItems.Count -le 2)) { ' single' } else { '' }
        $expand = if ($extraCount -gt 0) { "<button class=`"meta-expand`"><span class=`"car`"></span>expand &middot; $extraCount more</button>" } else { '' }
        $metaBlock = "<dl class=`"finding-meta$single`"$collapsed>$metaParts</dl>$expand"
    }

    return (
        "<li id=`"$(Esc-Html $Fid)`" class=`"finding`" data-severity=`"$sev`" data-kind=`"$kindEsc`" data-category=`"$catEsc`" data-pattern=`"$(Esc-Html $pattern)`" data-keys=`"$(Esc-Html (Data-Keys-For-Finding $Finding))`">" +
        $head + $title + $srcBlock + $metaBlock + '</li>'
    )
}

function Render-FindingsSection {
    param($Recent, [hashtable]$FindingIds)
    $grouped = @{ HIGH=[System.Collections.Generic.List[hashtable]]::new(); MEDIUM=[System.Collections.Generic.List[hashtable]]::new(); WARN=[System.Collections.Generic.List[hashtable]]::new(); INFO=[System.Collections.Generic.List[hashtable]]::new() }
    foreach ($f in $Recent) {
        if ($grouped.ContainsKey($f.Severity)) { [void]$grouped[$f.Severity].Add($f) }
    }
    $sevCounts = @{ HIGH=$grouped.HIGH.Count; MEDIUM=$grouped.MEDIUM.Count; WARN=$grouped.WARN.Count; INFO=$grouped.INFO.Count }
    $filterBar = Render-Filters $sevCounts

    $groupBlocks = ''
    foreach ($sev in $script:SEVERITY_ORDER) {
        if ($grouped[$sev].Count -eq 0) { continue }
        $items = @($grouped[$sev] | Sort-Object @{ E = { $_.Category.ToLower() } }, @{ E = { $_.Detail.ToLower() } })
        # Literal middle-dot — these flow through Esc-Html below.
        $mid = ' ' + [char]0x00B7 + ' '
        $suffix = if ($sev -eq 'INFO') { "$mid" + 'hidden by default' } else { '' }
        $hdrExtra = if ($sev -eq 'WARN') { "$mid" + 'access denied' } else { '' }
        $head = "<div class=`"sev-group`" data-sev=`"$sev`"><h3><span class=`"dot`"></span>$sev$(Esc-Html $hdrExtra)</h3><span class=`"count`">$($items.Count) findings$(Esc-Html $suffix)</span><span class=`"group-rule`"></span></div>"
        $cards = ''
        foreach ($f in $items) {
            $key = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($f)
            $card = Render-FindingCard $f $FindingIds[$key]
            if ($sev -eq 'INFO') {
                # Inline the style on the single <li id="..."> that opens each card.
                $card = $card -replace '<li id=', '<li style="display:none" id='
            }
            $cards += $card
        }
        $groupBlocks += $head + "<ul class=`"findings`">$cards</ul>"
    }

    $emptyCallout = ''
    $totalGroup = 0; foreach ($g in $grouped.Values) { $totalGroup += $g.Count }
    if ($totalGroup -eq 0) {
        $emptyCallout = '<div class="empty-callout"><span class="dot ok"></span><p>No findings to display. The scanners ran but matched nothing against the keyword database within the last 180 days. See the runtime tables below and the historical section (if present) for the full picture.</p></div>'
    }

    return (
        '<section id="findings">' +
        '<div class="sec-head">' +
        '<h2><span class="num">01</span>Findings &middot; cheat trace scan</h2>' +
        '<span class="sec-aside">recent (&le;180d) &middot; verdict-relevant</span>' +
        '</div>' +
        $filterBar + $emptyCallout + $groupBlocks +
        '</section>'
    )
}

function Render-Runtime {
    param($Processes, $Services, [hashtable]$ProcessIds, [hashtable]$ServiceIds)

    $sortKey = @{ HIGH=0; MEDIUM=1; LOW=2; CLEAN=3 }

    function _ProcRows($items, $ids, $kind) {
        $sortedItems = @($items | Sort-Object @{ E = { if ($sortKey.ContainsKey($_.Score)) { $sortKey[$_.Score] } else { 9 } } }, @{ E = { $_.Name.ToLower() } })
        $rows = ''
        foreach ($it in $sortedItems) {
            $key = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($it)
            $iid = $ids[$key]
            $score = $it.Score
            if ($kind -eq 'proc') {
                $pidStr = Esc-Html $it.ProcessId
                $name = Esc-Html $it.Name
                $exe = Esc-Html $it.ExecutablePath
                $cmd = Esc-Html $it.CommandLine
                $reasonHtml = ''
                if ($score -in 'HIGH','MEDIUM') {
                    $r = Esc-Html $it.Reason
                    $reasonHtml = if ($cmd) { "<div class=`"reason`">$r &middot; cmd <code>$cmd</code></div>" } else { "<div class=`"reason`">$r</div>" }
                }
                $rowClasses = if ($score -in 'HIGH','MEDIUM') { 'has-link' } else { 'clean-row' }
                if ($score -eq 'CLEAN') { $rowClasses += ' hidden' }
                $rows += (
                    "<tr id=`"$(Esc-Html $iid)`" class=`"$rowClasses`" data-pattern=`"$(Esc-Html $it.Pattern)`" data-keys=`"$(Esc-Html (Data-Keys-For-Proc $it))`">" +
                    "<td><span class=`"score`" data-s=`"$(Esc-Html $score)`"><i></i>$(Esc-Html $score)</span></td>" +
                    "<td>$pidStr</td>" +
                    "<td><span class=`"name`">$name</span><br><span style=`"color:var(--ink-4)`">$exe</span>$reasonHtml</td></tr>"
                )
            } else {
                $display = Esc-Html $it.DisplayName
                $st = Esc-Html $it.State
                $sm = Esc-Html $it.StartMode
                $path = Esc-Html $it.PathName
                $name = Esc-Html $it.Name
                $stateCell = $st
                if ($sm -and ($score -in 'HIGH','MEDIUM')) {
                    $stateCell += "<br><span style=`"color:var(--ink-5); font-size:10.5px`">$sm</span>"
                }
                $reasonHtml = ''
                if ($score -in 'HIGH','MEDIUM') {
                    $reasonHtml = "<div class=`"reason`">$(Esc-Html $it.Reason)</div>"
                }
                $rowClasses = if ($score -in 'HIGH','MEDIUM') { 'has-link' } else { 'clean-row' }
                if ($score -eq 'CLEAN') { $rowClasses += ' hidden' }
                $rows += (
                    "<tr id=`"$(Esc-Html $iid)`" class=`"$rowClasses`" data-pattern=`"$(Esc-Html $it.Pattern)`" data-keys=`"$(Esc-Html (Data-Keys-For-Svc $it))`">" +
                    "<td><span class=`"score`" data-s=`"$(Esc-Html $score)`"><i></i>$(Esc-Html $score)</span></td>" +
                    "<td>$stateCell</td>" +
                    "<td><span class=`"name`">$name</span> &middot; <span style=`"color:var(--ink-4)`">$display</span><br><span style=`"color:var(--ink-4)`">$path</span>$reasonHtml</td></tr>"
                )
            }
        }
        return $rows
    }

    function _Breakdown($items) {
        $nHi = 0; $nMd = 0; $nLow = 0
        foreach ($x in $items) {
            switch ($x.Score) {
                'HIGH'   { $nHi++ }
                'MEDIUM' { $nMd++ }
                'LOW'    { $nLow++ }
                'CLEAN'  { $nLow++ }
            }
        }
        return "<div class=`"breakdown`"><span class=`"hi`"><b>$nHi</b>HIGH</span><span class=`"md`"><b>$nMd</b>MED</span><span><b>$nLow</b>LOW/CLEAN</span></div>"
    }

    function _Foot($items, $targetId) {
        $nHidden = 0
        foreach ($x in $items) { if ($x.Score -eq 'CLEAN') { $nHidden++ } }
        $nShown = $items.Count - $nHidden
        return "<div class=`"runtime-foot`"><span><b>$nShown</b> of $($items.Count) shown &middot; $nHidden CLEAN hidden</span><button class=`"toggle-clean`" data-target=`"$(Esc-Html $targetId)`">show CLEAN</button></div>"
    }

    $procRows = _ProcRows $Processes $ProcessIds 'proc'
    $svcRows  = _ProcRows $Services $ServiceIds 'svc'
    $procBreak = _Breakdown $Processes
    $svcBreak = _Breakdown $Services
    $procFoot = _Foot $Processes 'proc-tbl'
    $svcFoot = _Foot $Services 'svc-tbl'

    return (
        '<section>' +
        '<div class="sec-head">' +
        '<h2><span class="num">02&middot;03</span>Runtime &middot; processes &amp; services</h2>' +
        '<span class="sec-aside">hover a row to highlight linked findings &uarr;</span>' +
        '</div>' +
        '<div class="runtime-grid">' +
        '<div class="tbl-shell">' +
        "<div class=`"tbl-head`"><h3>Processes</h3>$procBreak</div>" +
        '<table class="runtime" id="proc-tbl"><thead><tr><th style="width:90px">score</th><th style="width:60px">pid</th><th>name &middot; path</th></tr></thead><tbody>' +
        $procRows + '</tbody></table>' + $procFoot + '</div>' +
        '<div class="tbl-shell">' +
        "<div class=`"tbl-head`"><h3>Services</h3>$svcBreak</div>" +
        '<table class="runtime" id="svc-tbl"><thead><tr><th style="width:90px">score</th><th style="width:80px">state</th><th>name &middot; path</th></tr></thead><tbody>' +
        $svcRows + '</tbody></table>' + $svcFoot + '</div>' +
        '</div></section>'
    )
}

function Render-Historical {
    param($Archived, [int]$ThresholdDays)
    if (-not $Archived -or $Archived.Count -eq 0) { return '' }

    $archivedHigh = @($Archived | Where-Object { $_.Metadata.OriginalSeverity -eq 'HIGH' })
    $introExtra = ''
    if ($archivedHigh.Count -gt 0) {
        $introExtra = " <b style=`"color: var(--ink-2)`">$($archivedHigh.Count) originally HIGH-severity</b>."
    }

    $sorted = @($Archived | Sort-Object @{ E = { -([int]([string]($_.Metadata.AgeDays) -as [int])) } })

    $cards = ''
    foreach ($f in $sorted) {
        $stamps = Finding-Timestamps $f
        $whenHtml = ''
        if ($stamps.Count -gt 0) {
            $iso = Iso-Date $stamps[0].Dt
            $whenHtml = "<time class=`"finding-when`" datetime=`"$iso`">most recent $iso</time>"
        }
        $orig = if ($f.Metadata.OriginalSeverity) { $f.Metadata.OriginalSeverity } else { '' }
        $age = if ($f.Metadata.AgeDays) { $f.Metadata.AgeDays } else { '?' }
        $ageFmt = $age
        $ageInt = 0
        if ([int]::TryParse([string]$age, [ref]$ageInt)) { $ageFmt = ('{0:N0}' -f $ageInt) }
        $origPill = ''
        if ($orig) { $origPill = "<span class=`"hist-orig`">orig&nbsp;<b>$(Esc-Html $orig)</b>&nbsp;&middot;&nbsp;$ageFmt d old</span>" }

        $pattern = if ($f.Metadata.ContainsKey('Pattern')) { [string]$f.Metadata['Pattern'] } else { '' }
        $patHtml = if ($pattern) { "<span class=`"pat`" style=`"background:var(--panel-2); color:var(--ink-3); border-color:var(--rule-2);`">$(Esc-Html $pattern)</span>" } else { '' }

        $metaParts = ''
        if ($f.Metadata) {
            foreach ($k in $f.Metadata.Keys) {
                if ($k -eq 'RecencyClass') { continue }
                $v = $f.Metadata[$k]
                if ($null -eq $v -or $v -eq '') { continue }
                $ddCls = ''
                if ($k -in $script:HASH_KEYS) { $ddCls = ' class="hash"' }
                $inner = if ($k -in $script:BYTES_KEYS) { Format-Bytes $v } else { Esc-Html $v }
                $metaParts += "<div class=`"kv`"><dt>$(Esc-Html $k)</dt><dd$ddCls>$inner</dd></div>"
            }
        }
        $metaHtml = if ($metaParts) { "<dl class=`"finding-meta`">$metaParts</dl>" } else { '' }

        $sev = Esc-Html $f.Severity
        $kindEsc = Esc-Html (if ($f.Kind) { $f.Kind } else { 'other' })
        $catEsc = Esc-Html $f.Category
        $card = (
            "<li class=`"finding`" data-severity=`"$sev`" data-kind=`"$kindEsc`" data-category=`"$catEsc`">" +
            '<div class="finding-head">' +
            "<span class=`"sev-tag`" data-sev=`"$sev`">$sev</span>" +
            "<span class=`"kind-tag`">$kindEsc</span>" +
            "<span class=`"cat-tag`">$catEsc</span>" +
            $origPill + $whenHtml +
            '</div>' +
            "<div class=`"finding-title`">$patHtml$(Esc-Html $f.Detail)</div>" +
            "<div class=`"finding-source`"><span class=`"src-label`">source</span><code class=`"src-path`">$(Esc-Html $f.Source)</code></div>" +
            $metaHtml +
            '</li>'
        )
        $cards += $card
    }

    return (
        '<section class="hist">' +
        '<div class="hist-divider">' +
        "<span class=`"label`">archived &middot; &gt; $ThresholdDays days &middot; did NOT affect verdict</span>" +
        '<span class="hatch"></span>' +
        '</div>' +
        "<p class=`"hist-intro`">$($Archived.Count) finding(s) with a most-recent timestamp older than $ThresholdDays days were demoted by the recency-decay rule.$introExtra They are logged here for transparency &mdash; old artifacts from games or tools the user has long since stopped using do not, on their own, make a currently-clean machine look dirty.</p>" +
        "<ul class=`"findings`">$cards</ul>" +
        '</section>'
    )
}

function Render-Coverage {
    param([string[]]$Limitations)
    if (-not $Limitations -or $Limitations.Count -eq 0) { return '' }
    $items = ''
    foreach ($line in $Limitations) { $items += "<li>$(Esc-Html $line)</li>" }
    return "<section class=`"coverage`"><h2>Coverage limitations</h2><ul>$items</ul></section>"
}

function Render-DocFoot {
    param([bool]$LolDbUsed)
    $net = if ($LolDbUsed) { '1 outbound call to loldrivers.io (opt-in) &middot; file self-contained' } else { 'no network calls &middot; file self-contained' }
    return (
        '<div class="docfoot">' +
        "<span>alibi $($script:ALIBI_VERSION) &middot; powershell &middot; read-only scan &middot; no system state was modified</span>" +
        "<span>$net</span>" +
        '</div>'
    )
}

# ============================================================================
# ENTRY POINT
# ============================================================================

function Render-AlibiHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [string]$InputPath,
        [Parameter(Mandatory=$true)] [string]$OutputPath,
        [string]$ModeLabel = 'pc-mode',
        [string[]]$CoverageLimitations,
        [bool]$LolDbUsed = $false
    )

    if (-not (Test-Path $InputPath)) {
        Write-Host "ERROR: Input not found: $InputPath" -ForegroundColor Red
        exit 1
    }

    # Load shared visual resources from the same folder as this module.
    $cssPath = Join-Path $PSScriptRoot 'visual_styles.css'
    $jsPath  = Join-Path $PSScriptRoot 'visual_scripts.js'
    if (-not (Test-Path $cssPath)) { Write-Host "ERROR: visual_styles.css missing at $cssPath" -ForegroundColor Red; exit 1 }
    if (-not (Test-Path $jsPath))  { Write-Host "ERROR: visual_scripts.js missing at $jsPath" -ForegroundColor Red; exit 1 }
    $css = Get-Content $cssPath -Raw -Encoding UTF8
    $js  = Get-Content $jsPath  -Raw -Encoding UTF8

    # Parse the .txt report.
    $ctx = Parse-AlibiReport $InputPath
    Score-Items $ctx

    if (-not $ctx.Verdict) {
        # Fall back to a recomputed verdict if the .txt didn't carry one.
        $totHigh = 0; $totMed = 0
        foreach ($f in $ctx.Findings) {
            if ($f.Metadata.RecencyClass -eq 'historical') { continue }
            if ($f.Severity -eq 'HIGH')   { $totHigh++ }
            if ($f.Severity -eq 'MEDIUM') { $totMed++ }
        }
        foreach ($p in $ctx.Processes) { if ($p.Score -eq 'HIGH') { $totHigh++ } elseif ($p.Score -eq 'MEDIUM') { $totMed++ } }
        foreach ($s in $ctx.Services)  { if ($s.Score -eq 'HIGH') { $totHigh++ } elseif ($s.Score -eq 'MEDIUM') { $totMed++ } }
        $ctx.Verdict = if ($totHigh -gt 0) { 'CHEATS DETECTED' } elseif ($totMed -gt 0) { 'UNSURE' } else { 'CLEAN' }
    }

    # Use caller-supplied coverage block if present; otherwise pull from .txt;
    # otherwise fall back to a sane default.
    $coverage = $null
    if ($CoverageLimitations -and $CoverageLimitations.Count -gt 0) { $coverage = $CoverageLimitations }
    elseif ($ctx.Limitations.Count -gt 0) { $coverage = $ctx.Limitations.ToArray() }
    else {
        $coverage = @(
            'DMA cheats cannot be detected at runtime by design - no PC-side footprint. This scan flags DMA development artifacts only.',
            'Input devices configured on a separate machine leave no trace on this PC.',
            'Session duration is recorded in SRUM and requires an ESE database parser. Not extracted here.',
            'Keyword matching only. Sophisticated cleaners can wipe most of these artifacts.',
            'A clean result is necessary but not sufficient.'
        )
    }

    # Partition findings by recency.
    $recent = [System.Collections.Generic.List[hashtable]]::new()
    $archived = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($f in $ctx.Findings) {
        if ($f.Category -eq 'RecencyDecay') { continue }
        if ($f.Metadata.RecencyClass -eq 'historical') { [void]$archived.Add($f) }
        else { [void]$recent.Add($f) }
    }
    foreach ($f in $ctx.Findings) {
        if ($f.Category -eq 'RecencyDecay') { [void]$recent.Add($f) }
    }

    # Stable ids — keyed by object hashcode.
    $usedF = New-Object 'System.Collections.Generic.HashSet[string]'
    $usedP = New-Object 'System.Collections.Generic.HashSet[string]'
    $usedS = New-Object 'System.Collections.Generic.HashSet[string]'
    $findingIds = @{}
    $processIds = @{}
    $serviceIds = @{}
    foreach ($f in $recent) {
        $key = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($f)
        $findingIds[$key] = Finding-Id $f $usedF
    }
    foreach ($p in $ctx.Processes) {
        $key = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($p)
        $processIds[$key] = Process-Id $p $usedP
    }
    foreach ($s in $ctx.Services) {
        $key = [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($s)
        $serviceIds[$key] = Service-Id $s $usedS
    }

    $named = Build-NamedItems $recent $ctx.Processes $ctx.Services $findingIds $processIds $serviceIds $ctx.Verdict

    $state = State-For-Verdict $ctx.Verdict
    $subText = if ($script:VERDICT_SUBS.ContainsKey($ctx.Verdict)) { $script:VERDICT_SUBS[$ctx.Verdict] } else { '' }

    # Compose the HTML document.
    $titleHost = Esc-Html $ctx.Hostname
    $titleDate = Esc-Html (Iso-Date (Get-Date))
    $titleVerdict = Esc-Html $ctx.Verdict

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!doctype html>')
    [void]$sb.AppendLine('<html lang="en"><head>')
    [void]$sb.AppendLine('<meta charset="utf-8">')
    [void]$sb.AppendLine("<title>alibi &middot; $titleHost &middot; $titleDate &middot; $titleVerdict</title>")
    [void]$sb.AppendLine("<meta name=`"generator`" content=`"alibi $($script:ALIBI_VERSION) (powershell)`">")
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine('<!--')
    [void]$sb.AppendLine('  alibi · visual companion (dark)')
    [void]$sb.AppendLine('  Self-contained. No network, no external assets, no analytics.')
    [void]$sb.AppendLine('  All interactivity is plain vanilla JS in the <script> block at')
    [void]$sb.AppendLine('  the bottom of this file. View source freely.')
    [void]$sb.AppendLine('-->')
    [void]$sb.AppendLine("<style>")
    [void]$sb.AppendLine($css)
    [void]$sb.AppendLine('</style>')
    [void]$sb.AppendLine('</head><body>')
    [void]$sb.AppendLine('<div class="doc">')

    [void]$sb.AppendLine((Render-DocBar $ctx $LolDbUsed))
    [void]$sb.AppendLine((Render-Verdict $ctx $state $subText $ModeLabel $recent $archived $ctx.Processes $ctx.Services $named))
    [void]$sb.AppendLine((Render-Timeline $state $recent $archived $findingIds))
    [void]$sb.AppendLine((Render-Lifecycle $recent $ctx.Processes $findingIds))
    [void]$sb.AppendLine((Render-CatMap $recent))
    [void]$sb.AppendLine((Render-Donut $recent $ctx.Processes $ctx.Services))
    [void]$sb.AppendLine((Render-FindingsSection $recent $findingIds))
    [void]$sb.AppendLine((Render-Runtime $ctx.Processes $ctx.Services $processIds $serviceIds))
    [void]$sb.AppendLine((Render-Historical $archived $script:RECENCY_THRESHOLD_DAYS))
    [void]$sb.AppendLine((Render-Coverage $coverage))
    [void]$sb.AppendLine((Render-DocFoot $LolDbUsed))

    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<script>')
    [void]$sb.AppendLine($js)
    [void]$sb.AppendLine('</script>')
    [void]$sb.AppendLine('</body></html>')

    $html = $sb.ToString()
    Set-Content -Path $OutputPath -Value $html -Encoding UTF8

    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Green
    Write-Host '  Visual companion (dark-tactical) generated.' -ForegroundColor Green
    Write-Host "  Input:   $InputPath"
    Write-Host "  Output:  $OutputPath"
    Write-Host "  Verdict: $($ctx.Verdict)"
    Write-Host "  Mode:    $ModeLabel"
    Write-Host '================================================================' -ForegroundColor Green
}
