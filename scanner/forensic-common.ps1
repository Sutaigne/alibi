<#
.SYNOPSIS
    Shared engine for the Alibi kit.

.DESCRIPTION
    Dot-sourced by forensic-scan.ps1 (PC mode) and console-rig-audit.ps1
    (console-rig PC mode). Contains everything those two drivers have in
    common: keyword arrays, the file/hash database, all Scan-* functions,
    process and service snapshot logic, and shared utility helpers.

    The driver scripts handle only:
      - Their own banner / output filename
      - Composite-keyword assembly (combining base arrays with mode extras)
      - Verdict computation (the tier names differ between PC and console)
      - The QUICK READ block at the top of the report
      - Optional visual-companion launch

    Loading: a driver dot-sources this file AFTER setting up its own
    $Findings list, and BEFORE running any Scan-* function.

        $Findings = [System.Collections.Generic.List[pscustomobject]]::new()
        . "$PSScriptRoot\forensic-common.ps1"
        # ...optionally extend keyword arrays...
        Scan-Prefetch
        Scan-BAM
        ...

    Functions in this file read PowerShell parent-scope variables at call
    time, so the driver's keyword arrays and $Findings list are visible
    here automatically.

.NOTES
    Author: Bread
    Contributor: Drownmw
#>

# ============================================================================
# KEYWORD DATABASE (research-confirmed names only)
# ============================================================================

# Cheat brands - if any of these hit, verdict is "Cheats Detected"
$CheatBrands_COD = @(
    'engineowning','engine owning','phantomoverlay','phantom overlay','lavicheats','lavi cheats',
    'skycheats','sky cheats','iwantcheats','i want cheats','x22cheats','x22 cheats','golden gun',
    'tateware','gcaimx','hdcheat','securecheats','overlord spoofer','zhexcheats','zhex cheats',
    # Rivera Unlock Tool (RUT) + RUAVT bundle - paid CoD cheat sold via rut.gg.
    # Field-tested + corroborated by Hybrid Analysis sandbox, reseller pages,
    # Telegram @RUTFORCOD, and a multi-year elitepvpers community thread.
    # Bare 'rut' excluded (English-word false positives). Multi-token only.
    'rut.gg','old.rut.gg','rutforcod',
    'ruavt','rut and ruavt','rutandruavt',
    'rut launcher','rut v3 launcher','rut v4 launcher',
    'rut v3.exe','rut v4.exe','rutv3.exe','rutv4.exe',
    'rivera unlock','riveras unlock','rivera unlock tool','riveras rut',
    'rut unlocker','rut unlock tool','rut uav','rut-uav',
    # Activision C&D'd in Feb 2025; kept here so the scanner still hits
    # if a user's machine wasn't fully wiped after these brands shut down.
    'two2nd','two2nd_loader',
    'tomware','tomwareloader','tomware_loader',
    'cynicalsoftware','cynical_loader','cynical software'
)
$Spoofer_Brands = @(
    'sync spoofer','syncspoofer','tracex','slothytech','pokespoof','overlord.exe','overlord_',
    'hidhide','hid hide','hidhideclient','hidhidecli','hidhidedrv',
    # v3.8 - additional spoofer brands and storefronts
    'hwidspoofer','hwidspoofer.com',
    'synctop','sync-top'
)
$CheatFeature_Names = @(
    'aimbot','wallhack','wall_hack','wall-hack','triggerbot','trigger_bot','norecoil','no-recoil','no_recoil',
    'hwidspoofer','hwid_spoof','hwid-spoof','hwidchanger','macspoof','mac_spoof'
)
$DMA_Indicators = @(
    'pcileech','pcileech-fpga','pcileech_fpga','pcileech_squirrel','pcileech_enigma','pcileech_zdma',
    'pcileech_screamer','pcileech_leetdma','pcileech_captaindma','pcileech_hackdma','pcileech_lurker',
    'pcileech_mvp','pcileech_macku','_top.bin',
    # v3.8 - branded DMA hardware vendors (the consumer-friendly market that
    # replaced raw pcileech-fpga builds). Filename/process-name fragments.
    'atomicdma','atomic_dma','atomic-dma',
    'captaindma','captain_dma','captainfuser','captain_fuser',
    'leetdma','leet_dma',
    'lurkerdma','lurker_dma',
    'enigma_x1','enigmax1','enigma-x1',
    'mvpdma','mvp_dma',
    'hackdma','hack_dma',
    'zdma','z_dma',
    'suspectdma','suspect_dma','suspectcheats',
    'phoenixlabs','phoenixlabstore','phoenix_dma',
    'screamer_squirrel','squirrel_dma','lambdaconcept',
    'echeats','echeats.io','equalcheats',
    'ssz_dma','ssz.gg',
    'clutchsolution','clutch-solution'
)

# Input devices - separate verdict category from cheat brands
$InputDevices = @(
    'xim manager','ximmanager','xim apex','xim matrix','xim4','cronus','cronuszen','zen studio',
    'gpcscript','cronusmax','reasnow','reasnow s1','kmbox','km-box','km_box','titan two','titan.two',
    'gtuner','consoletuner',
    'rewasd','rewasdengine','rewasd engine','rewasd.exe'
)

# Dual-use tools (MEDIUM)
$DMA_DualUse = @('vivado','xilinx vivado','arbor','dma-cfw','dma_cfw')
$DualUse_Tools = @(
    'bleachbit','privazer','rbcleaner','cheatengine','cheat engine','processhacker','process hacker',
    'ollydbg','x64dbg','x32dbg','reclass','reclass.net','ida.exe','ida64.exe','ida pro'
)

# Suspicious script-content patterns - Things a normal user's script never
# contains, but cheat-helper / anti-forensic scripts often do. Matched HIGH
# against script CONTENTS (not just file names).
$ScriptContent_HighRisk = @(
    # Driver-signing bypass
    'bcdedit /set testsigning','bcdedit /set nointegritychecks','bcdedit -set testsigning',
    # Anti-cheat process kills
    'taskkill /f /im easyanticheat','taskkill /f /im battleye','taskkill /f /im vanguard',
    'taskkill /f /im ricochet','taskkill /f /im faceit','taskkill /f /im esea',
    'taskkill /im eac','taskkill /im be-service',
    'stop-service -name vgc','stop-service vgc','stop-service -name vgk',
    'sc stop vgc','sc stop vgk','sc stop bedaisy',
    # Defender disabling
    'set-mppreference -disablerealtime','set-mppreference -disablebehaviormonitoring',
    'set-mppreference -disableioavprotection','add-mppreference -exclusionpath',
    'add-mppreference -exclusionprocess','add-mppreference -exclusionextension',
    # HWID query patterns
    'wmic csproduct get uuid','wmic baseboard get serialnumber',
    'wmic diskdrive get serialnumber','wmic bios get serialnumber',
    'get-wmiobject win32_baseboard','get-wmiobject win32_diskdrive',
    'get-ciminstance win32_baseboard',
    # Encoded / remote-execution patterns
    'powershell -enc ','powershell -encodedcommand','powershell.exe -enc ',
    'iex(new-object net.webclient','iex (new-object net.webclient',
    'invoke-expression (new-object net.webclient','iwr ${','curl http','| iex','|iex',
    # Anti-forensic / log clearing
    'wevtutil cl ','wevtutil clear-log','clear-eventlog',
    'fsutil usn deletejournal','cipher /w:','vssadmin delete shadows',
    # Unsigned-driver service creation
    'sc.exe create','sc create '
)

# LUA / AutoHotkey mouse-macro patterns - anti-recoil + rapid-fire scripts.
# Matched HIGH against .lua / .ahk / .ps1 content.
$ScriptContent_MouseMacro = @(
    # Logitech G HUB / LGS LUA API
    'MoveMouseRelative','MoveMouseTo','GetMousePosition',
    'PressMouseButton','ReleaseMouseButton','PressAndReleaseMouseButton',
    'IsMouseButtonPressed','OnEvent("MOUSE_BUTTON','event == "MOUSE_BUTTON',
    'MOUSE_BUTTON_PRESSED','MOUSE_BUTTON_RELEASED',
    # Razer Synapse
    'rzMacro','rzcustom_macro',
    # Anti-recoil / no-recoil signatures
    'anti_recoil','antirecoil','anti-recoil','no_recoil','norecoil',
    'recoil_compensation','recoil_control','recoilcontrol',
    'rapid_fire_lua','rapidfire_lua',
    # AutoHotkey mouse macro patterns
    'MouseMove,','MouseClick,','SendInput {Click',
    'AutoHotkey_recoil','ahk_recoil'
)

# Lua-script cheat keywords - matched against .lua file NAMES and PATHS
# (Scan-LuaScripts). Distinct from $ScriptContent_MouseMacro which matches
# inside script CONTENT. Name-based catches cheat distributions even when
# the script body is encoded/obfuscated.
$LuaCheat_Keywords = @(
    'aimbot','aim_bot','aim-bot','triggerbot','trigger_bot','wallhack','wall_hack',
    'esp','norecoil','no_recoil','no-recoil','bhop','bunny_hop','bunnyhop',
    'spinbot','spin_bot','radar_hack','radarhack','speedhack','speed_hack',
    'skinchanger','skin_changer','injector','bypass','anticheat','anti_cheat',
    'cheat','hack','exploit','undetected','ud_','loader','ldr_',
    'engineowning','phantomoverlay','lavicheats','skycheats'
)

# Named DLL injectors / cheat loaders. Used by Scan-DLLInjectionTimestamps
# to filter Sysmon Event ID 7 / Security 4688 / Application log / Prefetch.
$DLLInjector_Names = @(
    'injector','inject','xenos','xenos64','extreme_injector','extremeinjector',
    'gdinjector','manual_map','manualmap','loadlibrary_injector',
    'process_hollowing','processhollowing','dllinjector','dll_inject',
    'syringe','chimera','shtreload','winject','winject64',
    'remoteinjection','remoteinjector','shellcode','shellcode_inject'
)

# Network attack / DDoS tools - HIGH if found (no legitimate gaming use).
# Named consumer DDoS clients and gaming-targeted stress tools.
$NetworkAttack_High = @(
    'loic','low orbit ion cannon',
    'hoic','high orbit ion cannon',
    'slowloris','pyloris',
    'goldeneye','goldeneyetool',
    'torshammer','tor hammer',
    'hulk.py','hulk_ddos',
    'rudy','r-u-dead-yet',
    'ufonet',
    'xerxes',
    'andosid',
    'byob_ddos',
    'ddos_attack','ddos_tool','ddostool',
    'booter_client','stresser_client'
)

# Dual-use network tools - MEDIUM. Legitimate sysadmin uses exist but unusual
# on a pure gaming PC.
$NetworkAttack_Medium = @(
    'hping','hping3',
    'masscan',
    'zmap',
    'ostinato',
    'iperf3',
    'tshark'
)

# ----------------------------------------------------------------------------
# v3.8 EXPANSION: game-specific cheat brand arrays + AI-vision aimbots.
# All multi-source / research-confirmed unless noted. Single-source items
# live in $CheatBrands_LowConfidence (emits MEDIUM, never HIGH).
# ----------------------------------------------------------------------------

# CS2 / CS:GO cheat brands (Source 2 era, post-2024 HvH scene).
$CheatBrands_CS2 = @(
    'neverlose','neverlose.cc','nl_loader','nl-loader',
    'memesense','memesense.gg','memes_loader',
    'fatality.win','fatality_loader',
    'primordial.cc','primordial_loader',
    'skeet.cc','gamesense.pub',
    'onetap','onetapv4','onetap.com',
    'aimware','aimware.net',
    'axion-cs2','axion_rage','axion cs2'
)

# Apex Legends cheat brands.
$CheatBrands_Apex = @(
    'kernaim','kernaim.to',
    'cosmocheats apex','cosmoloader',
    'apex_hacksuite','apex-hacksuite'
)

# Escape from Tarkov cheat brands.
$CheatBrands_Tarkov = @(
    'phantom eft','phantom_eft','phantomloader','phantom-eft',
    'cheatvault eft','cheatvault.net',
    'ownage software','ownage_eft','ownagesoftware'
)

# Rust cheat brands.
$CheatBrands_Rust = @(
    'cobracheat','cobra rust','cobra_rust','cobracheats',
    'cobrasn',
    'atomic rust','atomic_rust',
    'cheater.ninja','cheaterninja'
)

# Rainbow Six Siege cheat brands.
$CheatBrands_R6 = @(
    'hyperforcecheats','hyper_force_cheat',
    'cheatvault r6','cheatvault_r6'
)

# Marvel Rivals cheat brands (new title, NetEase Anti-Cheat).
$CheatBrands_MarvelRivals = @(
    'marvel maxim','marvel_maxim','maxim_rivals',
    'elocarry','elocarry.net','elocarry rivals'
)

# Single-source / lower-confidence cheat names. Emit at MEDIUM (dual-use)
# only - HIGH would be a false-positive risk given the thin sourcing.
$CheatBrands_LowConfidence = @(
    'midnight cs2','midnight_cs2',
    'predator cs2','predator_cs2',
    'anyx.gg','anyxcheat',
    'eucheats',
    'siegex',
    'rainbowsixcheats',
    'wh-satano','whsatano',
    'proofcore','proofcore.io',
    'chamscheats',
    'deprimereshop','depshop',
    'sternclient.biz',
    'hackvshack',
    'madchad.net',
    'gulfcheats','gulf_spoofer',
    'moddingassociation'
)

# PC-side AI-vision aimbots. These run on the SAME gaming PC (vs. console-rig
# external AI which is on a separate PC and covered by $VisionAimbots in the
# console driver). They use ONNX / YOLO models + screen capture + virtual
# HID or Arduino Leonardo for mouse movement. Detected as HIGH when present;
# the new Scan-AIVisionArtifacts also flags the supporting Python/ONNX
# constellation.
$VisionAimbot_AI_PC = @(
    'aimmy','aimmy.exe','babyhamsta',
    'sunone_aimbot','sunone_aimbot_2','sunone',
    'rootkit_aimbot','rootkit-ai-aimbot','ai-aimbot',
    'aimahead',
    'zelesisneo','zelesis.com','zelesis_neo',
    'reflex_aimbot','xxreflextheone',
    'aimi_yolov3',
    'yolov8_aimbot','yolov5_aimbot',
    'aim_bot_yolo','magicxuantung',
    'unibot','vike256_unibot',
    'ardoras','kinuzo_ardoras',
    'embedded_aim_assist','pi_aimbot','tharushavj',
    'csmacro_ai','csmacro'
)

# Future browser-history / bookmark scanner targets. NOT used by any current
# scanner; held here so a future Scan-BrowserHistory can consume the same
# list. Domains-only - no path tokens. Match threshold for that scanner must
# require sustained activity (>= 3 visits to >= 2 distinct cheat-marketplace
# domains within the last 6 months) so a single curious click years ago does
# NOT bump verdict.
$CheatMarketplaceDomains = @(
    'skycheats.com','privatecheatz.com','battlelog.co','lavicheats.com',
    'cosmocheats.com','cheatseller.com','kernaim.to','gulfcheats.com',
    'clutch-solution.com','cheatvault.net','hyperforcecheats.com',
    'qlmshop.com','elocarry.net','chamscheats.com','proofcore.io',
    'zsoft.store','deprimereshop.com','cheater.ninja','vredux.com',
    'iniquus.io','infocheats.net','hackvshack.net','exloader.net',
    'anyx.gg','ownagesoftware.com','elitehacks.ru','wh-satano.ru',
    'sternclient.biz','cs2-cheats.com','madchad.net','phoenixlabstore.com',
    'suspectcheats.com','echeats.io','ssz.gg','atomicdma.com',
    'unknowncheats.me','elitepvpers.com','mpgh.net','ownedcore.com',
    'guidedhacking.com','high-minded.cx'
)

# Known cheat-sample SHA256 hashes. Each entry MUST cite its source.
$KnownCheatHashes = @(
    @{
        SHA256 = 'b1b89dedcff0c502d605a707e550b1565224b5949e778168ac45f01b8171160f'
        Name   = 'RUT AND RUAVT LAUNCHER UPDATED.exe (rut.gg)'
        Source = 'Hybrid Analysis sandbox report'
    }
    # Add additional confirmed samples here. Each requires a verifiable source URL.
)

# Known-good vendors for the user-writable location allowlist
$KnownGood = @(
    'microsoft','windows','onedrive','teams','office','edgewebview','msedge',
    'google','chrome','update','slack','discord','zoom','signal','spotify',
    'dropbox','adobe','nvidia','amd','intel','realtek','razer','logitech',
    'corsair','steelseries','dell','hp','lenovo','asus','asustek','msi',
    'steam','epic','battle.net','riot','origin','ubisoft','rockstar',
    'github','vscode','code.exe','jetbrains','notion','postman','docker',
    'python','node','npm','git','antigravity','claude','codex','uv.exe','blender'
)

# Driver publishers whose drivers are explicitly allowed (suppresses the
# "unsigned driver" MEDIUM finding on Scan-Drivers).
#
# Substring matched (regex-escaped, case-insensitive) against the Manufacturer
# field returned by driverquery /si /fo csv. To avoid accidental substring
# matches, short ambiguous tokens are avoided in favor of more specific
# variants (e.g. 'Hewlett-Packard' + 'HP Inc' instead of bare 'HP').
$DriverPublisher_Allowlist = @(
    # --- OS / system / chipset / silicon ---
    'Microsoft','Microsoft Corporation',
    'Intel','Intel Corporation',
    'AMD','Advanced Micro Devices',
    'NVIDIA','NVIDIA Corporation',
    'Realtek',
    'Qualcomm',
    'Broadcom',
    'MediaTek',
    'ASMedia',
    'Synaptics',

    # --- Gaming peripherals ---
    'Logitech',
    'Razer',
    'Corsair',
    'SteelSeries',
    'HyperX',
    'Kingston',
    'Turtle Beach',
    'Roccat',
    'Glorious PC Gaming',
    'Endgame Gear',
    'Pulsar Gaming',
    'Mad Catz',
    'Thrustmaster',
    'Saitek',

    # --- PC / laptop OEMs ---
    'Dell Inc','Dell Computer','Alienware',
    'Hewlett-Packard','HP Inc',
    'Lenovo',
    'Acer Inc','Acer Incorporated','Predator',
    'ASUS','ASUSTeK',
    'Micro-Star','MSI',
    'Gigabyte','GIGA-BYTE','Aorus',
    'ASRock',
    'EVGA',
    'Origin PC',
    'iBuyPower',

    # --- Cases / cooling / PSUs ---
    'Cooler Master',
    'NZXT',
    'Thermaltake',
    'be quiet',
    'Fractal Design',
    'Lian Li',
    'Phanteks',
    'Noctua',
    'Arctic',
    'Antec',
    'SilverStone',
    'Corsair Components',

    # --- Memory / storage ---
    'G.SKILL','G.Skill',
    'Crucial',
    'Micron',
    'Western Digital','SanDisk',
    'Seagate',
    'Samsung Electronics',
    'SK Hynix','SK hynix',

    # --- Monitors / displays ---
    'LG Electronics',
    'BenQ',
    'Zowie',
    'ViewSonic',

    # --- Audio ---
    'Creative Technology','Creative Labs',
    'Sennheiser',
    'EPOS'
)

# Patterns to match in user AppData / Documents for known input-device apps
$AppDataPatterns = @(
    @{ Pattern = 'XIM Technologies'; Label = 'XIM Manager' },
    @{ Pattern = 'XIM*';             Label = 'XIM (other)' },
    @{ Pattern = 'ConsoleTuner';     Label = 'Cronus / Titan' },
    @{ Pattern = 'Cronus*';          Label = 'Cronus' },
    @{ Pattern = 'ZenStudio';        Label = 'Cronus Zen Studio' },
    @{ Pattern = 'ReaSnow*';         Label = 'ReaSnow' }
)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Add-Finding {
    param([string]$Category, [string]$Source, [string]$Detail,
          [ValidateSet('HIGH','MEDIUM','WARN','INFO')] [string]$Severity = 'INFO',
          [string]$Kind = '',
          [hashtable]$Metadata = @{})
    $Findings.Add([pscustomobject]@{
        Severity = $Severity; Category = $Category
        Source = $Source; Detail = $Detail; Metadata = $Metadata
        Kind = $Kind
    }) | Out-Null
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

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
    $hit = Match-Keyword $combined $Keywords_High_Cheats
    if ($hit) { return @{ Score='HIGH'; Kind='cheat'; Pattern=$hit; Reason="matches '$hit' (cheat keyword)" } }
    $hit = Match-Keyword $combined $Keywords_High_Input
    if ($hit) { return @{ Score='HIGH'; Kind='input'; Pattern=$hit; Reason="matches '$hit' (input device)" } }
    $hit = Match-Keyword $combined $Keywords_Medium
    if ($hit) { return @{ Score='MEDIUM'; Kind='dual-use'; Pattern=$hit; Reason="matches '$hit' (dual-use tool)" } }
    $bucket = Classify-PathRisk $Path
    if ($bucket -eq 'user-writable') {
        if (Match-Allowlist "$Path $Name") {
            return @{ Score='CLEAN'; Kind='other'; Pattern=''; Reason='user-writable but known-good vendor' }
        }
        return @{ Score='MEDIUM'; Kind='other'; Pattern=''; Reason='user-writable location, no allowlist match' }
    }
    if ($bucket -eq 'unknown')  { return @{ Score='LOW';   Kind='other'; Pattern=''; Reason='image path not recorded' } }
    if ($bucket -eq 'typical')  { return @{ Score='LOW';   Kind='other'; Pattern=''; Reason='runs from Program Files' } }
    return @{ Score='CLEAN'; Kind='other'; Pattern=''; Reason='standard system location' }
}

function Convert-FileTimeBytes {
    param([byte[]]$Bytes, [int]$Offset = 0)
    if ($null -eq $Bytes -or $Bytes.Length -lt ($Offset + 8)) { return $null }
    try {
        $ft = [BitConverter]::ToInt64($Bytes, $Offset)
        if ($ft -le 0) { return $null }
        [DateTime]::FromFileTime($ft)
    } catch { $null }
}

function Score-And-Add {
    param([string]$Category, [string]$Source, [string]$Text, [string]$DetailPrefix = '', [hashtable]$Metadata = @{})
    $hit = Match-Keyword $Text $Keywords_High_Cheats
    if ($hit) {
        $Metadata['Pattern'] = $hit
        Add-Finding $Category $Source "$DetailPrefix[$hit] $Text" 'HIGH' 'cheat' $Metadata
        return
    }
    $hit = Match-Keyword $Text $Keywords_High_Input
    if ($hit) {
        $Metadata['Pattern'] = $hit
        Add-Finding $Category $Source "$DetailPrefix[$hit] $Text" 'HIGH' 'input' $Metadata
        return
    }
    $hit = Match-Keyword $Text $Keywords_Medium
    if ($hit) {
        $Metadata['Pattern'] = $hit
        Add-Finding $Category $Source "$DetailPrefix[$hit] $Text" 'MEDIUM' 'dual-use' $Metadata
        return
    }
}

# ============================================================================
# SCAN FUNCTIONS
# ============================================================================

function Scan-Prefetch {
    Write-Host '  [*] Prefetch...' -ForegroundColor DarkGray
    $pf = "$env:SystemRoot\Prefetch"
    if (-not (Test-Path $pf)) { return }
    try { $files = Get-ChildItem $pf -Filter '*.pf' -ErrorAction Stop }
    catch { Add-Finding 'Prefetch' $pf 'Access denied (run as admin)' 'WARN' 'other'; return }
    foreach ($f in $files) {
        $meta = @{
            FirstSeen = $f.CreationTime.ToString('s')
            LastModified = $f.LastWriteTime.ToString('s')
        }
        Score-And-Add 'Prefetch' $f.FullName $f.BaseName '' $meta
    }
}

function Scan-BAM {
    Write-Host '  [*] BAM (last execution timestamps)...' -ForegroundColor DarkGray
    foreach ($base in @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
    )) {
        if (-not (Test-Path $base)) { continue }
        try { $sids = Get-ChildItem $base -ErrorAction Stop }
        catch { Add-Finding 'BAM' $base 'Access denied' 'WARN' 'other'; continue }
        foreach ($sid in $sids) {
            try { $key = Get-Item $sid.PSPath -ErrorAction Stop } catch { continue }
            foreach ($vn in $key.GetValueNames()) {
                if ($vn -in @('SequenceNumber','Version')) { continue }
                $bytes = $key.GetValue($vn)
                $lastRun = if ($bytes -is [byte[]]) { Convert-FileTimeBytes $bytes } else { $null }
                $meta = @{
                    Executable = $vn
                    LastExecution = if ($lastRun) { $lastRun.ToString('s') } else { 'unknown' }
                    UserSID = $sid.PSChildName
                }
                $suffix = if ($lastRun) { " - last run: $($lastRun.ToString('s'))" } else { '' }
                Score-And-Add 'BAM' $sid.PSChildName "$vn$suffix" '' $meta
            }
        }
    }
}

function Scan-InstalledSoftware {
    Write-Host '  [*] Installed software...' -ForegroundColor DarkGray
    foreach ($k in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )) {
        $apps = Get-ItemProperty $k -ErrorAction SilentlyContinue
        foreach ($a in $apps) {
            if (-not $a.DisplayName) { continue }
            $id = if ($a.InstallDate -match '^\d{8}$') {
                try { [datetime]::ParseExact($a.InstallDate,'yyyyMMdd',$null).ToString('yyyy-MM-dd') }
                catch { $a.InstallDate }
            } else { $a.InstallDate }
            $meta = @{
                Name = $a.DisplayName; Version = $a.DisplayVersion; Publisher = $a.Publisher
                InstallDate = $id; InstallLocation = $a.InstallLocation; SizeKB = $a.EstimatedSize
            }
            Score-And-Add 'Installed' $a.DisplayName $a.DisplayName '' $meta
        }
    }
}

function Scan-RecentFiles {
    Write-Host '  [*] Recent files...' -ForegroundColor DarkGray
    $recent = "$env:APPDATA\Microsoft\Windows\Recent"
    if (-not (Test-Path $recent)) { return }
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop } catch {}
    Get-ChildItem $recent -Recurse -File -Depth 8 -ErrorAction SilentlyContinue | ForEach-Object {
        $target = $null
        if ($shell -and $_.Extension -eq '.lnk') {
            try { $target = $shell.CreateShortcut($_.FullName).TargetPath } catch {}
        }
        $meta = @{ Target = $target; LastWrite = $_.LastWriteTime.ToString('s') }
        Score-And-Add 'Recent' $_.FullName $_.Name '' $meta
    }
}

function Scan-MUICache {
    Write-Host '  [*] MUICache...' -ForegroundColor DarkGray
    $muiKey = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
    if (-not (Test-Path $muiKey)) { return }
    try { $props = Get-ItemProperty $muiKey -ErrorAction Stop } catch { return }
    foreach ($name in $props.PSObject.Properties.Name) {
        if ($name -match '^PS') { continue }
        $meta = @{ Value = $name; Data = $props.$name }
        Score-And-Add 'MUICache' 'HKCU\...\MuiCache' $name '' $meta
    }
}

function Scan-USBHistory {
    Write-Host '  [*] USB device history...' -ForegroundColor DarkGray
    $usbKey = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'
    if (-not (Test-Path $usbKey)) { return }
    try { $vendors = Get-ChildItem $usbKey -ErrorAction Stop }
    catch { Add-Finding 'USB' $usbKey 'Access denied' 'WARN' 'other'; return }
    $propGuid = '{83da6326-97a6-4088-9453-a1923f573b29}'
    foreach ($v in $vendors) {
        try { $devs = Get-ChildItem $v.PSPath -ErrorAction Stop } catch { continue }
        foreach ($d in $devs) {
            try { $props = Get-ItemProperty $d.PSPath -ErrorAction Stop } catch { continue }
            $blob = "$($props.FriendlyName) | $($props.DeviceDesc) | $($props.Mfg) | $($v.PSChildName)"
            $hit_c = Match-Keyword $blob $Keywords_High_Cheats
            $hit_i = Match-Keyword $blob $Keywords_High_Input
            $hit_m = Match-Keyword $blob $Keywords_Medium
            if (-not ($hit_c -or $hit_i -or $hit_m)) { continue }
            $firstInstall = $lastArrival = $lastRemoval = $null
            $propsPath = Join-Path $d.PSPath "Properties\$propGuid"
            foreach ($e in @(
                @{ Sub = '0064\00000000'; Var = 'firstInstall' },
                @{ Sub = '0065\00000000'; Var = 'lastArrival'  },
                @{ Sub = '0066\00000000'; Var = 'lastRemoval'  }
            )) {
                $p = Join-Path $propsPath $e.Sub
                if (Test-Path $p) {
                    try {
                        $k = Get-Item $p -ErrorAction Stop
                        $bytes = $k.GetValue('(default)'); if ($null -eq $bytes) { $bytes = $k.GetValue('') }
                        $ft = Convert-FileTimeBytes $bytes
                        if ($ft) { Set-Variable -Name $e.Var -Value $ft }
                    } catch {}
                }
            }
            $sev = 'HIGH'; $kind = 'cheat'; $pat = $hit_c
            if (-not $hit_c) { $sev = 'HIGH'; $kind = 'input'; $pat = $hit_i }
            if (-not ($hit_c -or $hit_i)) { $sev = 'MEDIUM'; $kind = 'dual-use'; $pat = $hit_m }
            if ($sev -eq 'HIGH' -and -not $firstInstall -and -not $lastArrival -and -not $lastRemoval) {
                $sev = 'MEDIUM'; if ($kind -eq 'input') { $kind = 'dual-use' }
            }
            $meta = @{
                Pattern = $pat
                FriendlyName = $props.FriendlyName
                VID_PID = $v.PSChildName
                FirstInstall = if ($firstInstall) { $firstInstall.ToString('s') } else { 'unknown' }
                LastArrival = if ($lastArrival) { $lastArrival.ToString('s') } else { 'unknown' }
                LastRemoval = if ($lastRemoval) { $lastRemoval.ToString('s') } else { 'unknown' }
            }
            Add-Finding 'USB' $v.PSChildName "[$pat] $($props.FriendlyName)" $sev $kind $meta
        }
    }
}

function Scan-DriverSigning {
    Write-Host '  [*] BCD driver-signing flags...' -ForegroundColor DarkGray
    try {
        $bcd = & bcdedit /enum '{current}' 2>$null
        if ($LASTEXITCODE -ne 0) { Add-Finding 'BCD' 'bcdedit' 'Cannot read (admin needed)' 'WARN' 'other'; return }
        $ts = ($bcd | Select-String 'testsigning' -SimpleMatch).Line
        if ($ts -match 'Yes') { Add-Finding 'BCD' 'testsigning' 'TEST SIGNING ENABLED - unsigned drivers can load' 'HIGH' 'cheat' @{} }
        $ni = ($bcd | Select-String 'nointegritychecks' -SimpleMatch).Line
        if ($ni -match 'Yes') { Add-Finding 'BCD' 'nointegritychecks' 'Driver integrity checks DISABLED' 'HIGH' 'cheat' @{} }
    } catch { Add-Finding 'BCD' 'bcdedit' "Error" 'WARN' 'other' }
}

function Get-LOLDriversDB {
    # Fetches the LOLDrivers (Living Off The Land Drivers) public CSV from
    # loldrivers.io and builds two lookup indexes:
    #   FileIndex : lowercase .sys filename -> @{ Category; Tags; Id }
    #   HashIndex : lowercase SHA256        -> @{ Category; Tags; Id; Filename }
    # Returns $null if fetch / parse fails.
    #
    # This is the ONLY network call the kit ever makes. It is opt-in: drivers
    # must explicitly call this function (typically gated behind a Y/N prompt
    # or a -SkipLOLDrivers flag). No PC data is sent; only the public CSV is
    # downloaded.

    Write-Host '  [*] Fetching LOLDrivers database (loldrivers.io)...' -ForegroundColor DarkGray

    $url = 'https://www.loldrivers.io/api/drivers.csv'
    try {
        $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $csv  = $resp.Content | ConvertFrom-Csv
    } catch {
        Add-Finding 'LOLDrivers' $url "Failed to fetch LOLDrivers DB: $_" 'WARN' 'other' @{}
        return $null
    }

    $fileIndex = @{}
    $hashIndex = @{}

    foreach ($row in $csv) {
        $cat  = $row.Category     # 'malicious' | 'vulnerable'
        $tags = $row.Tags         # comma-separated driver filenames e.g. "rtcore64.sys,rtcore32.sys"
        $id   = $row.Id

        # Index by every .sys filename in Tags
        foreach ($tag in ($tags -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '\.sys$' })) {
            $key = $tag.ToLower()
            if (-not $fileIndex.ContainsKey($key)) {
                $fileIndex[$key] = @{ Category=$cat; Tags=$tags; Id=$id }
            }
        }

        # Index by SHA256 hashes. LOLDrivers CSV embeds hashes across several
        # possible columns; probe defensively and extract any 64-hex-char run.
        foreach ($col in @('SHA256','Sha256','sha256','KnownVulnerableSamples','Samples')) {
            $val = $row.$col
            if ([string]::IsNullOrWhiteSpace($val)) { continue }
            $hexMatches = [regex]::Matches($val, '[0-9a-fA-F]{64}')
            foreach ($m in $hexMatches) {
                $h = $m.Value.ToLower()
                if (-not $hashIndex.ContainsKey($h)) {
                    $fn = if ($tags -match '\.sys') { ($tags -split ',')[0].Trim() } else { '' }
                    $hashIndex[$h] = @{ Category=$cat; Tags=$tags; Id=$id; Filename=$fn }
                }
            }
        }
    }

    Write-Host "      Loaded $($fileIndex.Count) filename entries, $($hashIndex.Count) hash entries." -ForegroundColor DarkGray
    return @{ FileIndex=$fileIndex; HashIndex=$hashIndex }
}

function Resolve-LOLDriversDB {
    # Orchestrates the LOLDrivers opt-in flow. Returns a DB hashtable (with
    # FileIndex + HashIndex) or $null if the user declined or fetch failed.
    #
    # Behavior:
    #   - If -SkipLOLDrivers, returns $null silently (writes a skip note).
    #   - If a cached DB exists at $env:TEMP\alibi-loldb.clixml and is
    #     less than 1 hour old, uses it silently (covers the unified-launcher
    #     case where PC and console-rig scans run back-to-back).
    #   - Otherwise prompts Y/N. On Y, fetches and writes the cache. On
    #     anything else, returns $null and writes a skip note.
    param([switch]$SkipLOLDrivers)

    if ($SkipLOLDrivers) {
        Add-Finding 'LOLDrivers' 'skipped' 'LOLDrivers cross-reference skipped (-SkipLOLDrivers)' 'INFO' 'other' @{
            Note = 'Remove the -SkipLOLDrivers flag to enable BYOVD detection.'
        }
        return $null
    }

    $cachePath = Join-Path $env:TEMP 'alibi-loldb.clixml'
    if (Test-Path $cachePath) {
        try {
            $age = (Get-Date) - (Get-Item $cachePath).LastWriteTime
            if ($age.TotalHours -lt 1) {
                Write-Host '  [*] LOLDrivers: using cached DB (under 1h old)' -ForegroundColor DarkGray
                $cached = Import-Clixml -Path $cachePath -ErrorAction Stop
                Add-Finding 'LOLDrivers' $cachePath "LOLDrivers DB loaded from local cache (age: $([int]$age.TotalMinutes) min)" 'INFO' 'other' @{
                    CacheFile = $cachePath
                    AgeMinutes = [int]$age.TotalMinutes
                    FilenameEntries = $cached.FileIndex.Count
                    HashEntries = $cached.HashIndex.Count
                }
                return $cached
            }
        } catch {}
    }

    Write-Host ''
    Write-Host '  LOLDrivers cross-reference (loldrivers.io)' -ForegroundColor Yellow
    Write-Host '  Makes ONE network request to fetch the public vulnerable/malicious' -ForegroundColor DarkGray
    Write-Host '  driver database. No data about this PC is sent.' -ForegroundColor DarkGray
    Write-Host '  Press Y to fetch, any other key to skip.' -ForegroundColor Yellow
    $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    Write-Host ''

    if ($key.Character -notin @('y','Y')) {
        Write-Host '  Skipping LOLDrivers fetch.' -ForegroundColor DarkGray
        Add-Finding 'LOLDrivers' 'skipped' 'LOLDrivers cross-reference skipped by user' 'INFO' 'other' @{
            Note = 'Re-run and press Y at the prompt, or pass nothing (default) and press Y, to enable BYOVD detection.'
        }
        return $null
    }

    $db = Get-LOLDriversDB
    if ($db) {
        try { $db | Export-Clixml -Path $cachePath -ErrorAction Stop } catch {}
    }
    return $db
}

function Scan-Drivers {
    # Driver enumeration + (optional) LOLDrivers cross-reference for BYOVD
    # detection. Reads $LOLDb from parent scope - drivers set this to the
    # result of Get-LOLDriversDB (or leave it $null to skip).
    Write-Host '  [*] Driver enumeration + LOLDrivers cross-reference...' -ForegroundColor DarkGray

    # Collect all drivers from driverquery (gives DeviceName + Manufacturer + IsSigned).
    $driverRows = [System.Collections.Generic.List[hashtable]]::new()
    try {
        $dqResults = & driverquery /si /fo csv 2>$null | ConvertFrom-Csv
        foreach ($d in $dqResults) {
            [void]$driverRows.Add(@{
                DeviceName   = $d.DeviceName
                Manufacturer = $d.Manufacturer
                IsSigned     = $d.IsSigned
                FileName     = ''
                FilePath     = ''
                SHA256       = ''
            })
        }
    } catch {
        Add-Finding 'Drivers' 'driverquery' 'driverquery failed' 'WARN' 'other' @{}
    }

    # Enrich with file paths from Win32_SystemDriver - this gives the actual
    # .sys path which we need for LOLDrivers filename and hash matching.
    try {
        $cimDrivers = Get-CimInstance Win32_SystemDriver -ErrorAction Stop
        foreach ($cim in $cimDrivers) {
            $match = $driverRows | Where-Object { $_.DeviceName -eq $cim.Name } | Select-Object -First 1
            $rawPath = $cim.PathName -replace '^\\SystemRoot\\', "$env:SystemRoot\" `
                                     -replace '^\\\?\?\\', ''
            if ($match) {
                $match.FilePath = $rawPath
                $match.FileName = [System.IO.Path]::GetFileName($rawPath)
            } else {
                # In CIM but not driverquery - add a fresh row.
                [void]$driverRows.Add(@{
                    DeviceName   = $cim.Name
                    Manufacturer = $cim.Description
                    IsSigned     = ''
                    FileName     = [System.IO.Path]::GetFileName($rawPath)
                    FilePath     = $rawPath
                    SHA256       = ''
                })
            }
        }
    } catch {}

    # Hash drivers in non-standard locations (vulnerable drivers often get
    # dropped to user-writable paths). Skip Windows\System32 entries - those
    # are the OS's own drivers and not the BYOVD target.
    foreach ($d in $driverRows) {
        if (-not $d.FilePath -or -not (Test-Path $d.FilePath -ErrorAction SilentlyContinue)) { continue }
        $bucket = Classify-PathRisk $d.FilePath
        if ($bucket -in @('user-writable','unknown','typical')) {
            try {
                $hash = (Get-FileHash $d.FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
                $d.SHA256 = $hash.ToLower()
            } catch {}
        }
    }

    # Score each driver against the existing rules + LOLDrivers (if loaded).
    foreach ($d in $driverRows) {
        $meta = @{
            DeviceName   = $d.DeviceName
            Manufacturer = $d.Manufacturer
            IsSigned     = $d.IsSigned
            FileName     = $d.FileName
            FilePath     = $d.FilePath
        }

        # Rule 1: cheat/input keyword match (existing behavior).
        Score-And-Add 'Drivers' $d.DeviceName "$($d.DeviceName) $($d.Manufacturer) $($d.FileName)" '' $meta

        # Rule 2: unsigned driver check (existing behavior).
        if ($d.IsSigned -in @('FALSE','False')) {
            $allow = $false
            foreach ($t in $DriverPublisher_Allowlist) {
                if ($d.Manufacturer -and $d.Manufacturer -match [regex]::Escape($t)) { $allow = $true; break }
            }
            if ((-not $d.Manufacturer -or $d.Manufacturer -eq 'N/A') -and
                $d.DeviceName -match '^(USB|HID|WUDF|Microsoft|Bluetooth)') { $allow = $true }
            if (-not $allow) {
                Add-Finding 'Drivers' $d.DeviceName "UNSIGNED: $($d.DeviceName)" 'MEDIUM' 'dual-use' $meta
            }
        }

        # Rule 3: LOLDrivers cross-reference (only when DB loaded).
        if (-not $LOLDb) { continue }

        $lolHit = $null

        # 3a: filename match (weaker - filenames can be spoofed).
        if ($d.FileName) {
            $fnKey = $d.FileName.ToLower()
            if ($LOLDb.FileIndex.ContainsKey($fnKey)) {
                $lolHit = $LOLDb.FileIndex[$fnKey]
                $lolHit['MatchedBy'] = 'Filename'
            }
        }

        # 3b: SHA256 match (stronger - cryptographic confirmation).
        if (-not $lolHit -and $d.SHA256) {
            if ($LOLDb.HashIndex.ContainsKey($d.SHA256)) {
                $lolHit = $LOLDb.HashIndex[$d.SHA256]
                $lolHit['MatchedBy'] = 'SHA256'
            }
        }

        if (-not $lolHit) { continue }

        $lolMeta = $meta + @{
            LOLDrivers_Id       = $lolHit.Id
            LOLDrivers_Category = $lolHit.Category
            LOLDrivers_Tags     = $lolHit.Tags
            LOLDrivers_MatchBy  = $lolHit.MatchedBy
            SHA256              = $d.SHA256
            LOLDrivers_URL      = "https://www.loldrivers.io/drivers/$($lolHit.Id)/"
        }

        # Verdict tiering:
        #   malicious (any match)       -> HIGH cheat
        #   vulnerable + hash confirmed -> HIGH cheat (confirmed BYOVD candidate)
        #   vulnerable + filename only  -> MEDIUM dual-use (could be different version)
        if ($lolHit.Category -match 'malicious') {
            Add-Finding 'LOLDrivers' $d.FilePath `
                "MALICIOUS DRIVER (LOLDrivers): $($d.FileName) [$($lolHit.MatchedBy) match]" `
                'HIGH' 'cheat' $lolMeta
        } elseif ($lolHit.MatchedBy -eq 'SHA256') {
            Add-Finding 'LOLDrivers' $d.FilePath `
                "VULNERABLE DRIVER - hash confirmed (BYOVD risk): $($d.FileName)" `
                'HIGH' 'cheat' $lolMeta
        } else {
            Add-Finding 'LOLDrivers' $d.FilePath `
                "VULNERABLE DRIVER - filename match (BYOVD risk): $($d.FileName)" `
                'MEDIUM' 'dual-use' $lolMeta
        }
    }
}

function Get-DownloadSourceUrl {
    param([string]$Path)
    try {
        $ads = Get-Content -Path $Path -Stream 'Zone.Identifier' -ErrorAction Stop
        @{
            HostUrl     = ($ads | Where-Object { $_ -match '^HostUrl=' })     -replace '^HostUrl=', ''
            ReferrerUrl = ($ads | Where-Object { $_ -match '^ReferrerUrl=' }) -replace '^ReferrerUrl=', ''
        }
    } catch { $null }
}

function Scan-Downloads {
    Write-Host '  [*] Downloads folder...' -ForegroundColor DarkGray
    $dl = "$env:USERPROFILE\Downloads"
    if (-not (Test-Path $dl)) { return }
    Get-ChildItem $dl -Recurse -File -Depth 8 -ErrorAction SilentlyContinue | ForEach-Object {
        $zone = Get-DownloadSourceUrl $_.FullName
        $meta = @{
            FileName = $_.Name; SizeBytes = $_.Length
            Created = $_.CreationTime.ToString('s'); LastWrite = $_.LastWriteTime.ToString('s')
            DownloadedFrom = if ($zone) { $zone.HostUrl } else { '(no source)' }
        }
        $suffix = if ($zone -and $zone.HostUrl) { " - from: $($zone.HostUrl)" } else { '' }
        Score-And-Add 'Downloads' $_.FullName "$($_.Name)$suffix" '' $meta
    }
}

function Scan-Services-Trace {
    Write-Host '  [*] Services (keyword pass)...' -ForegroundColor DarkGray
    $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    try { $svcs = Get-ChildItem $svcKey -ErrorAction Stop }
    catch { Add-Finding 'Services' $svcKey 'Access denied' 'WARN' 'other'; return }
    foreach ($s in $svcs) {
        try { $p = Get-ItemProperty $s.PSPath -ErrorAction Stop } catch { continue }
        $meta = @{ ServiceName = $s.PSChildName; DisplayName = $p.DisplayName; ImagePath = $p.ImagePath }
        $blob = "$($s.PSChildName) | $($p.DisplayName) | $($p.ImagePath)"
        Score-And-Add 'Services' $s.PSChildName $blob '' $meta
    }
}

function Scan-DMABuildArtifacts {
    Write-Host '  [*] DMA build artifacts...' -ForegroundColor DarkGray
    $roots = @(
        "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Downloads", "$env:USERPROFILE\source",
        "$env:USERPROFILE\Projects"
    ) | Where-Object { Test-Path $_ }
    foreach ($root in $roots) {
        Get-ChildItem $root -Recurse -File -Depth 8 -Filter '*_top.bin' -ErrorAction SilentlyContinue | ForEach-Object {
            Add-Finding 'DMA' $_.FullName "pcileech firmware build output: $($_.Name)" 'HIGH' 'cheat' @{
                FileName = $_.Name; FullPath = $_.FullName
                Created = $_.CreationTime.ToString('s')
            }
        }
        Get-ChildItem $root -Recurse -Directory -Depth 8 -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)pcileech' } | ForEach-Object {
            Add-Finding 'DMA' $_.FullName "pcileech directory: $($_.Name)" 'HIGH' 'cheat' @{
                Directory = $_.FullName; Created = $_.CreationTime.ToString('s')
            }
        }
    }
}

function Scan-ApplicationData {
    Write-Host '  [*] Application data dirs...' -ForegroundColor DarkGray
    $roots = @($env:APPDATA, $env:LOCALAPPDATA, "$env:USERPROFILE\Documents") |
        Where-Object { $_ -and (Test-Path $_) }
    foreach ($root in $roots) {
        foreach ($appPattern in $AppDataPatterns) {
            $matches = Get-ChildItem $root -Directory -Filter $appPattern.Pattern -ErrorAction SilentlyContinue
            foreach ($dir in $matches) {
                try { $files = Get-ChildItem $dir.FullName -Recurse -File -Depth 8 -ErrorAction SilentlyContinue } catch { continue }
                if (-not $files -or $files.Count -eq 0) {
                    Add-Finding 'AppData' $dir.FullName "$($appPattern.Label) data dir (empty)" 'MEDIUM' 'input' @{
                        Label = $appPattern.Label; Directory = $dir.FullName; FileCount = 0
                    }
                    continue
                }
                $oldest = ($files | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime
                $newest = ($files | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
                $span = $newest - $oldest
                $distinctDays = ($files | Select-Object @{N='d';E={$_.LastWriteTime.Date}} | Sort-Object d -Unique).Count
                Add-Finding 'AppData' $dir.FullName "$($appPattern.Label) - $($files.Count) files, $distinctDays distinct days" 'HIGH' 'input' @{
                    Label = $appPattern.Label; Directory = $dir.FullName
                    FileCount = $files.Count; DistinctActivityDays = $distinctDays
                    ActivitySpanDays = [int]$span.TotalDays
                    OldestWrite = $oldest.ToString('s'); NewestWrite = $newest.ToString('s')
                }
            }
        }
    }
}

function Scan-ShimCache {
    Write-Host '  [*] ShimCache...' -ForegroundColor DarkGray
    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
    if (-not (Test-Path $key)) { Add-Finding 'ShimCache' $key 'Not present or admin needed' 'WARN' 'other'; return }
    try {
        $props = Get-ItemProperty $key -ErrorAction Stop
        $blob = $props.AppCompatCache
        if (-not $blob) { return }
        Add-Finding 'ShimCache' $key 'AppCompatCache blob present' 'INFO' 'other' @{
            BlobSizeBytes = $blob.Length
            Note = 'Binary format. Parse offline with AppCompatCacheParser for full executable history.'
        }
    } catch { Add-Finding 'ShimCache' $key "Access denied" 'WARN' 'other' }
}

function Scan-UserScriptContents {
    Write-Host '  [*] User-folder script contents (reads .bat / .cmd / .ps1 / .lua / .ahk)...' -ForegroundColor DarkGray

    $selfDir = if ($PSScriptRoot) { $PSScriptRoot.ToLower() } else { '' }
    $excludeNames = @('forensic-scan.ps1','console-rig-audit.ps1','generate-visual-companion.ps1','forensic-common.ps1','generate-visual-companion-console.ps1')

    $scanRoots = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads"
    )
    foreach ($extra in @(
        "$env:USERPROFILE\source", "$env:USERPROFILE\Projects",
        "$env:USERPROFILE\Scripts", "$env:USERPROFILE\Tools",
        "$env:USERPROFILE\Cheats", "$env:USERPROFILE\Game",
        "$env:USERPROFILE\Games", "$env:USERPROFILE\bin"
    )) {
        if (Test-Path $extra) { $scanRoots += $extra }
    }
    $scanRoots = $scanRoots | Where-Object { Test-Path $_ }

    $scriptFiles = [System.Collections.Generic.List[object]]::new()
    foreach ($root in $scanRoots) {
        foreach ($ext in @('*.bat','*.cmd','*.ps1','*.vbs','*.wsf','*.psm1','*.lua','*.ahk')) {
            try {
                Get-ChildItem $root -Recurse -File -Depth 8 -Filter $ext -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.Length -lt 10MB -and
                        ($_.Name.ToLower() -notin $excludeNames) -and
                        (-not ($selfDir -and $_.DirectoryName.ToLower().StartsWith($selfDir)))
                    } |
                    ForEach-Object { [void]$scriptFiles.Add($_) }
            } catch {}
        }
    }

    $cap = 2000
    if ($scriptFiles.Count -gt $cap) {
        Add-Finding 'UserScripts' '(scan)' "Found $($scriptFiles.Count) scripts in user folders; scanning first $cap by modification time" 'WARN' 'other' @{ Found = $scriptFiles.Count; Scanned = $cap }
        $scriptFiles = @($scriptFiles | Sort-Object LastWriteTime -Descending | Select-Object -First $cap)
    }

    foreach ($f in $scriptFiles) {
        try {
            $content = ''
            $readSize = [math]::Min([int]$f.Length, 204800)
            if ($readSize -le 0) { continue }
            $bytes = New-Object byte[] $readSize
            $fs = [System.IO.File]::OpenRead($f.FullName)
            try { [void]$fs.Read($bytes, 0, $readSize) } finally { $fs.Close() }
            try { $content = [System.Text.Encoding]::UTF8.GetString($bytes) } catch {}
            if ([string]::IsNullOrWhiteSpace($content)) {
                try { $content = [System.Text.Encoding]::ASCII.GetString($bytes) } catch {}
            }
            if ([string]::IsNullOrWhiteSpace($content)) { continue }

            $rel = $f.FullName
            if ($env:USERPROFILE) { $rel = $rel -replace [regex]::Escape($env:USERPROFILE), '~' }

            $baseMeta = @{
                FileName  = $f.Name
                FullPath  = $f.FullName
                SizeBytes = $f.Length
                LastWrite = $f.LastWriteTime.ToString('s')
            }

            $hit = Match-Keyword $content $Keywords_High_Cheats
            if ($hit) {
                $meta = $baseMeta.Clone(); $meta['Pattern'] = $hit; $meta['MatchKind'] = 'cheat-brand in script'
                Add-Finding 'UserScripts' $f.FullName "[$hit] $rel - cheat keyword inside script content" 'HIGH' 'cheat' $meta
                continue
            }
            $hit = Match-Keyword $content $Keywords_High_Input
            if ($hit) {
                $meta = $baseMeta.Clone(); $meta['Pattern'] = $hit; $meta['MatchKind'] = 'input-device in script'
                Add-Finding 'UserScripts' $f.FullName "[$hit] $rel - input-device keyword inside script content" 'HIGH' 'input' $meta
                continue
            }
            $hit = Match-Keyword $content $Keywords_ScriptHigh
            if ($hit) {
                $meta = $baseMeta.Clone(); $meta['Pattern'] = $hit; $meta['MatchKind'] = 'high-risk command in script'
                Add-Finding 'UserScripts' $f.FullName "[$hit] $rel - high-risk command pattern inside script" 'HIGH' 'cheat' $meta
                continue
            }
            $hit = Match-Keyword $content $Keywords_MouseMacro
            if ($hit) {
                $meta = $baseMeta.Clone(); $meta['Pattern'] = $hit; $meta['MatchKind'] = 'mouse-macro / anti-recoil script'
                Add-Finding 'UserScripts' $f.FullName "[$hit] $rel - mouse-macro / anti-recoil script pattern" 'HIGH' 'cheat' $meta
                continue
            }
            $hit = Match-Keyword $content $Keywords_Medium
            if ($hit) {
                $meta = $baseMeta.Clone(); $meta['Pattern'] = $hit; $meta['MatchKind'] = 'dual-use in script'
                Add-Finding 'UserScripts' $f.FullName "[$hit] $rel - dual-use keyword inside script content" 'MEDIUM' 'dual-use' $meta
                continue
            }
        } catch {}
    }
}

function Scan-ObscuredFileNames {
    Write-Host '  [*] Obscured filenames (hex / numeric-only .exe / .dll / .lua in user folders)...' -ForegroundColor DarkGray

    $roots = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads"
    )
    foreach ($extra in @(
        "$env:USERPROFILE\source", "$env:USERPROFILE\Projects",
        "$env:USERPROFILE\Scripts", "$env:USERPROFILE\Tools",
        "$env:USERPROFILE\Cheats", "$env:USERPROFILE\Game",
        "$env:USERPROFILE\Games", "$env:USERPROFILE\bin"
    )) {
        if (Test-Path $extra) { $roots += $extra }
    }
    $roots = $roots | Where-Object { Test-Path $_ }

    $extWatchlist = @('.exe','.dll','.bat','.cmd','.ps1','.vbs','.lua','.ahk','.sys','.bin')

    foreach ($root in $roots) {
        try {
            Get-ChildItem $root -Recurse -File -Depth 8 -ErrorAction SilentlyContinue |
                Where-Object { $extWatchlist -contains $_.Extension.ToLower() -and $_.Length -lt 100MB } |
                ForEach-Object {
                    $name = $_.BaseName
                    $reason = ''
                    if ($name -match '^0x[0-9a-fA-F]+$') { $reason = "0x-prefix hex name ($name$($_.Extension))" }
                    elseif ($name -match '^[0-9a-fA-F]{8,}$' -and $name -match '[a-fA-F]') { $reason = "raw hex name ($name$($_.Extension))" }
                    elseif ($name -match '^\d{4,}$') { $reason = "pure-numeric name ($name$($_.Extension))" }
                    elseif ($name -match '^[a-zA-Z0-9]{1,2}$' -and $name -notin @('go','vc','7z','C','x')) { $reason = "ultra-short obscured name ($name$($_.Extension))" }
                    if ($reason) {
                        Add-Finding 'ObscuredNames' $_.FullName "Obscured filename: $reason" 'MEDIUM' 'dual-use' @{
                            FileName = $_.Name; FullPath = $_.FullName; Pattern = $reason
                            SizeBytes = $_.Length; LastWrite = $_.LastWriteTime.ToString('s')
                        }
                    }
                }
        } catch {}
    }
}

function Scan-ProcessModules {
    Write-Host '  [*] Process modules (DLLs loaded into running processes)...' -ForegroundColor DarkGray
    $procs = $null
    try { $procs = Get-Process -ErrorAction Stop } catch { return }
    $totalScanned = 0
    $globalCap = 8000   # hard cap across ALL processes — typical machine scans ~3000-5000 modules
    :proc foreach ($p in $procs) {
        if ($totalScanned -ge $globalCap) { break }
        $procName = $p.Name
        if ($procName -in @('Idle','System','Registry','Memory Compression')) { continue }
        $mods = $null
        try { $mods = $p.Modules } catch { continue }
        if (-not $mods -or $mods.Count -eq 0) { continue }
        $modList = if ($mods.Count -gt 300) { $mods | Select-Object -First 300 } else { $mods }
        foreach ($m in $modList) {
            if ($totalScanned -ge $globalCap) { break proc }
            $modPath = ''
            $modName = ''
            try { $modPath = $m.FileName; $modName = $m.ModuleName } catch { continue }
            if ([string]::IsNullOrWhiteSpace($modPath)) { continue }
            if ($modPath -eq $p.Path) { continue }
            $totalScanned++
            $hit = Match-Keyword "$modName $modPath" $Keywords_High_Cheats
            if ($hit) {
                Add-Finding 'ProcessModules' "$procName (PID $($p.Id))" "[$hit] $modName loaded into $procName" 'HIGH' 'cheat' @{
                    Pattern=$hit; ProcessName=$procName; ProcessId=$p.Id; ModuleName=$modName; ModulePath=$modPath
                }
                continue
            }
            $hit = Match-Keyword "$modName $modPath" $Keywords_High_Input
            if ($hit) {
                Add-Finding 'ProcessModules' "$procName (PID $($p.Id))" "[$hit] $modName loaded into $procName" 'HIGH' 'input' @{
                    Pattern=$hit; ProcessName=$procName; ProcessId=$p.Id; ModuleName=$modName; ModulePath=$modPath
                }
                continue
            }
            $bucket = Classify-PathRisk $modPath
            if ($bucket -eq 'user-writable') {
                if (-not (Match-Allowlist "$modPath $modName")) {
                    Add-Finding 'ProcessModules' "$procName (PID $($p.Id))" "DLL loaded from user-writable path: $modName loaded into $procName" 'MEDIUM' 'dual-use' @{
                        ProcessName=$procName; ProcessId=$p.Id; ModuleName=$modName; ModulePath=$modPath
                        Reason='DLL loaded from user-writable location, not on known-good vendor allowlist - common pattern for injected cheat DLLs'
                    }
                }
            }
        }
    }
    Add-Finding 'ProcessModules' '(scan)' "Scanned $totalScanned DLL modules across all running processes" 'INFO' 'other' @{ ModulesScanned = $totalScanned }
}

function Scan-KnownHashes {
    Write-Host '  [*] Known cheat hashes (SHA256 of user-folder executables)...' -ForegroundColor DarkGray
    if ($KnownCheatHashes.Count -eq 0) { return }
    $hashLookup = @{}
    foreach ($h in $KnownCheatHashes) { $hashLookup[$h.SHA256.ToLower()] = $h }

    $roots = @(
        "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Documents",
        "$env:USERPROFILE\Downloads"
    )
    foreach ($extra in @(
        "$env:USERPROFILE\source", "$env:USERPROFILE\Projects",
        "$env:USERPROFILE\Scripts", "$env:USERPROFILE\Tools",
        "$env:USERPROFILE\Cheats", "$env:USERPROFILE\Game",
        "$env:USERPROFILE\Games", "$env:USERPROFILE\bin",
        "$env:APPDATA", "$env:LOCALAPPDATA"
    )) {
        if (Test-Path $extra) { $roots += $extra }
    }
    $roots = $roots | Where-Object { Test-Path $_ }

    $candidates = [System.Collections.Generic.List[object]]::new()
    foreach ($root in $roots) {
        foreach ($ext in @('*.exe','*.dll')) {
            try {
                Get-ChildItem $root -Recurse -File -Depth 8 -Filter $ext -ErrorAction SilentlyContinue |
                    Where-Object { $_.Length -lt 100MB -and $_.Length -gt 0 } |
                    ForEach-Object { [void]$candidates.Add($_) }
            } catch {}
        }
    }

    $cap = 500
    if ($candidates.Count -gt $cap) {
        $candidates = @($candidates | Sort-Object LastWriteTime -Descending | Select-Object -First $cap)
        Add-Finding 'KnownHashes' '(scan)' "Found $($candidates.Count) executables in user folders; hashing newest $cap" 'INFO' 'other' @{ Found = $candidates.Count; Hashed = $cap }
    }

    $hashedCount = 0
    foreach ($f in $candidates) {
        try {
            $h = Get-FileHash $f.FullName -Algorithm SHA256 -ErrorAction Stop
            $hashedCount++
            $hashLc = $h.Hash.ToLower()
            if ($hashLookup.ContainsKey($hashLc)) {
                $info = $hashLookup[$hashLc]
                Add-Finding 'KnownHashes' $f.FullName "[$($info.Name)] hash match - confirmed cheat sample" 'HIGH' 'cheat' @{
                    Pattern=$info.Name; SHA256=$h.Hash; FileName=$f.Name; FullPath=$f.FullName
                    SizeBytes=$f.Length; LastWrite=$f.LastWriteTime.ToString('s')
                    KnownSampleOf=$info.Name; HashSource=$info.Source
                }
            }
        } catch {}
    }
    Add-Finding 'KnownHashes' '(scan)' "Hashed $hashedCount executables, checked against $($KnownCheatHashes.Count) known-bad SHA256 sample(s)" 'INFO' 'other' @{ Hashed=$hashedCount; DatabaseSize=$KnownCheatHashes.Count }
}

function Scan-LuaScripts {
    Write-Host '  [*] Lua scripts (name + path keyword match)...' -ForegroundColor DarkGray
    $roots = @(
        "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Downloads", "$env:USERPROFILE\AppData\Roaming",
        "$env:USERPROFILE\AppData\Local", "$env:USERPROFILE\source",
        "$env:USERPROFILE\Projects", "$env:USERPROFILE\Games"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $roots) {
        Get-ChildItem $root -Recurse -File -Depth 8 -Filter '*.lua' -ErrorAction SilentlyContinue | ForEach-Object {
            $file = $_
            $zone = Get-DownloadSourceUrl $file.FullName
            $meta = @{
                FileName       = $file.Name
                FullPath       = $file.FullName
                SizeBytes      = $file.Length
                Created        = $file.CreationTime.ToString('s')
                LastWrite      = $file.LastWriteTime.ToString('s')
                DownloadedFrom = if ($zone -and $zone.HostUrl) { $zone.HostUrl } else { '(no source)' }
            }

            $lc = "$($file.Name) $($file.FullName)".ToLower()

            $hit = $null
            foreach ($kw in $LuaCheat_Keywords) {
                if ($lc -match [regex]::Escape($kw.ToLower())) { $hit = $kw; break }
            }
            if ($hit) {
                $meta['Pattern'] = $hit
                Add-Finding 'LuaScript' $file.FullName "[$hit] $($file.Name)" 'HIGH' 'cheat' $meta
                return
            }

            $hitC = Match-Keyword $lc $Keywords_High_Cheats
            if ($hitC) {
                $meta['Pattern'] = $hitC
                Add-Finding 'LuaScript' $file.FullName "[$hitC] $($file.Name)" 'HIGH' 'cheat' $meta
                return
            }
            $hitI = Match-Keyword $lc $Keywords_High_Input
            if ($hitI) {
                $meta['Pattern'] = $hitI
                Add-Finding 'LuaScript' $file.FullName "[$hitI] $($file.Name)" 'HIGH' 'input' $meta
                return
            }

            # No cheat or input-device keyword. Emit at INFO so the file is listed
            # in the report (game-mod / G-HUB Lua / Neovim configs commonly show
            # up here) but the verdict is not bumped to UNSURE on its own.
            if (-not (Match-Allowlist $file.FullName)) {
                Add-Finding 'LuaScript' $file.FullName "Unrecognized Lua script (no cheat indicator): $($file.Name)" 'INFO' 'other' $meta
            }
        }
    }
}

function Scan-DLLInjectionTimestamps {
    Write-Host '  [*] DLL injection timestamps (Sysmon + Event Log + Prefetch)...' -ForegroundColor DarkGray

    $injectorPattern = ($DLLInjector_Names | ForEach-Object { [regex]::Escape($_) }) -join '|'
    $found = [System.Collections.Generic.List[hashtable]]::new()

    # Time-window filter: align with recency-decay rule (no point pulling
    # events older than 180 days because they'd be filtered out anyway).
    # -FilterHashtable is server-side-filtered; far faster than -MaxEvents
    # followed by Where-Object on a busy Windows machine.
    $eventCutoff = (Get-Date).AddDays(-180)

    # Source 1: Sysmon Event ID 7 (Image Loaded) - best source when available.
    try {
        $sysmonEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            Id        = 7
            StartTime = $eventCutoff
        } -MaxEvents 2000 -ErrorAction Stop
        foreach ($ev in $sysmonEvents) {
            $xml  = [xml]$ev.ToXml()
            $data = @{}
            foreach ($node in $xml.Event.EventData.Data) { $data[$node.Name] = $node.'#text' }
            $imgPath = $data['ImageLoaded']
            if ([string]::IsNullOrWhiteSpace($imgPath)) { continue }
            $imgName = [System.IO.Path]::GetFileName($imgPath).ToLower()
            if ($imgName -notmatch "($injectorPattern)") { continue }
            [void]$found.Add(@{
                Source      = 'Sysmon EID 7'
                Timestamp   = $ev.TimeCreated.ToString('s')
                ImageLoaded = $imgPath
                TargetProc  = $data['Image']
                ProcessId   = $data['ProcessId']
                Hashes      = $data['Hashes']
                Signed      = $data['Signed']
                Signature   = $data['Signature']
            })
        }
    } catch {
        Add-Finding 'DLLInject' 'Sysmon' 'Sysmon not available (not installed or access denied) - install for full DLL-load telemetry' 'WARN' 'other' @{}
    }

    # Source 2: Security Event ID 4688 (Process Create).
    # -FilterHashtable with StartTime is dramatically faster than -FilterXPath
    # on busy machines because the event log service does the filtering.
    try {
        $secEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4688
            StartTime = $eventCutoff
        } -MaxEvents 2000 -ErrorAction Stop
        foreach ($ev in $secEvents) {
            $xml  = [xml]$ev.ToXml()
            $data = @{}
            foreach ($node in $xml.Event.EventData.Data) { $data[$node.Name] = $node.'#text' }
            $newProc = $data['NewProcessName']
            if ([string]::IsNullOrWhiteSpace($newProc)) { continue }
            $procName = [System.IO.Path]::GetFileName($newProc).ToLower()
            if ($procName -notmatch "($injectorPattern)") { continue }
            [void]$found.Add(@{
                Source      = 'Security EID 4688'
                Timestamp   = $ev.TimeCreated.ToString('s')
                ImageLoaded = $newProc
                TargetProc  = $data['ParentProcessName']
                ProcessId   = $data['NewProcessId']
                Hashes      = ''
                Signed      = ''
                Signature   = ''
            })
        }
    } catch {}

    # Source 3: Application Event Log (generic fallback).
    try {
        $appEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Application'
            StartTime = $eventCutoff
        } -MaxEvents 1500 -ErrorAction Stop |
            Where-Object { $_.Message -match "($injectorPattern)" }
        foreach ($ev in $appEvents) {
            [void]$found.Add(@{
                Source      = 'Application EventLog'
                Timestamp   = $ev.TimeCreated.ToString('s')
                ImageLoaded = "EventLog message match: $($ev.Message.Substring(0,[math]::Min(200,$ev.Message.Length)))"
                TargetProc  = ''
                ProcessId   = ''
                Hashes      = ''
                Signed      = ''
                Signature   = ''
            })
        }
    } catch {}

    # Source 4: Prefetch cross-reference for injector executables.
    $pfPath = "$env:SystemRoot\Prefetch"
    if (Test-Path $pfPath) {
        try {
            Get-ChildItem $pfPath -Filter '*.pf' -ErrorAction Stop | ForEach-Object {
                $pfName = $_.BaseName.ToLower()
                if ($pfName -notmatch "($injectorPattern)") { return }
                [void]$found.Add(@{
                    Source      = 'Prefetch'
                    Timestamp   = $_.LastWriteTime.ToString('s')
                    ImageLoaded = $_.FullName
                    TargetProc  = ''
                    ProcessId   = ''
                    Hashes      = ''
                    Signed      = ''
                    Signature   = "FirstSeen: $($_.CreationTime.ToString('s'))"
                })
            }
        } catch {}
    }

    if ($found.Count -eq 0) {
        Add-Finding 'DLLInject' 'EventLog' 'No DLL injector events found in available event sources' 'INFO' 'other' @{
            Note = 'Checked: Sysmon EID 7, Security EID 4688, Application log, Prefetch'
        }
        return
    }

    $dedup = @{}
    foreach ($f in $found) {
        $key = "$($f.ImageLoaded)|$($f.Timestamp)"
        if (-not $dedup.ContainsKey($key)) { $dedup[$key] = $f }
    }

    foreach ($ev in ($dedup.Values | Sort-Object { $_.Timestamp } -Descending)) {
        $meta = @{
            Source        = $ev.Source
            Timestamp     = $ev.Timestamp
            ImageLoaded   = $ev.ImageLoaded
            TargetProcess = $ev.TargetProc
            ProcessId     = $ev.ProcessId
        }
        if ($ev.Hashes)    { $meta['Hashes']    = $ev.Hashes }
        if ($ev.Signed)    { $meta['Signed']    = $ev.Signed }
        if ($ev.Signature) { $meta['Signature'] = $ev.Signature }

        # Safe filename extraction - Application log entries are full message
        # strings, not paths. Split on slashes; truncate if no separators.
        $imgName = try {
            $raw = $ev.ImageLoaded
            if ($raw -match '[/\\]') {
                ($raw -split '[/\\]' | Where-Object { $_ -ne '' } | Select-Object -Last 1).Trim()
            } elseif ($raw.Length -gt 80) {
                $raw.Substring(0, 80) + '...'
            } else {
                $raw
            }
        } catch { $ev.ImageLoaded }

        Add-Finding 'DLLInject' $ev.Source `
            "Injector activity: $imgName @ $($ev.Timestamp)" `
            'MEDIUM' 'dual-use' $meta
    }
}

function Scan-NetworkAttackTools {
    Write-Host '  [*] Network attack / DDoS tools...' -ForegroundColor DarkGray

    function Score-NetworkBlob {
        param([string]$Blob)
        if ([string]::IsNullOrWhiteSpace($Blob)) { return $null }
        $lc = $Blob.ToLower()
        foreach ($kw in $NetworkAttack_High) {
            if ($lc -match [regex]::Escape($kw.ToLower())) { return @{ Sev='HIGH'; Kind='cheat'; Pat=$kw } }
        }
        foreach ($kw in $NetworkAttack_Medium) {
            if ($lc -match [regex]::Escape($kw.ToLower())) { return @{ Sev='MEDIUM'; Kind='dual-use'; Pat=$kw } }
        }
        return $null
    }

    # Source 1: Prefetch.
    $pfPath = "$env:SystemRoot\Prefetch"
    if (Test-Path $pfPath) {
        try {
            Get-ChildItem $pfPath -Filter '*.pf' -ErrorAction Stop | ForEach-Object {
                $s = Score-NetworkBlob $_.BaseName
                if (-not $s) { return }
                Add-Finding 'NetAttack' $_.FullName `
                    "[$($s.Pat)] DDoS/attack tool in Prefetch: $($_.BaseName)" `
                    $s.Sev $s.Kind @{
                        Pattern      = $s.Pat
                        PrefetchFile = $_.Name
                        FirstSeen    = $_.CreationTime.ToString('s')
                        LastRun      = $_.LastWriteTime.ToString('s')
                    }
            }
        } catch { Add-Finding 'NetAttack' $pfPath 'Prefetch access denied (run as admin)' 'WARN' 'other' @{} }
    }

    # Source 2: BAM (last execution timestamps).
    foreach ($base in @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
    )) {
        if (-not (Test-Path $base)) { continue }
        try { $sids = Get-ChildItem $base -ErrorAction Stop } catch { continue }
        foreach ($sid in $sids) {
            try { $key = Get-Item $sid.PSPath -ErrorAction Stop } catch { continue }
            foreach ($vn in $key.GetValueNames()) {
                if ($vn -in @('SequenceNumber','Version')) { continue }
                $s = Score-NetworkBlob $vn
                if (-not $s) { continue }
                $bytes = $key.GetValue($vn)
                $lastRun = if ($bytes -is [byte[]]) { Convert-FileTimeBytes $bytes } else { $null }
                Add-Finding 'NetAttack' $sid.PSChildName `
                    "[$($s.Pat)] DDoS/attack tool execution: $vn" `
                    $s.Sev $s.Kind @{
                        Pattern       = $s.Pat
                        Executable    = $vn
                        LastExecution = if ($lastRun) { $lastRun.ToString('s') } else { 'unknown' }
                        UserSID       = $sid.PSChildName
                    }
            }
        }
    }

    # Source 3: Installed software.
    foreach ($k in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )) {
        $apps = Get-ItemProperty $k -ErrorAction SilentlyContinue
        foreach ($a in $apps) {
            if (-not $a.DisplayName) { continue }
            $s = Score-NetworkBlob "$($a.DisplayName) $($a.Publisher)"
            if (-not $s) { continue }
            $id = if ($a.InstallDate -match '^\d{8}$') {
                try { [datetime]::ParseExact($a.InstallDate,'yyyyMMdd',$null).ToString('yyyy-MM-dd') }
                catch { $a.InstallDate }
            } else { $a.InstallDate }
            Add-Finding 'NetAttack' $a.DisplayName `
                "[$($s.Pat)] DDoS/attack tool installed: $($a.DisplayName)" `
                $s.Sev $s.Kind @{
                    Pattern     = $s.Pat
                    Name        = $a.DisplayName
                    Publisher   = $a.Publisher
                    InstallDate = $id
                    Version     = $a.DisplayVersion
                }
        }
    }

    # Source 4: Downloads folder (with Zone.Identifier source URL).
    $dl = "$env:USERPROFILE\Downloads"
    if (Test-Path $dl) {
        Get-ChildItem $dl -Recurse -File -Depth 8 -ErrorAction SilentlyContinue | ForEach-Object {
            $s = Score-NetworkBlob $_.Name
            if (-not $s) { return }
            $zone = Get-DownloadSourceUrl $_.FullName
            Add-Finding 'NetAttack' $_.FullName `
                "[$($s.Pat)] DDoS/attack tool in Downloads: $($_.Name)" `
                $s.Sev $s.Kind @{
                    Pattern        = $s.Pat
                    FileName       = $_.Name
                    SizeBytes      = $_.Length
                    Created        = $_.CreationTime.ToString('s')
                    LastWrite      = $_.LastWriteTime.ToString('s')
                    DownloadedFrom = if ($zone -and $zone.HostUrl) { $zone.HostUrl } else { '(no source)' }
                }
        }
    }

    # Source 5: MUICache (records executables ever launched by the user).
    $muiKey = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
    if (Test-Path $muiKey) {
        try {
            $props = Get-ItemProperty $muiKey -ErrorAction Stop
            foreach ($name in $props.PSObject.Properties.Name) {
                if ($name -match '^PS') { continue }
                $s = Score-NetworkBlob $name
                if (-not $s) { continue }
                Add-Finding 'NetAttack' 'HKCU\...\MuiCache' `
                    "[$($s.Pat)] DDoS/attack tool ever launched: $name" `
                    $s.Sev $s.Kind @{
                        Pattern = $s.Pat
                        Value   = $name
                        Data    = $props.$name
                    }
            }
        } catch {}
    }

    # Source 6: Recent Files shell links.
    $recent = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recent) {
        $shell = $null
        try { $shell = New-Object -ComObject WScript.Shell -ErrorAction Stop } catch {}
        Get-ChildItem $recent -Recurse -File -Depth 8 -ErrorAction SilentlyContinue | ForEach-Object {
            $s = Score-NetworkBlob $_.Name
            if (-not $s) { return }
            $target = $null
            if ($shell -and $_.Extension -eq '.lnk') {
                try { $target = $shell.CreateShortcut($_.FullName).TargetPath } catch {}
            }
            Add-Finding 'NetAttack' $_.FullName `
                "[$($s.Pat)] DDoS/attack tool in Recent files: $($_.Name)" `
                $s.Sev $s.Kind @{
                    Pattern   = $s.Pat
                    Target    = $target
                    LastWrite = $_.LastWriteTime.ToString('s')
                }
        }
    }
}

function Scan-AIVisionArtifacts {
    # v3.8 - Detects the PC-side AI-vision aimbot constellation. These run
    # locally with screen capture + a YOLO/ONNX model + a virtual HID or
    # Arduino Leonardo. Detection logic:
    #   - Named brand executable (Aimmy.exe, sunone_aimbot.exe, etc.) = HIGH cheat
    #   - ONNX model file alone, no companion artifact = INFO (legitimate ML work
    #     is common; many people have yolov5s.onnx for unrelated reasons)
    #   - ONNX + Python ML deps (ultralytics/torch/mss/pyautogui) co-located in
    #     a user-writable dir = MEDIUM (could be ML hobby OR aimbot dev)
    #   - ONNX + named brand executable in same dir tree = HIGH cheat
    #   - ONNX + Arduino sketch with HID descriptor = HIGH cheat
    #
    # v4.1.1 perf: skips dependency-cache directories where actual aimbots
    # would never live (node_modules, site-packages, .venv, conda envs, etc.).
    # An ML-heavy user can have hundreds of thousands of files in those caches
    # — walking them was the single biggest contributor to AIVision wall time.
    Write-Host '  [*] AI-vision aimbot artifacts (ONNX / YOLO / external HID)...' -ForegroundColor DarkGray

    # Skip these directory NAMES (matched as path segments, case-insensitive).
    # A real AI-aimbot constellation lives in a hand-organized user folder,
    # not in a dependency cache. Skipping these is detection-neutral.
    $excludePattern = '(?i)\\(node_modules|\.git|\.hg|\.svn|site-packages|\.venv|venv|env|envs|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|anaconda3|miniconda3|conda|\.cache|\.npm|\.yarn|\.next|\.nuxt|\.cargo|\.rustup|dist-info)\\'

    $roots = @(
        "$env:USERPROFILE\Documents", "$env:USERPROFILE\Desktop",
        "$env:USERPROFILE\Downloads", "$env:USERPROFILE\source",
        "$env:USERPROFILE\Projects", "$env:USERPROFILE\AppData\Local",
        "$env:USERPROFILE\AppData\Roaming"
    ) | Where-Object { $_ -and (Test-Path $_) }

    $onnxFiles = [System.Collections.Generic.List[object]]::new()
    $brandHits = [System.Collections.Generic.List[object]]::new()
    $arduinoHits = [System.Collections.Generic.List[object]]::new()
    $pyDepHits = [System.Collections.Generic.List[object]]::new()

    # Hard caps on the .exe/.py walk in particular — ML-heavy users can have
    # tens of thousands of Python scripts across virtualenvs. We don't need
    # to scan them all to find a named-brand aimbot binary.
    $exePyCapPerRoot = 800
    $pyDepCapPerRoot = 150

    foreach ($root in $roots) {
        # ONNX models (YOLO weights). Cap recursion depth implicitly via cap on results.
        try {
            Get-ChildItem $root -Recurse -File -Depth 8 -Filter '*.onnx' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch $excludePattern } |
                Select-Object -First 200 |
                ForEach-Object { [void]$onnxFiles.Add($_) }
        } catch {}

        # Named-brand executables (HIGH on their own).
        try {
            Get-ChildItem $root -Recurse -File -Depth 8 -Include '*.exe','*.py' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch $excludePattern -and $_.Length -lt 200MB } |
                Select-Object -First $exePyCapPerRoot |
                ForEach-Object {
                    $hit = Match-Keyword "$($_.Name) $($_.DirectoryName)" $VisionAimbot_AI_PC
                    if ($hit) {
                        $meta = @{
                            Pattern   = $hit
                            FileName  = $_.Name
                            FullPath  = $_.FullName
                            SizeBytes = $_.Length
                            Created   = $_.CreationTime.ToString('s')
                            LastWrite = $_.LastWriteTime.ToString('s')
                        }
                        Add-Finding 'AIVision' $_.FullName "[$hit] AI-vision aimbot executable: $($_.Name)" 'HIGH' 'cheat' $meta
                        [void]$brandHits.Add($_)
                    }
                }
        } catch {}

        # Arduino sketches with HID-descriptor patterns - dead giveaway when
        # paired with the ONNX/Python side of the constellation.
        try {
            Get-ChildItem $root -Recurse -File -Depth 8 -Filter '*.ino' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch $excludePattern } |
                Select-Object -First 100 |
                ForEach-Object {
                    try {
                        $content = Get-Content $_.FullName -Raw -ErrorAction Stop
                        if ($content -match '(?i)(Mouse\.move|HID-Project|MouseAbsolute|Keyboard\.press.*Mouse)') {
                            [void]$arduinoHits.Add($_)
                        }
                    } catch {}
                }
        } catch {}

        # Python ML dependency markers - requirements.txt / pyproject.toml /
        # site-packages dirs naming aimbot-typical libraries.
        try {
            Get-ChildItem $root -Recurse -File -Depth 8 -Include 'requirements.txt','pyproject.toml','*.cfg' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch $excludePattern } |
                Select-Object -First $pyDepCapPerRoot |
                ForEach-Object {
                    try {
                        $content = Get-Content $_.FullName -Raw -ErrorAction Stop
                        $combo = 0
                        if ($content -match '(?i)ultralytics') { $combo++ }
                        if ($content -match '(?i)\btorch\b') { $combo++ }
                        if ($content -match '(?i)\bmss\b') { $combo++ }
                        if ($content -match '(?i)pyautogui|pydirectinput|pynput') { $combo++ }
                        if ($content -match '(?i)opencv-python|cv2') { $combo++ }
                        if ($content -match '(?i)onnxruntime') { $combo++ }
                        if ($combo -ge 3) {
                            [void]$pyDepHits.Add(@{ File=$_; Score=$combo })
                        }
                    } catch {}
                }
        } catch {}
    }

    # Emit ONNX findings according to constellation rules.
    foreach ($onnx in $onnxFiles) {
        $meta = @{
            FileName  = $onnx.Name
            FullPath  = $onnx.FullName
            SizeBytes = $onnx.Length
            Created   = $onnx.CreationTime.ToString('s')
            LastWrite = $onnx.LastWriteTime.ToString('s')
        }

        # Is there a brand-hit executable in the same directory subtree?
        $coLocatedBrand = $brandHits | Where-Object { $_.FullName.StartsWith($onnx.DirectoryName) -or $onnx.FullName.StartsWith($_.DirectoryName) } | Select-Object -First 1
        if ($coLocatedBrand) {
            $meta['CoLocated'] = $coLocatedBrand.FullName
            Add-Finding 'AIVision' $onnx.FullName "ONNX model co-located with AI-aimbot executable: $($onnx.Name)" 'HIGH' 'cheat' $meta
            continue
        }

        # Is there an Arduino HID sketch nearby?
        $coLocatedArduino = $arduinoHits | Where-Object { $_.FullName.StartsWith($onnx.DirectoryName) -or $onnx.FullName.StartsWith($_.DirectoryName) } | Select-Object -First 1
        if ($coLocatedArduino) {
            $meta['CoLocatedArduino'] = $coLocatedArduino.FullName
            Add-Finding 'AIVision' $onnx.FullName "ONNX model co-located with Arduino HID sketch: $($onnx.Name)" 'HIGH' 'cheat' $meta
            continue
        }

        # Is there a Python ML deps file with 3+ aimbot-typical libraries nearby?
        $coLocatedDeps = $pyDepHits | Where-Object { $_.File.FullName.StartsWith($onnx.DirectoryName) -or $onnx.FullName.StartsWith($_.File.DirectoryName) } | Select-Object -First 1
        if ($coLocatedDeps) {
            $meta['CoLocatedDeps'] = $coLocatedDeps.File.FullName
            $meta['DepsScore'] = $coLocatedDeps.Score
            Add-Finding 'AIVision' $onnx.FullName "ONNX model + Python ML deps (ultralytics/torch/mss/pyautogui) at $($onnx.DirectoryName)" 'MEDIUM' 'dual-use' $meta
            continue
        }

        # Lone ONNX file - common for legitimate ML work. INFO only.
        Add-Finding 'AIVision' $onnx.FullName "ONNX model present (no aimbot constellation): $($onnx.Name)" 'INFO' 'other' $meta
    }

    # Arduino sketches alone (without ONNX nearby) - INFO. With ONNX they
    # already got promoted above.
    foreach ($ino in $arduinoHits) {
        $colocated = $onnxFiles | Where-Object { $_.FullName.StartsWith($ino.DirectoryName) -or $ino.FullName.StartsWith($_.DirectoryName) } | Select-Object -First 1
        if (-not $colocated) {
            Add-Finding 'AIVision' $ino.FullName "Arduino HID sketch (no ONNX constellation): $($ino.Name)" 'INFO' 'other' @{
                FileName = $ino.Name; FullPath = $ino.FullName
                LastWrite = $ino.LastWriteTime.ToString('s')
            }
        }
    }
}

# ============================================================================
# PROCESS AND SERVICE SNAPSHOT FUNCTIONS
# ============================================================================

function Get-ProcessSnapshot {
    Write-Host '  [*] Collecting running processes (scored)...' -ForegroundColor DarkGray
    try { $raw = Get-CimInstance Win32_Process -ErrorAction Stop } catch { return @() }
    $scored = foreach ($p in $raw) {
        $s = Score-Item -Name $p.Name -Path $p.ExecutablePath -Extra $p.CommandLine
        [PSCustomObject]@{
            ProcessId = $p.ProcessId; ParentProcessId = $p.ParentProcessId
            Name = $p.Name
            Started = if ($p.CreationDate) { $p.CreationDate.ToString('s') } else { '' }
            ExecutablePath = $p.ExecutablePath; CommandLine = $p.CommandLine
            Score = $s.Score; Kind = $s.Kind; Pattern = $s.Pattern; Reason = $s.Reason
        }
    }
    return $scored | Sort-Object @{E={ switch ($_.Score) { 'HIGH' {1} 'MEDIUM' {2} 'LOW' {3} 'CLEAN' {4} } }}, Name
}

function Get-ServiceSnapshot {
    Write-Host '  [*] Collecting services (scored)...' -ForegroundColor DarkGray
    try { $raw = Get-CimInstance Win32_Service -ErrorAction Stop } catch { return @() }
    $scored = foreach ($s in $raw) {
        $sc = Score-Item -Name $s.Name -Path $s.PathName -Extra $s.DisplayName
        [PSCustomObject]@{
            Name = $s.Name; DisplayName = $s.DisplayName
            State = $s.State; StartMode = $s.StartMode
            PathName = $s.PathName; StartName = $s.StartName; ProcessId = $s.ProcessId
            Score = $sc.Score; Kind = $sc.Kind; Pattern = $sc.Pattern; Reason = $sc.Reason
        }
    }
    return $scored | Sort-Object @{E={ switch ($_.Score) { 'HIGH' {1} 'MEDIUM' {2} 'LOW' {3} 'CLEAN' {4} } }}, Name
}

function Get-Named-Items {
    param($Findings, $Procs, $Svcs, [string]$Kind, [string]$Severity)
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $Findings) {
        if ($f.Severity -eq $Severity -and $f.Kind -eq $Kind) {
            $pat = if ($f.Metadata.Pattern) { $f.Metadata.Pattern } else { '?' }
            $cat = $f.Category
            [void]$names.Add("[$cat] $pat - $($f.Detail)")
        }
    }
    foreach ($p in $Procs) {
        if ($p.Score -eq $Severity -and $p.Kind -eq $Kind) {
            [void]$names.Add("[Process] $($p.Pattern) - $($p.Name) (PID $($p.ProcessId))")
        }
    }
    foreach ($s in $Svcs) {
        if ($s.Score -eq $Severity -and $s.Kind -eq $Kind) {
            [void]$names.Add("[Service] $($s.Pattern) - $($s.Name) ($($s.State))")
        }
    }
    return $names
}

# ============================================================================
# RECENCY DECAY (v3.8)
# ============================================================================
# Old artifacts get LOGGED in the report (so a reviewer can still see them),
# but don't BUMP the verdict if they're older than the threshold. A user who
# cheated in GTA three years ago and is now scanning a clean COD rig shouldn't
# get the same verdict as a current active cheater.
#
# Threshold: 180 days (6 months). Drivers can override $RecencyThresholdDays
# before calling Apply-RecencyDecay if they want a different window.
#
# Categories listed in $AlwaysRecentCategories represent CURRENT state (a
# process running right now, a service registered right now, a driver loaded
# right now). Those are not eligible for decay regardless of any file
# timestamps on the underlying binary - if it's currently in memory, it's
# current evidence.

$Script:RecencyThresholdDays = 180

$Script:AlwaysRecentCategories = @(
    'Processes',       # via Get-ProcessSnapshot - running right now
    'Services',        # registered services snapshot
    'ProcessModules',  # DLLs currently loaded
    'Drivers',         # currently loaded kernel drivers
    'LOLDrivers',      # currently loaded drivers cross-referenced
    'ShimCache',       # presence indicator, no temporal meaning
    'BCD'              # current boot config state
)

# Ordered list of metadata keys to consult when looking for "the most recent
# evidence" timestamp on a finding. Order matters: we walk from
# most-decisive-recent (last execution) toward less-recent (creation).
$Script:RecencyMetadataKeys = @(
    'LastRun','LastExecution','LastArrival','Timestamp',
    'LastWrite','LastModified','NewestWrite',
    'Created','FirstSeen','FirstInstall','InstallDate','LastRemoval'
)

function Get-FindingTimestamp {
    # Returns the most recent DateTime extracted from a finding's metadata,
    # or $null if no timestamp-shaped metadata is present.
    param([pscustomobject]$Finding)
    if (-not $Finding.Metadata) { return $null }
    $best = $null
    foreach ($key in $Script:RecencyMetadataKeys) {
        if (-not $Finding.Metadata.ContainsKey($key)) { continue }
        $val = $Finding.Metadata[$key]
        if ($null -eq $val -or $val -eq '' -or $val -eq 'unknown') { continue }
        $dt = $null
        if ($val -is [datetime]) {
            $dt = $val
        } else {
            try { $dt = [datetime]::Parse($val) } catch {}
        }
        if ($dt -and ($null -eq $best -or $dt -gt $best)) { $best = $dt }
    }
    return $best
}

function Apply-RecencyDecay {
    # Walks $Findings (parent-scope) and applies recency decay.
    # Findings older than $RecencyThresholdDays:
    #   - Severity downgrade: HIGH -> MEDIUM, MEDIUM -> INFO
    #   - Metadata.RecencyClass = 'historical'
    #   - Metadata.OriginalSeverity preserved so the reviewer sees what it was
    #   - Metadata.AgeDays + MostRecentTimestamp added
    # Recent findings get Metadata.RecencyClass = 'recent' (informational tag).
    # Findings with no usable timestamp + not in AlwaysRecentCategories get
    # RecencyClass = 'unknown' and are TREATED AS RECENT for verdict safety
    # (better to flag than miss).
    Write-Host '  [*] Applying recency decay (>180-day findings demoted)...' -ForegroundColor DarkGray

    $cutoff = (Get-Date).AddDays(-$Script:RecencyThresholdDays)
    $historicalCount = 0
    $unknownCount = 0
    $recentCount = 0

    foreach ($f in $Findings) {
        if ($Script:AlwaysRecentCategories -contains $f.Category) {
            $f.Metadata['RecencyClass'] = 'recent'
            $recentCount++
            continue
        }

        $ts = Get-FindingTimestamp $f
        if (-not $ts) {
            $f.Metadata['RecencyClass'] = 'unknown'
            $unknownCount++
            continue
        }

        $age = ((Get-Date) - $ts).TotalDays
        $f.Metadata['AgeDays'] = [int]$age
        $f.Metadata['MostRecentTimestamp'] = $ts.ToString('s')

        if ($ts -lt $cutoff) {
            $f.Metadata['RecencyClass'] = 'historical'
            $f.Metadata['OriginalSeverity'] = $f.Severity
            switch ($f.Severity) {
                'HIGH'   { $f.Severity = 'MEDIUM' }
                'MEDIUM' { $f.Severity = 'INFO' }
                default  { } # INFO / WARN unchanged
            }
            $historicalCount++
        } else {
            $f.Metadata['RecencyClass'] = 'recent'
            $recentCount++
        }
    }

    Add-Finding 'RecencyDecay' '(summary)' "Recency analysis: $recentCount recent, $historicalCount historical (>$($Script:RecencyThresholdDays)d demoted), $unknownCount unknown-timestamp" 'INFO' 'other' @{
        ThresholdDays = $Script:RecencyThresholdDays
        RecentFindings = $recentCount
        HistoricalFindings = $historicalCount
        UnknownTimestampFindings = $unknownCount
    }
}

# ============================================================================
# Convenience: run the full scan sequence in one call.
# Drivers can call this instead of listing each Scan-* manually.
# ============================================================================
function Invoke-AllScans {
    # Wraps every Scan-* call in a stopwatch so per-scanner wall time lands
    # in the report as an INFO finding. Lets reviewers (and the author)
    # see exactly which step is slow on which machine without guessing.
    $allScans = @(
        'Scan-Prefetch','Scan-BAM','Scan-InstalledSoftware','Scan-RecentFiles',
        'Scan-MUICache','Scan-USBHistory','Scan-DriverSigning','Scan-Drivers',
        'Scan-Downloads','Scan-Services-Trace','Scan-DMABuildArtifacts',
        'Scan-ApplicationData','Scan-ShimCache','Scan-UserScriptContents',
        'Scan-ObscuredFileNames','Scan-ProcessModules','Scan-KnownHashes',
        'Scan-LuaScripts','Scan-DLLInjectionTimestamps','Scan-NetworkAttackTools',
        'Scan-AIVisionArtifacts'
    )
    $timings = [System.Collections.Generic.List[pscustomobject]]::new()
    $totalSw = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($scanName in $allScans) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try { & $scanName } catch {
            Add-Finding 'ScanTiming' $scanName "Scanner threw: $_" 'WARN' 'other' @{}
        }
        $sw.Stop()
        $timings.Add([pscustomobject]@{ Name=$scanName; Seconds=[math]::Round($sw.Elapsed.TotalSeconds,2) }) | Out-Null
    }
    $totalSw.Stop()
    # Emit a single INFO finding summarising slowest-first per-scanner timings.
    $top = ($timings | Sort-Object Seconds -Descending | Select-Object -First 8 |
        ForEach-Object { "$($_.Name)=$($_.Seconds)s" }) -join ', '
    $meta = @{ TotalSeconds = [math]::Round($totalSw.Elapsed.TotalSeconds,2); SlowestFirst = $top }
    foreach ($t in $timings) { $meta[$t.Name] = "$($t.Seconds)s" }
    Add-Finding 'ScanTiming' '(summary)' "Scan timing: total $($meta.TotalSeconds)s. Slowest: $top" 'INFO' 'other' $meta
}
