"""Keyword database — research-confirmed cheat brands, input devices, dual-use
tools, allowlists, and known-hash list. Mirrors forensic-common.ps1.

A driver assembles composite arrays from these bases (see forensic_scan.py
and console_rig_audit.py for the PC-mode and console-mode compositions).

Add a new keyword in ONE place here and every scanner picks it up.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Cheat brands (HIGH cheat if matched)
# ---------------------------------------------------------------------------
CHEAT_BRANDS_COD: list[str] = [
    "engineowning", "engine owning", "phantomoverlay", "phantom overlay",
    "lavicheats", "lavi cheats", "skycheats", "sky cheats",
    "iwantcheats", "i want cheats", "x22cheats", "x22 cheats", "golden gun",
    "tateware", "gcaimx", "hdcheat", "securecheats", "overlord spoofer",
    "zhexcheats", "zhex cheats",
    # Rivera Unlock Tool (RUT) + RUAVT bundle (rut.gg). Multi-token only;
    # bare 'rut' excluded to avoid English-word false positives.
    "rut.gg", "old.rut.gg", "rutforcod",
    "ruavt", "rut and ruavt", "rutandruavt",
    "rut launcher", "rut v3 launcher", "rut v4 launcher",
    "rut v3.exe", "rut v4.exe", "rutv3.exe", "rutv4.exe",
    "rivera unlock", "riveras unlock", "rivera unlock tool", "riveras rut",
    "rut unlocker", "rut unlock tool", "rut uav", "rut-uav",
    # Activision C&D'd Feb 2025 — kept so scanner still hits leftover artifacts.
    "two2nd", "two2nd_loader",
    "tomware", "tomwareloader", "tomware_loader",
    "cynicalsoftware", "cynical_loader", "cynical software",
]

SPOOFER_BRANDS: list[str] = [
    "sync spoofer", "syncspoofer", "tracex", "slothytech", "pokespoof",
    "overlord.exe", "overlord_",
    "hidhide", "hid hide", "hidhideclient", "hidhidecli", "hidhidedrv",
    # v3.8 additions
    "hwidspoofer", "hwidspoofer.com",
    "synctop", "sync-top",
]

CHEAT_FEATURE_NAMES: list[str] = [
    "aimbot", "wallhack", "wall_hack", "wall-hack", "triggerbot", "trigger_bot",
    "norecoil", "no-recoil", "no_recoil",
    "hwidspoofer", "hwid_spoof", "hwid-spoof", "hwidchanger",
    "macspoof", "mac_spoof",
]

DMA_INDICATORS: list[str] = [
    "pcileech", "pcileech-fpga", "pcileech_fpga", "pcileech_squirrel",
    "pcileech_enigma", "pcileech_zdma", "pcileech_screamer", "pcileech_leetdma",
    "pcileech_captaindma", "pcileech_hackdma", "pcileech_lurker",
    "pcileech_mvp", "pcileech_macku", "_top.bin",
    # v3.8 branded DMA hardware vendors
    "atomicdma", "atomic_dma", "atomic-dma",
    "captaindma", "captain_dma", "captainfuser", "captain_fuser",
    "leetdma", "leet_dma",
    "lurkerdma", "lurker_dma",
    "enigma_x1", "enigmax1", "enigma-x1",
    "mvpdma", "mvp_dma",
    "hackdma", "hack_dma",
    "zdma", "z_dma",
    "suspectdma", "suspect_dma", "suspectcheats",
    "phoenixlabs", "phoenixlabstore", "phoenix_dma",
    "screamer_squirrel", "squirrel_dma", "lambdaconcept",
    "echeats", "echeats.io", "equalcheats",
    "ssz_dma", "ssz.gg",
    "clutchsolution", "clutch-solution",
]

# ---------------------------------------------------------------------------
# Input devices (HIGH input)
# ---------------------------------------------------------------------------
INPUT_DEVICES: list[str] = [
    "xim manager", "ximmanager", "xim apex", "xim matrix", "xim4",
    "cronus", "cronuszen", "zen studio", "gpcscript", "cronusmax",
    "reasnow", "reasnow s1", "kmbox", "km-box", "km_box",
    "titan two", "titan.two", "gtuner", "consoletuner",
    "rewasd", "rewasdengine", "rewasd engine", "rewasd.exe",
]

# ---------------------------------------------------------------------------
# Dual-use tools (MEDIUM)
# ---------------------------------------------------------------------------
DMA_DUAL_USE: list[str] = ["vivado", "xilinx vivado", "arbor", "dma-cfw", "dma_cfw"]

DUAL_USE_TOOLS: list[str] = [
    "bleachbit", "privazer", "rbcleaner", "cheatengine", "cheat engine",
    "processhacker", "process hacker", "ollydbg", "x64dbg", "x32dbg",
    "reclass", "reclass.net", "ida.exe", "ida64.exe", "ida pro",
]

# ---------------------------------------------------------------------------
# Script-content patterns (matched inside .bat / .cmd / .ps1 / .lua / .ahk)
# ---------------------------------------------------------------------------
SCRIPT_CONTENT_HIGH_RISK: list[str] = [
    "bcdedit /set testsigning", "bcdedit /set nointegritychecks",
    "bcdedit -set testsigning",
    "taskkill /f /im easyanticheat", "taskkill /f /im battleye",
    "taskkill /f /im vanguard", "taskkill /f /im ricochet",
    "taskkill /f /im faceit", "taskkill /f /im esea",
    "taskkill /im eac", "taskkill /im be-service",
    "stop-service -name vgc", "stop-service vgc", "stop-service -name vgk",
    "sc stop vgc", "sc stop vgk", "sc stop bedaisy",
    "set-mppreference -disablerealtime",
    "set-mppreference -disablebehaviormonitoring",
    "set-mppreference -disableioavprotection",
    "add-mppreference -exclusionpath",
    "add-mppreference -exclusionprocess",
    "add-mppreference -exclusionextension",
    "wmic csproduct get uuid", "wmic baseboard get serialnumber",
    "wmic diskdrive get serialnumber", "wmic bios get serialnumber",
    "get-wmiobject win32_baseboard", "get-wmiobject win32_diskdrive",
    "get-ciminstance win32_baseboard",
    "powershell -enc ", "powershell -encodedcommand",
    "powershell.exe -enc ",
    "iex(new-object net.webclient", "iex (new-object net.webclient",
    "invoke-expression (new-object net.webclient",
    "iwr ${", "curl http", "| iex", "|iex",
    "wevtutil cl ", "wevtutil clear-log", "clear-eventlog",
    "fsutil usn deletejournal", "cipher /w:", "vssadmin delete shadows",
    "sc.exe create", "sc create ",
]

SCRIPT_CONTENT_MOUSE_MACRO: list[str] = [
    "MoveMouseRelative", "MoveMouseTo", "GetMousePosition",
    "PressMouseButton", "ReleaseMouseButton", "PressAndReleaseMouseButton",
    "IsMouseButtonPressed", 'OnEvent("MOUSE_BUTTON', 'event == "MOUSE_BUTTON',
    "MOUSE_BUTTON_PRESSED", "MOUSE_BUTTON_RELEASED",
    "rzMacro", "rzcustom_macro",
    "anti_recoil", "antirecoil", "anti-recoil", "no_recoil", "norecoil",
    "recoil_compensation", "recoil_control", "recoilcontrol",
    "rapid_fire_lua", "rapidfire_lua",
    "MouseMove,", "MouseClick,", "SendInput {Click",
    "AutoHotkey_recoil", "ahk_recoil",
]

LUA_CHEAT_KEYWORDS: list[str] = [
    "aimbot", "aim_bot", "aim-bot", "triggerbot", "trigger_bot",
    "wallhack", "wall_hack",
    "esp", "norecoil", "no_recoil", "no-recoil", "bhop", "bunny_hop", "bunnyhop",
    "spinbot", "spin_bot", "radar_hack", "radarhack", "speedhack", "speed_hack",
    "skinchanger", "skin_changer", "injector", "bypass", "anticheat", "anti_cheat",
    "cheat", "hack", "exploit", "undetected", "ud_", "loader", "ldr_",
    "engineowning", "phantomoverlay", "lavicheats", "skycheats",
]

DLL_INJECTOR_NAMES: list[str] = [
    "injector", "inject", "xenos", "xenos64", "extreme_injector", "extremeinjector",
    "gdinjector", "manual_map", "manualmap", "loadlibrary_injector",
    "process_hollowing", "processhollowing", "dllinjector", "dll_inject",
    "syringe", "chimera", "shtreload", "winject", "winject64",
    "remoteinjection", "remoteinjector", "shellcode", "shellcode_inject",
]

NETWORK_ATTACK_HIGH: list[str] = [
    "loic", "low orbit ion cannon",
    "hoic", "high orbit ion cannon",
    "slowloris", "pyloris",
    "goldeneye", "goldeneyetool",
    "torshammer", "tor hammer",
    "hulk.py", "hulk_ddos",
    "rudy", "r-u-dead-yet",
    "ufonet",
    "xerxes",
    "andosid",
    "byob_ddos",
    "ddos_attack", "ddos_tool", "ddostool",
    "booter_client", "stresser_client",
]

NETWORK_ATTACK_MEDIUM: list[str] = [
    "hping", "hping3",
    "masscan",
    "zmap",
    "ostinato",
    "iperf3",
    "tshark",
]

# ---------------------------------------------------------------------------
# v3.8 game-specific cheat brand arrays
# ---------------------------------------------------------------------------
CHEAT_BRANDS_CS2: list[str] = [
    "neverlose", "neverlose.cc", "nl_loader", "nl-loader",
    "memesense", "memesense.gg", "memes_loader",
    "fatality.win", "fatality_loader",
    "primordial.cc", "primordial_loader",
    "skeet.cc", "gamesense.pub",
    "onetap", "onetapv4", "onetap.com",
    "aimware", "aimware.net",
    "axion-cs2", "axion_rage", "axion cs2",
]

CHEAT_BRANDS_APEX: list[str] = [
    "kernaim", "kernaim.to",
    "cosmocheats apex", "cosmoloader",
    "apex_hacksuite", "apex-hacksuite",
]

CHEAT_BRANDS_TARKOV: list[str] = [
    "phantom eft", "phantom_eft", "phantomloader", "phantom-eft",
    "cheatvault eft", "cheatvault.net",
    "ownage software", "ownage_eft", "ownagesoftware",
]

CHEAT_BRANDS_RUST: list[str] = [
    "cobracheat", "cobra rust", "cobra_rust", "cobracheats",
    "cobrasn",
    "atomic rust", "atomic_rust",
    "cheater.ninja", "cheaterninja",
]

CHEAT_BRANDS_R6: list[str] = [
    "hyperforcecheats", "hyper_force_cheat",
    "cheatvault r6", "cheatvault_r6",
]

CHEAT_BRANDS_MARVEL_RIVALS: list[str] = [
    "marvel maxim", "marvel_maxim", "maxim_rivals",
    "elocarry", "elocarry.net", "elocarry rivals",
]

# Single-source / lower-confidence cheat names — MEDIUM only.
CHEAT_BRANDS_LOW_CONFIDENCE: list[str] = [
    "midnight cs2", "midnight_cs2",
    "predator cs2", "predator_cs2",
    "anyx.gg", "anyxcheat",
    "eucheats",
    "siegex",
    "rainbowsixcheats",
    "wh-satano", "whsatano",
    "proofcore", "proofcore.io",
    "chamscheats",
    "deprimereshop", "depshop",
    "sternclient.biz",
    "hackvshack",
    "madchad.net",
    "gulfcheats", "gulf_spoofer",
    "moddingassociation",
]

# PC-side AI-vision aimbots (HIGH cheat).
VISION_AIMBOT_AI_PC: list[str] = [
    "aimmy", "aimmy.exe", "babyhamsta",
    "sunone_aimbot", "sunone_aimbot_2", "sunone",
    "rootkit_aimbot", "rootkit-ai-aimbot", "ai-aimbot",
    "aimahead",
    "zelesisneo", "zelesis.com", "zelesis_neo",
    "reflex_aimbot", "xxreflextheone",
    "aimi_yolov3",
    "yolov8_aimbot", "yolov5_aimbot",
    "aim_bot_yolo", "magicxuantung",
    "unibot", "vike256_unibot",
    "ardoras", "kinuzo_ardoras",
    "embedded_aim_assist", "pi_aimbot", "tharushavj",
    "csmacro_ai", "csmacro",
]

# Deferred (not consumed by any current scanner). Held for a future
# Scan-BrowserHistory that MUST enforce a hit threshold
# (>=3 visits across >=2 distinct domains in last 6 months).
CHEAT_MARKETPLACE_DOMAINS: list[str] = [
    "skycheats.com", "privatecheatz.com", "battlelog.co", "lavicheats.com",
    "cosmocheats.com", "cheatseller.com", "kernaim.to", "gulfcheats.com",
    "clutch-solution.com", "cheatvault.net", "hyperforcecheats.com",
    "qlmshop.com", "elocarry.net", "chamscheats.com", "proofcore.io",
    "zsoft.store", "deprimereshop.com", "cheater.ninja", "vredux.com",
    "iniquus.io", "infocheats.net", "hackvshack.net", "exloader.net",
    "anyx.gg", "ownagesoftware.com", "elitehacks.ru", "wh-satano.ru",
    "sternclient.biz", "cs2-cheats.com", "madchad.net", "phoenixlabstore.com",
    "suspectcheats.com", "echeats.io", "ssz.gg", "atomicdma.com",
    "unknowncheats.me", "elitepvpers.com", "mpgh.net", "ownedcore.com",
    "guidedhacking.com", "high-minded.cx",
]

# ---------------------------------------------------------------------------
# Console-only keyword arrays (used by console_rig_audit.py)
# ---------------------------------------------------------------------------
VISION_AIMBOTS_CONSOLE: list[str] = [
    "aimmmo", "aim mmo", "aim_mmo",
    "aimsync", "aim sync", "aim_sync",
    "aimflux", "aim flux", "aim_flux",
    "norecoilz", "no recoil z", "no_recoil_z",
    "divisionx", "division x", "division_x",
    "predator aim", "predatoraim", "predator-aim",
    "looplus", "loop plus", "loop+",
    "apox aim", "apoxaim", "apox-aim",
    "aimkey", "aim key",
    "aimx", "aim-x", "aim_x",
    "kernaim", "kernel aim", "kernel-aim",
    "colorbot", "color bot", "color-bot",
    "pixelbot", "pixel bot", "pixel-bot",
    "ml aim", "ml-aim", "machine learning aim",
    "ai aimbot", "ai-aimbot", "ai_aimbot",
    "vision aimbot", "vision-aimbot",
    "screen aimbot", "screen-aimbot",
]

HID_EMULATORS: list[str] = [
    "vigembus", "vigem bus", "vigem-bus", "vigemclient",
    "vjoy", "v-joy",
    "scptoolkit", "scp toolkit", "scp-toolkit",
    "ds4windows", "ds4 windows",
]

CAPTURE_CARD_SOFTWARE: list[str] = [
    "elgato game capture", "elgato 4k capture", "elgato_gamecapture", "gamecapture",
    "avermedia", "recentral", "rec central",
    "obs studio", "obs-studio", "obs64", "obs32",
    "streamlabs", "streamlabs obs",
    "xsplit", "x-split",
    "magewell",
]

# ---------------------------------------------------------------------------
# Known cheat-sample SHA256 hashes. Each entry MUST cite its source.
# ---------------------------------------------------------------------------
KNOWN_CHEAT_HASHES: list[dict[str, str]] = [
    {
        "sha256": "b1b89dedcff0c502d605a707e550b1565224b5949e778168ac45f01b8171160f",
        "name": "RUT AND RUAVT LAUNCHER UPDATED.exe (rut.gg)",
        "source": "Hybrid Analysis sandbox report",
    },
    # Add additional confirmed samples here. Each requires a verifiable source URL.
]

# ---------------------------------------------------------------------------
# Vendor allowlists
# ---------------------------------------------------------------------------
KNOWN_GOOD: list[str] = [
    "microsoft", "windows", "onedrive", "teams", "office", "edgewebview", "msedge",
    "google", "chrome", "update", "slack", "discord", "zoom", "signal", "spotify",
    "dropbox", "adobe", "nvidia", "amd", "intel", "realtek", "razer", "logitech",
    "corsair", "steelseries", "dell", "hp", "lenovo", "asus", "asustek", "msi",
    "steam", "epic", "battle.net", "riot", "origin", "ubisoft", "rockstar",
    "github", "vscode", "code.exe", "jetbrains", "notion", "postman", "docker",
    "python", "node", "npm", "git", "antigravity", "claude", "codex", "uv.exe", "blender",
]

# Driver publishers whose drivers are explicitly allowed (suppresses the
# "unsigned driver" MEDIUM finding on Scan-Drivers). Substring matched against
# the Manufacturer field returned by `driverquery /si /fo csv`. To avoid
# accidental substring matches, short ambiguous tokens are avoided in favour
# of more specific variants (e.g. "Hewlett-Packard" + "HP Inc" instead of bare "HP").
DRIVER_PUBLISHER_ALLOWLIST: list[str] = [
    # OS / system / chipset / silicon
    "Microsoft", "Microsoft Corporation",
    "Intel", "Intel Corporation",
    "AMD", "Advanced Micro Devices",
    "NVIDIA", "NVIDIA Corporation",
    "Realtek",
    "Qualcomm",
    "Broadcom",
    "MediaTek",
    "ASMedia",
    "Synaptics",
    # Gaming peripherals
    "Logitech", "Razer", "Corsair", "SteelSeries", "HyperX", "Kingston",
    "Turtle Beach", "Roccat", "Glorious PC Gaming", "Endgame Gear",
    "Pulsar Gaming", "Mad Catz", "Thrustmaster", "Saitek",
    # PC / laptop OEMs
    "Dell Inc", "Dell Computer", "Alienware",
    "Hewlett-Packard", "HP Inc",
    "Lenovo",
    "Acer Inc", "Acer Incorporated", "Predator",
    "ASUS", "ASUSTeK",
    "Micro-Star", "MSI",
    "Gigabyte", "GIGA-BYTE", "Aorus",
    "ASRock",
    "EVGA",
    "Origin PC",
    "iBuyPower",
    # Cases / cooling / PSUs
    "Cooler Master", "NZXT", "Thermaltake", "be quiet", "Fractal Design",
    "Lian Li", "Phanteks", "Noctua", "Arctic", "Antec", "SilverStone",
    "Corsair Components",
    # Memory / storage
    "G.SKILL", "G.Skill",
    "Crucial", "Micron",
    "Western Digital", "SanDisk",
    "Seagate",
    "Samsung Electronics",
    "SK Hynix", "SK hynix",
    # Monitors / displays
    "LG Electronics", "BenQ", "Zowie", "ViewSonic",
    # Audio
    "Creative Technology", "Creative Labs", "Sennheiser", "EPOS",
]

# AppData / Documents patterns for known input-device apps.
APPDATA_PATTERNS: list[dict[str, str]] = [
    {"pattern": "XIM Technologies", "label": "XIM Manager"},
    {"pattern": "XIM*", "label": "XIM (other)"},
    {"pattern": "ConsoleTuner", "label": "Cronus / Titan"},
    {"pattern": "Cronus*", "label": "Cronus"},
    {"pattern": "ZenStudio", "label": "Cronus Zen Studio"},
    {"pattern": "ReaSnow*", "label": "ReaSnow"},
]

# ---------------------------------------------------------------------------
# Recency decay configuration (v3.8)
# ---------------------------------------------------------------------------
RECENCY_THRESHOLD_DAYS = 180

# Categories representing CURRENT state (a process running right now, a
# service registered right now). Not eligible for decay regardless of any
# underlying binary timestamps.
ALWAYS_RECENT_CATEGORIES: set[str] = {
    "Processes",
    "Services",
    "ProcessModules",
    "Drivers",
    "LOLDrivers",
    "ShimCache",
    "BCD",
}

# Ordered list of metadata keys consulted to find the most-recent timestamp
# on a finding. Order matters: walk from decisive-recent (last execution)
# toward less-recent (creation / install).
RECENCY_METADATA_KEYS: list[str] = [
    "LastRun", "LastExecution", "LastArrival", "Timestamp",
    "LastWrite", "LastModified", "NewestWrite",
    "Created", "FirstSeen", "FirstInstall", "InstallDate", "LastRemoval",
]
