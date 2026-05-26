================================================================
  PC FORENSIC CHECK v3.2 - README
================================================================


WHAT THIS IS
------------

A read-only forensic scan of your Windows PC. It produces a single
text report on your Desktop covering:

  1. A clear VERDICT at the top of the file (one of four tiers)
  2. Cheat / input-device trace check
  3. Snapshot of all currently running processes, each suspicion-scored
  4. Snapshot of all registered services, each suspicion-scored

Everything goes into ONE timestamped .txt file on your Desktop.

The point of this kit is to let you demonstrate the state of your PC
to a third party. You run the scan; you send them the .txt file.


WHICH TOOL DO I RUN?
--------------------

This kit covers two scenarios. Pick the one that matches yours:

  PC GAMER
    You play on a Windows PC. Standard case.
    >>> Run `run-check.bat`

  CONSOLE GAMER, but with a PC connected to the console rig
    Capture-card host, second monitor, streaming PC, shared desktop.
    The console-cheat MITM stack lives on this PC, so scanning it
    is the right move.
    >>> Run `console-run-check.bat`

  CONSOLE GAMER with no PC anywhere in the loop
    Pure console + TV + controller. There is nothing for the scanner
    to scan. Use the visual setup checklist instead.
    >>> Open `console-setup-checklist.html` and follow it


HOW TO RUN
----------

1. Double-click `run-check.bat`
2. When Windows asks for admin permission (UAC prompt), click Yes.
3. Wait 30 to 90 seconds.
4. When done, a black window will show:
     Saved to: C:\Users\<you>\Desktop\PCForensicCheck_<timestamp>.txt
5. That .txt file is your report. Send it to whoever asked for it.


THE FOUR VERDICTS
-----------------

The QUICK READ block at the top of every report shows one of these:

  CHEATS DETECTED
      The scan found HIGH-confidence indicators of cheat software,
      HWID spoofers, or DMA-cheat development artifacts.
      The report names exactly what was found and where.

  INPUT DEVICES DETECTED
      No cheat brands or HWID spoofers, but the scan found commercial
      input-device software (XIM, Cronus, ReaSnow, KMBox, Titan, etc.).
      These are mouse/keyboard adapters. Whether they constitute
      cheating depends on the game's rules. The report names what
      was found; context is left to the reader.

  UNSURE
      No HIGH-confidence matches, but one or more MEDIUM findings
      require human review. Common causes: dual-use tools (cheat-engine,
      processhacker), or binaries running from user-writable locations
      that the allowlist doesn't recognize.

      For this case, the report embeds a ready-to-use prompt for any
      AI chat with web access (ChatGPT, Claude, Gemini, etc.). You
      paste the prompt and attach the .txt file. The AI looks up
      each MEDIUM item and classifies it as benign, worth-reviewing,
      or suspicious, with cited sources.

  CLEAN
      No HIGH and no MEDIUM matches. The report includes a count of
      everything that was scanned and a note that clean is necessary
      but not sufficient (DMA cheats and separately-paired input
      devices leave no trace on this machine by design).


WHAT GETS SCANNED
-----------------

Cheat trace phase (22 Windows artifact locations):

  Prefetch       - execution evidence for binaries that ran
  BAM            - kernel-level last-execution timestamps
  Installed      - Add/Remove Programs registry hives
  Recent Files   - shell shortcuts to recently-opened files
  MUICache       - cached display names of executed programs
  USB History    - every USB device ever connected (with timestamps)
  BCD Flags      - boot config (test-signing, integrity bypass)
  Drivers        - installed kernel drivers + signed status
  Downloads      - current contents with origin URLs
  Services       - registered Windows services (keyword pass)
  DMA Artifacts  - pcileech build outputs in user directories
  AppData        - usage frequency for input-device app dirs
  ShimCache      - application compatibility cache (presence)
  User Scripts   - .bat / .cmd / .ps1 / .vbs / .lua / .ahk in user folders,
                   with content matched against cheat keywords, high-risk
                   command patterns (Defender-disable, anti-cheat-kill,
                   driver-signing-bypass, HWID-query, log-clearing), AND
                   gaming-mouse macro patterns (anti-recoil, MoveMouseRelative
                   + OnEvent combos, Razer Synapse macros, AutoHotkey
                   mouse-control loops)
  Obscured Names - .exe / .dll / .lua / .sys in user folders whose name
                   is hex (0x001, 4f3a8b21), pure-numeric (12345), or
                   ultra-short (a, x1). Normal users do not have these;
                   cheaters use them to evade keyword-name matching.
  Process Modules- every DLL loaded into every running process. Flags any
                   DLL loaded from a user-writable path (AppData, Temp,
                   Downloads, Documents) that is NOT on the known-good
                   vendor allowlist. This is the canonical fingerprint of
                   an injected cheat DLL at runtime.
  Known Hashes   - SHA256 hashes every .exe / .dll in user folders (newest
                   500 only) and compares against a curated database of
                   confirmed cheat samples. Catches renamed cheat
                   executables that would slip past name-keyword matching.
  Lua Scripts    - .lua files across Documents / Desktop / Downloads /
                   AppData / source / Projects / Games matched by NAME and
                   PATH against cheat-specific Lua tokens (aimbot, esp,
                   bhop, spinbot, radarhack, skinchanger, etc.). HIGH on
                   keyword match; unrecognized Lua scripts are listed at
                   INFO so reviewers can see them but they do NOT bump the
                   verdict to UNSURE on their own (game mods, Logitech
                   G HUB, Neovim, etc. legitimately use Lua).
  DLL Injection  - historical injector-execution timeline pulled from
                   Sysmon Event ID 7 (Image Loaded), Security Event ID 4688
                   (Process Create), Application event log, and Prefetch.
                   Matches against a named-injector list (xenos,
                   extreme_injector, gdinjector, manual_map, syringe,
                   chimera, winject, dll_inject, etc.). Best coverage when
                   Sysmon is installed; falls back to 4688 + Prefetch
                   otherwise.
  AI Vision      - the v3.8 PC-side AI-vision aimbot constellation:
                   .onnx model files + Python ML deps (ultralytics, torch,
                   mss, pyautogui) + Arduino HID sketches + named brand
                   executables (Aimmy, sunone_aimbot, RootKit AI-Aimbot,
                   Zelesis NEO, etc.). A lone .onnx file is INFO (common
                   in legitimate ML work). ONNX + brand exe nearby = HIGH.
                   ONNX + 3+ aimbot-typical Python libs = MEDIUM.
                   ONNX + Arduino HID sketch nearby = HIGH.
  LOLDrivers     - (opt-in network) cross-references every loaded kernel
                   driver against the LOLDrivers (Living Off The Land
                   Drivers) public database at loldrivers.io. Catches
                   vulnerable and malicious drivers commonly used in
                   BYOVD (Bring Your Own Vulnerable Driver) attacks -
                   the technique many DMA and kernel-level cheats use
                   to gain ring-0 access without writing their own
                   kernel driver. HIGH on malicious-category matches
                   or hash-confirmed vulnerable drivers; MEDIUM on
                   filename-only vulnerable matches (could be a
                   different version). One HTTPS GET to fetch the CSV;
                   nothing about your PC is sent. Press Y at the prompt
                   to enable, or any other key to skip.
  Net Attack     - DDoS / network-attack tool scan across 6 sources:
                   Prefetch, BAM, Installed software, Downloads (with
                   Zone.Identifier source URL), MUICache, and Recent Files.
                   HIGH on named consumer DDoS clients (LOIC, HOIC,
                   slowloris, GoldenEye, torshammer, hulk, rudy, ufonet,
                   xerxes, andosid, booter/stresser clients). MEDIUM on
                   dual-use network tools (hping, masscan, zmap, ostinato,
                   iperf3, tshark) - legitimate sysadmin uses exist but
                   unusual on a pure gaming PC.

Process and service scoring:

  Every running process and every registered service is scored against
  the same keyword database, plus path-risk classification:

  HIGH    - Binary name, path, or command line matches a research-
            confirmed cheat or input-device keyword.
  MEDIUM  - Matches a dual-use tool keyword, OR runs from a user-
            writable location (AppData, Temp, user profile) and is
            not on the known-good vendor allowlist.
  LOW     - Runs from Program Files or another non-standard but
            typical location, no keyword match.
  CLEAN   - Runs from System32 / SysWOW64 / standard Windows paths,
            no keyword match.


KEYWORD DATABASE
----------------

  - COD cheat brands documented in Activision lawsuits and ban-wave
    reporting (EngineOwning, PhantomOverlay, Lavi/Sky/iWantCheats, X22,
    Golden Gun, Tateware, GcAimX, HdCheat, SecureCheats OVERLORD, ZHEX)
  - HWID spoofer brands (Sync, TraceX/SlothyTech, PokeSpoof)
  - Cheat feature SKUs (aimbot, wallhack, triggerbot, norecoil, etc.)
  - DMA-cheat development artifacts (pcileech FPGA variants, _top.bin)
  - Commercial input devices (XIM, Cronus, ReaSnow, KMBox, Titan)
  - Dual-use tools at MEDIUM (Cheat Engine, ProcessHacker, x64dbg,
    IDA Pro, BleachBit, PrivaZer)
  - Lua-script cheat tokens for name-based .lua matching (aimbot,
    esp, bhop, spinbot, radarhack, skinchanger, undetected, etc.)
  - Named DLL injectors (Xenos, Extreme Injector, GH Injector,
    manual_map, Syringe, Chimera, Winject, DLL Inject, etc.)
  - Named DDoS / network-attack clients at HIGH (LOIC, HOIC,
    slowloris, GoldenEye, torshammer, hulk, rudy, ufonet, xerxes,
    andosid, booter/stresser)
  - Dual-use network tools at MEDIUM (hping/hping3, masscan, zmap,
    ostinato, iperf3, tshark)
  - v3.8 multi-game expansion: per-title cheat brand arrays for
    CS2 (Neverlose, Memesense, Fatality, Primordial, Skeet, Onetap,
    Aimware, Axion), Apex (Kernaim, CosmoCheats), Tarkov (Phantom EFT,
    CheatVault, Ownage), Rust (Cobra, Atomic, Cheater.Ninja), R6
    (HyperForce, CheatVault R6), Marvel Rivals (Marvel Maxim, EloCarry)
  - v3.8 historical CoD cheats (Two2nd, Tomware, Cynical Software)
    kept after their Feb 2025 C&D shutdowns to catch leftover artifacts
  - v3.8 branded DMA hardware (Atomic, Captain, Leet, Lurker, Suspect,
    Phoenix Labs, Squirrel, Enigma X-1, MVP, HackDMA, ZDMA, Captain Fuser)
  - v3.8 PC-side AI-vision aimbots (Aimmy, sunone_aimbot, RootKit
    AI-Aimbot, Zelesis NEO, Unibot, Embedded-AI Pi aimbot, etc.)
  - v3.8 low-confidence array (MEDIUM-only) for single-source cheat
    names (Midnight CS2, Predator CS2, AnyX, EUCheats, HyperForce, etc.)
    so they're flagged but never trigger HIGH on thin sourcing

Keyword-list construction biases toward strict named matches to
minimize false positives on legitimate software.


WHAT IT DOES NOT DO
-------------------

  - No outbound network calls EXCEPT one opt-in fetch:
    The LOLDrivers cross-reference (BYOVD detection) prompts you
    Y/N before making ONE HTTPS GET to loldrivers.io to download
    the public vulnerable/malicious driver CSV. No data about your
    PC is sent. Press any key other than Y to skip, or pass
    -SkipLOLDrivers on the command line for unattended runs.
  - No file modification anywhere on your system. The only files
    created are the report on your Desktop and (if you opt in) a
    cached copy of the LOLDrivers DB at %TEMP%\pc-check-loldb.clixml.
  - No telemetry, keystroke logging, screen capture, or background
    process. The script runs once, writes the report, and exits.

If you want to verify any of this: open `forensic-scan.ps1` in
Notepad. It's PowerShell source. Everything it does is visible.


KNOWN LIMITATIONS
-----------------

  - DMA cheats running on a separate device cannot be detected
    by any scan that runs on the gaming PC. There is no PC-side
    footprint by design. This scan flags DMA *development*
    artifacts (FPGA build files) only.

  - Input devices configured on a separate machine and used purely
    as pass-through would not leave traces here.

  - Session duration is recorded in a database called SRUM but
    cannot be read by pure PowerShell. Requires an external tool
    like Eric Zimmerman's SrumECmd.

  - Keyword matching only. A sophisticated cleaner can wipe most
    of these artifacts. A clean result is necessary but not
    sufficient evidence.

  - DLL injection coverage is best with Sysmon installed (Event ID 7
    captures every DLL load). Without Sysmon, the scan falls back to
    Security Event ID 4688 (process creation, requires audit policy
    enabled), Application log message matches, and Prefetch. Events
    older than the event-log retention window (default Security log
    is ~7 days) are not recoverable.

  - DDoS-tool detection matches artifact names only. It cannot tell
    whether a tool was actually used, succeeded, or was directed at
    any specific target.

  - Lua-script scanning checks file NAMES and PATHS, not contents.
    Content-based Lua matching is handled separately by the User
    Scripts scanner. Unrecognized .lua files are listed at INFO and
    do not affect the verdict on their own.

  - RECENCY DECAY (v3.8): findings older than 180 days are LOGGED in
    the report but DEMOTED so they don't bump the verdict. HIGH becomes
    MEDIUM; MEDIUM becomes INFO. A user who cheated in another game
    years ago and is now scanning a clean current setup shouldn't get
    the same verdict as a current active cheater. The original severity
    and age (days) are recorded on each historical finding. State-based
    sources (running processes, registered services, currently-loaded
    drivers, ProcessModules, ShimCache, BCD flags) are always treated
    as recent because they reflect the current state of the machine.
    Findings with no usable timestamp metadata default to recent (the
    safer interpretation - flag rather than miss).

  - LOLDrivers BYOVD detection is opt-in and depends on whether you
    pressed Y at the prompt (or omitted -SkipLOLDrivers). If you
    declined, the scan still enumerates drivers and checks signing
    state, but does not cross-reference against the public DB.
    Filename-only matches are MEDIUM because driver filenames can
    be spoofed; only SHA256 matches are HIGH for the "vulnerable"
    category (malicious-category matches are always HIGH).


THE VISUAL COMPANION
--------------------

`generate-visual-companion.ps1` produces a styled HTML report from
the .txt. Run it like this:

  .\generate-visual-companion.ps1 -InputPath .\PCForensicCheck_<ts>.txt

It drops `<basename>_visual.html` next to the source file. Open in
any browser. Useful when you want a single-page document for review
rather than a long text file.


FILES IN THIS PACKAGE
---------------------

  README.txt                       This file.

  --- PC GAMER ---
  run-check.bat                    Double-click to run the PC scan.
  forensic-scan.ps1                The PC scan logic (auditable).
  generate-visual-companion.ps1    Optional HTML renderer for PC reports.

  --- CONSOLE GAMER (PC in the rig) ---
  console-run-check.bat            Double-click to scan the rig PC.
  console-rig-audit.ps1            Console-rig scan logic (auditable).

  --- CONSOLE GAMER (no PC in the rig) ---
  console-setup-checklist.html     Photo/screenshot dossier guide.

  --- REFERENCE / EXPLAINERS ---
  top-bin-explainer.html           What the _top.bin file is, illustrated.
  top-bin-explainer-offline.html   Same, no internet required.


REQUIREMENTS
------------

  - Windows 10 or 11 (PowerShell 5.1+, preinstalled).
  - Administrator account (or ability to approve UAC prompt).
  - 30-90 seconds of runtime.
  - About 1 MB of free disk space for the output file.

No installation. No external dependencies. No downloads.


----------------------------------------------------------------
  Author: Bread
  Contributor: Drownmw
----------------------------------------------------------------
