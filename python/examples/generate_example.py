"""Generate synthetic example reports that exercise every visual state.

Three PC-mode reports are produced, one per verdict tier:

  - pc-mode-cheats-detected.txt + _visual.html
      Verdict: CHEATS DETECTED. Comprehensive HIGH cheat coverage —
      EngineOwning prefetch, RUT launcher hash hit, pcileech DMA build
      output, LOLDrivers BYOVD (vulnerable tier), AI-vision constellation
      (executable + co-located ONNX model), Lua mouse-macro script, BCD
      testsigning. Also carries HIGH input findings (Cronus / XIM) so the
      v4.2 verdict-aware named-items routing has something to push to
      "also". MEDIUM dual-use, INFO scan summaries, WARN access-denied,
      and a HISTORICAL demoted prefetch entry are all present.

  - pc-mode-input-devices-detected.txt + _visual.html
      Verdict: INPUT DEVICES DETECTED. The shape Brad's own machine
      produces — XIM Matrix + Cronus Zen + reWASD + HidHide stack with
      USB-history and AppData activity tracks, zero HIGH cheats. With no
      cheats in the picture, all HIGH input findings route to "main".
      This is the false-positive scenario v4.2's bounded keyword matching
      was designed to land in cleanly (no more hoic→CHOICE.EXE noise).

  - pc-mode-clean.txt + _visual.html
      Verdict: CLEAN. No HIGH or MEDIUM matches in the recent window.
      Includes one HISTORICAL demoted entry (a long-ago XIM Manager
      install) so the lifecycle section still has a track to render.

The data is piped through the production formatters (reports.build_text_report
and visual_companion.render_html), so the output is guaranteed to match
exactly what a real scan would produce.

The three fabricated users (Marcus / Jordan / Alex) are plausible Windows
profile names; all timestamps, hashes, file sizes, install dates, and
VID/PID pairs are made up but in the right shape that a reviewer can
read the report as if it were real.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_SRC = _HERE.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from alibi import SCANNER_VERSION
from alibi.findings import Finding, ScoredItem
from alibi.keywords import RECENCY_THRESHOLD_DAYS
from alibi.reports import ReportContext, ReportSpec, build_text_report, collect_named_items
from alibi.utils import Engine
from alibi.visual_companion import render_html, write_html
from alibi.forensic_scan import _pc_quick_read, _PC_LIMITATIONS


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _ago(days: int = 0, hours: int = 0) -> str:
    return _iso(datetime.now() - timedelta(days=days, hours=hours))


# Keyword set used by all three engines. Mirrors a realistic subset of the
# production keywords.py so finding patterns reference strings that exist
# in the live scanner.
_KW_CHEAT = ["engineowning", "rut.gg", "rut v4 launcher", "aimmy", "pcileech"]
_KW_INPUT = ["cronus", "cronuszen", "xim matrix", "rewasd", "hidhide"]
_KW_MEDIUM = ["cheatengine", "vivado", "ds4windows", "vigembus", "obs studio"]
_KW_SCRIPT = ["bcdedit /set testsigning", "Disable-WindowsDefender"]
_KW_MOUSE_MACRO = ["MoveMouseRelative", "mouse_event"]


def _make_engine() -> Engine:
    return Engine(
        keywords_high_cheats=_KW_CHEAT,
        keywords_high_input=_KW_INPUT,
        keywords_medium=_KW_MEDIUM,
        keywords_script_high=_KW_SCRIPT,
        keywords_mouse_macro=_KW_MOUSE_MACRO,
    )


# ---------------------------------------------------------------------------
# PC MODE — CHEATS DETECTED  (fabricated user: Marcus)
# ---------------------------------------------------------------------------
def build_cheats_engine() -> Engine:
    e = _make_engine()
    home = r"C:\Users\Marcus"

    # --- HIGH cheat findings, multiple categories ------------------------
    e.add("Prefetch", rf"C:\Windows\Prefetch\ENGINEOWNING.EXE-7A4C2E91.pf",
          "[engineowning] ENGINEOWNING", "HIGH", "cheat",
          {"Pattern": "engineowning",
           "FirstSeen": _ago(days=11), "LastModified": _ago(days=2),
           "MostRecentTimestamp": _ago(days=2),
           "AgeDays": 2})
    e.add("MUICache", r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
          rf"[rut.gg] {home}\Downloads\RUT V4 Launcher.exe",
          "HIGH", "cheat",
          {"Pattern": "rut.gg",
           "Value": rf"{home}\Downloads\RUT V4 Launcher.exe",
           "Data": "RUT and RUAVT", "LastWrite": _ago(days=4),
           "MostRecentTimestamp": _ago(days=4), "AgeDays": 4})
    e.add("DMA", rf"{home}\source\pcileech-fpga-build\pcileech_top.bin",
          "pcileech firmware build output: pcileech_top.bin", "HIGH", "cheat",
          {"Pattern": "pcileech", "FileName": "pcileech_top.bin",
           "FullPath": rf"{home}\source\pcileech-fpga-build\pcileech_top.bin",
           "SizeBytes": 4_194_304,
           "Created": _ago(days=17), "LastWrite": _ago(days=6),
           "MostRecentTimestamp": _ago(days=6), "AgeDays": 6})
    e.add("KnownHashes", rf"{home}\Downloads\RUT V4 Launcher.exe",
          "[RUT V4 Launcher.exe (rut.gg)] hash match - confirmed cheat sample",
          "HIGH", "cheat",
          {"Pattern": "RUT V4 Launcher.exe (rut.gg)",
           "SHA256": "b1b89dedcff0c502d605a707e550b1565224b5949e778168ac45f01b8171160f",
           "FileName": "RUT V4 Launcher.exe",
           "FullPath": rf"{home}\Downloads\RUT V4 Launcher.exe",
           "SizeBytes": 8_421_376, "LastWrite": _ago(days=4),
           "MostRecentTimestamp": _ago(days=4), "AgeDays": 4,
           "KnownSampleOf": "RUT V4 Launcher.exe (rut.gg)",
           "HashSource": "Hybrid Analysis sandbox report"})

    # LOLDrivers BYOVD — vulnerable tier
    e.add("LOLDrivers", rf"{home}\AppData\Local\Temp\rtcore64.sys",
          "VULNERABLE DRIVER - hash confirmed (BYOVD risk): rtcore64.sys",
          "HIGH", "cheat",
          {"DeviceName": "RTCore64", "Manufacturer": "MSI",
           "IsSigned": "True", "FileName": "rtcore64.sys",
           "FilePath": rf"{home}\AppData\Local\Temp\rtcore64.sys",
           "LOLDrivers_Id": "0c9b1b21-5e26-4e0e-8baa-2bbb4ce4f0bd",
           "LOLDrivers_Category": "vulnerable",
           "LOLDrivers_Tags": "rtcore64.sys,rtcore32.sys",
           "LOLDrivers_MatchBy": "SHA256",
           "SHA256": "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd",
           "LOLDrivers_URL": "https://www.loldrivers.io/drivers/0c9b1b21-5e26-4e0e-8baa-2bbb4ce4f0bd/",
           "MostRecentTimestamp": _ago(days=7), "AgeDays": 7})

    # USB history hit + AppData activity for Cronus (HIGH input — will route
    # to "also" because verdict is CHEATS DETECTED).
    e.add("USB", "VID_2E24&PID_1000",
          "[cronus] Cronus Zen", "HIGH", "input",
          {"Pattern": "cronus", "FriendlyName": "Cronus Zen",
           "VID_PID": "VID_2E24&PID_1000",
           "FirstInstall": _ago(days=87),
           "LastArrival": _ago(days=1),
           "LastRemoval": _ago(hours=6),
           "MostRecentTimestamp": _ago(days=1), "AgeDays": 1})
    e.add("AppData", rf"{home}\AppData\Local\ConsoleTuner",
          "Cronus Zen Studio - 184 files, 29 distinct days",
          "HIGH", "input",
          {"Pattern": "cronuszen", "Label": "Cronus Zen Studio",
           "Directory": rf"{home}\AppData\Local\ConsoleTuner",
           "FileCount": 184, "DistinctActivityDays": 29,
           "ActivitySpanDays": 92,
           "OldestWrite": _ago(days=92),
           "NewestWrite": _ago(days=1),
           "MostRecentTimestamp": _ago(days=1), "AgeDays": 1})

    # HIGH script content
    e.add("UserScripts", rf"{home}\Desktop\setup.bat",
          "[bcdedit /set testsigning] ~\\Desktop\\setup.bat - high-risk command pattern inside script",
          "HIGH", "cheat",
          {"Pattern": "bcdedit /set testsigning",
           "MatchKind": "high-risk command in script",
           "FileName": "setup.bat",
           "FullPath": rf"{home}\Desktop\setup.bat",
           "SizeBytes": 412, "LastWrite": _ago(days=8),
           "MostRecentTimestamp": _ago(days=8), "AgeDays": 8})
    e.add("UserScripts", rf"{home}\Documents\macros\norecoil.lua",
          "[MoveMouseRelative] ~\\Documents\\macros\\norecoil.lua - mouse-macro / anti-recoil script pattern",
          "HIGH", "cheat",
          {"Pattern": "MoveMouseRelative",
           "MatchKind": "mouse-macro / anti-recoil script",
           "FileName": "norecoil.lua",
           "FullPath": rf"{home}\Documents\macros\norecoil.lua",
           "SizeBytes": 2_104, "LastWrite": _ago(days=3),
           "MostRecentTimestamp": _ago(days=3), "AgeDays": 3})

    # AI-vision constellation
    e.add("AIVision", rf"{home}\source\aimmy\aimmy.exe",
          "[aimmy] AI-vision aimbot executable: aimmy.exe", "HIGH", "cheat",
          {"Pattern": "aimmy", "FileName": "aimmy.exe",
           "FullPath": rf"{home}\source\aimmy\aimmy.exe",
           "SizeBytes": 18_223_104,
           "Created": _ago(days=18), "LastWrite": _ago(days=2),
           "MostRecentTimestamp": _ago(days=2), "AgeDays": 2})
    e.add("AIVision", rf"{home}\source\aimmy\models\yolov8n.onnx",
          "ONNX model co-located with AI-aimbot executable: yolov8n.onnx",
          "HIGH", "cheat",
          {"FileName": "yolov8n.onnx",
           "FullPath": rf"{home}\source\aimmy\models\yolov8n.onnx",
           "SizeBytes": 12_405_633,
           "CoLocated": rf"{home}\source\aimmy\aimmy.exe",
           "Created": _ago(days=18), "LastWrite": _ago(days=18),
           "MostRecentTimestamp": _ago(days=18), "AgeDays": 18})

    # BCD flag
    e.add("BCD", "testsigning",
          "TEST SIGNING ENABLED - unsigned drivers can load",
          "HIGH", "cheat", {})

    # --- MEDIUM dual-use --------------------------------------------------
    e.add("Installed", "Cheat Engine 7.5",
          "[cheatengine] Cheat Engine 7.5", "MEDIUM", "dual-use",
          {"Pattern": "cheatengine", "Name": "Cheat Engine 7.5",
           "Publisher": "Dark Byte", "InstallDate": "2026-03-12",
           "Version": "7.5",
           "MostRecentTimestamp": "2026-03-12T00:00:00", "AgeDays": 75})
    e.add("ObscuredNames", rf"{home}\Downloads\3a7b9c1e2d4f6018.exe",
          "Obscured filename: raw hex name (3a7b9c1e2d4f6018.exe)",
          "MEDIUM", "dual-use",
          {"FileName": "3a7b9c1e2d4f6018.exe",
           "FullPath": rf"{home}\Downloads\3a7b9c1e2d4f6018.exe",
           "Pattern": "raw hex name (3a7b9c1e2d4f6018.exe)",
           "SizeBytes": 1_204_800,
           "LastWrite": _ago(days=4),
           "MostRecentTimestamp": _ago(days=4), "AgeDays": 4})
    e.add("DLLInject", "Sysmon EID 7",
          "Injector activity: xenos64.dll @ " + _ago(days=11),
          "MEDIUM", "dual-use",
          {"Source": "Sysmon EID 7",
           "Timestamp": _ago(days=11),
           "ImageLoaded": rf"{home}\source\xenos\xenos64.dll",
           "TargetProcess": "explorer.exe", "ProcessId": "4288",
           "MostRecentTimestamp": _ago(days=11), "AgeDays": 11})

    # --- INFO -------------------------------------------------------------
    e.add("ProcessModules", "(scan)",
          "Scanned 8412 DLL modules across all running processes",
          "INFO", "other", {"ModulesScanned": 8412})
    e.add("KnownHashes", "(scan)",
          "Hashed 312 executables, checked against 1 known-bad SHA256 sample(s)",
          "INFO", "other", {"Hashed": 312, "DatabaseSize": 1})
    e.add("RecencyDecay", "(summary)",
          "Recency analysis: 19 recent, 3 historical (>180d demoted), 2 unknown-timestamp",
          "INFO", "other",
          {"ThresholdDays": 180, "RecentFindings": 19,
           "HistoricalFindings": 3, "UnknownTimestampFindings": 2})

    # --- WARN -------------------------------------------------------------
    e.add("BAM", r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
          "Access denied", "WARN", "other", {})
    e.add("ShimCache",
          r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
          "Access denied", "WARN", "other", {})

    # --- HISTORICAL (recency-decay demoted) -------------------------------
    e.add("Prefetch", r"C:\Windows\Prefetch\OLDCHEAT.EXE-9F8E7D6C.pf",
          "[engineowning] OLDCHEAT (CoD MW 2019)", "MEDIUM", "cheat",
          {"Pattern": "engineowning",
           "FirstSeen": _ago(days=720), "LastModified": _ago(days=420),
           "MostRecentTimestamp": _ago(days=420),
           "AgeDays": 420, "RecencyClass": "historical",
           "OriginalSeverity": "HIGH"})

    return e


def build_cheats_processes() -> list[ScoredItem]:
    home = r"C:\Users\Marcus"
    return [
        ScoredItem(
            name="ENGINEOWNING.exe", score="HIGH", kind="cheat",
            pattern="engineowning",
            reason="matches 'engineowning' (cheat keyword)",
            extra={"ProcessId": "9128", "ParentProcessId": "4288",
                   "Started": _ago(hours=2),
                   "ExecutablePath": rf"{home}\AppData\Local\engineowning\EO.exe",
                   "CommandLine": rf'"{home}\AppData\Local\engineowning\EO.exe" --loader'},
        ),
        ScoredItem(
            name="cheatengine-x86_64.exe", score="MEDIUM", kind="dual-use",
            pattern="cheatengine",
            reason="matches 'cheatengine' (dual-use tool)",
            extra={"ProcessId": "7416", "ParentProcessId": "4288",
                   "Started": _ago(hours=1),
                   "ExecutablePath": r"C:\Program Files\Cheat Engine 7.5\cheatengine-x86_64.exe",
                   "CommandLine": r'"C:\Program Files\Cheat Engine 7.5\cheatengine-x86_64.exe"'},
        ),
        ScoredItem(
            name="explorer.exe", score="CLEAN", kind="other",
            extra={"ProcessId": "4288", "ParentProcessId": "4128",
                   "Started": _ago(days=1),
                   "ExecutablePath": r"C:\Windows\explorer.exe",
                   "CommandLine": r"C:\Windows\Explorer.EXE"},
            reason="standard system location",
        ),
        ScoredItem(
            name="svchost.exe", score="CLEAN", kind="other",
            extra={"ProcessId": "1248", "ParentProcessId": "984",
                   "Started": _ago(days=1),
                   "ExecutablePath": r"C:\Windows\System32\svchost.exe",
                   "CommandLine": r"C:\Windows\System32\svchost.exe -k NetworkService"},
            reason="standard system location",
        ),
        ScoredItem(
            name="chrome.exe", score="LOW", kind="other",
            extra={"ProcessId": "12384", "ParentProcessId": "4288",
                   "Started": _ago(hours=3),
                   "ExecutablePath": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                   "CommandLine": r'"C:\Program Files\Google\Chrome\Application\chrome.exe"'},
            reason="runs from Program Files",
        ),
    ]


def build_cheats_services() -> list[ScoredItem]:
    return [
        ScoredItem(
            name="HidHide", score="HIGH", kind="input",
            pattern="hidhide",
            reason="matches 'hidhide' (input-device keyword)",
            extra={"DisplayName": "HidHide Service", "State": "Running",
                   "StartMode": "Auto",
                   "PathName": r"C:\Program Files\Nefarius Software Solutions\HidHide\x64\HidHideClient.exe",
                   "StartName": "LocalSystem", "ProcessId": "3120"},
        ),
        ScoredItem(
            name="vgc", score="CLEAN", kind="other",
            extra={"DisplayName": "vgc", "State": "Stopped",
                   "StartMode": "Manual",
                   "PathName": r'"C:\Program Files\Riot Vanguard\vgc.exe"',
                   "StartName": "LocalSystem", "ProcessId": "0"},
            reason="standard system location",
        ),
        ScoredItem(
            name="ViGEmBus", score="MEDIUM", kind="dual-use",
            pattern="vigembus",
            reason="matches 'vigembus' (dual-use tool)",
            extra={"DisplayName": "Virtual Gamepad Emulation Bus",
                   "State": "Running", "StartMode": "Manual",
                   "PathName": r"C:\Windows\System32\drivers\ViGEmBus.sys",
                   "StartName": "LocalSystem", "ProcessId": "4"},
        ),
    ]


# ---------------------------------------------------------------------------
# PC MODE — INPUT DEVICES DETECTED  (fabricated user: Jordan)
# ---------------------------------------------------------------------------
def build_input_engine() -> Engine:
    e = _make_engine()
    home = r"C:\Users\Jordan"

    # --- HIGH input findings — the full XIM/Cronus/HidHide/reWASD stack --
    e.add("Installed", "XIM MATRIX",
          "[xim matrix] XIM MATRIX", "HIGH", "input",
          {"Pattern": "xim matrix", "Name": "XIM MATRIX",
           "Publisher": "XIM Technologies",
           "InstallDate": "2026-02-04",
           "Version": "20250118.6",
           "MostRecentTimestamp": "2026-02-04T00:00:00",
           "AgeDays": 111})
    e.add("Installed", "Cronus Zen Studio",
          "[cronuszen] Cronus Zen Studio", "HIGH", "input",
          {"Pattern": "cronuszen", "Name": "Cronus Zen Studio",
           "Publisher": "Collective Minds Gaming Co.",
           "InstallDate": "2025-09-22",
           "Version": "2.2.10",
           "MostRecentTimestamp": "2025-09-22T00:00:00",
           "AgeDays": 246})
    e.add("Installed", "reWASD",
          "[rewasd] reWASD", "HIGH", "input",
          {"Pattern": "rewasd", "Name": "reWASD",
           "Publisher": "Disc Soft Ltd",
           "InstallDate": "2026-01-18",
           "Version": "7.0.0.8400",
           "MostRecentTimestamp": "2026-01-18T00:00:00",
           "AgeDays": 128})
    e.add("Installed", "HidHide",
          "[hidhide] HidHide", "HIGH", "input",
          {"Pattern": "hidhide", "Name": "HidHide",
           "Publisher": "Nefarius Software Solutions e.U.",
           "InstallDate": "2026-01-18",
           "Version": "1.5.230.0",
           "MostRecentTimestamp": "2026-01-18T00:00:00",
           "AgeDays": 128})

    # USB-history hits (Cronus Zen + XIM Matrix have real VIDs)
    e.add("USB", "VID_2E24&PID_1000",
          "[cronus] Cronus Zen", "HIGH", "input",
          {"Pattern": "cronus", "FriendlyName": "Cronus Zen",
           "VID_PID": "VID_2E24&PID_1000",
           "FirstInstall": _ago(days=240),
           "LastArrival": _ago(hours=8),
           "LastRemoval": _ago(hours=2),
           "MostRecentTimestamp": _ago(hours=2),
           "AgeDays": 0})
    e.add("USB", "VID_2516&PID_0140",
          "[xim matrix] XIM Matrix", "HIGH", "input",
          {"Pattern": "xim matrix", "FriendlyName": "XIM Matrix",
           "VID_PID": "VID_2516&PID_0140",
           "FirstInstall": _ago(days=110),
           "LastArrival": _ago(hours=8),
           "LastRemoval": _ago(hours=2),
           "MostRecentTimestamp": _ago(hours=2),
           "AgeDays": 0})

    # AppData activity tracks — these populate the lifecycle section
    e.add("AppData", rf"{home}\AppData\Local\XIM Matrix",
          "XIM MATRIX - 312 files, 41 distinct days",
          "HIGH", "input",
          {"Pattern": "xim matrix", "Label": "XIM MATRIX",
           "Directory": rf"{home}\AppData\Local\XIM Matrix",
           "FileCount": 312, "DistinctActivityDays": 41,
           "ActivitySpanDays": 110,
           "OldestWrite": _ago(days=110),
           "NewestWrite": _ago(hours=8),
           "MostRecentTimestamp": _ago(hours=8),
           "AgeDays": 0})
    e.add("AppData", rf"{home}\AppData\Local\ConsoleTuner",
          "Cronus Zen Studio - 528 files, 87 distinct days",
          "HIGH", "input",
          {"Pattern": "cronuszen", "Label": "Cronus Zen Studio",
           "Directory": rf"{home}\AppData\Local\ConsoleTuner",
           "FileCount": 528, "DistinctActivityDays": 87,
           "ActivitySpanDays": 240,
           "OldestWrite": _ago(days=240),
           "NewestWrite": _ago(hours=8),
           "MostRecentTimestamp": _ago(hours=8),
           "AgeDays": 0})
    e.add("AppData", rf"{home}\AppData\Roaming\reWASD",
          "reWASD - 96 files, 22 distinct days",
          "HIGH", "input",
          {"Pattern": "rewasd", "Label": "reWASD",
           "Directory": rf"{home}\AppData\Roaming\reWASD",
           "FileCount": 96, "DistinctActivityDays": 22,
           "ActivitySpanDays": 128,
           "OldestWrite": _ago(days=128),
           "NewestWrite": _ago(days=1),
           "MostRecentTimestamp": _ago(days=1), "AgeDays": 1})

    # --- MEDIUM dual-use (capture / virtual-pad) — entirely normal for a
    # console-stick player who also streams.
    e.add("Installed", "OBS Studio",
          "[obs studio] OBS Studio", "MEDIUM", "dual-use",
          {"Pattern": "obs studio", "Name": "OBS Studio",
           "Publisher": "OBS Project", "InstallDate": "2026-02-08",
           "Version": "30.1.2",
           "MostRecentTimestamp": "2026-02-08T00:00:00",
           "AgeDays": 107})
    e.add("Installed", "DS4Windows",
          "[ds4windows] DS4Windows", "MEDIUM", "dual-use",
          {"Pattern": "ds4windows", "Name": "DS4Windows",
           "Publisher": "Ryochan7", "InstallDate": "2026-01-15",
           "Version": "3.3.3",
           "MostRecentTimestamp": "2026-01-15T00:00:00",
           "AgeDays": 131})

    # --- INFO -------------------------------------------------------------
    e.add("ProcessModules", "(scan)",
          "Scanned 7204 DLL modules across all running processes",
          "INFO", "other", {"ModulesScanned": 7204})
    e.add("KnownHashes", "(scan)",
          "Hashed 268 executables, checked against 1 known-bad SHA256 sample(s)",
          "INFO", "other", {"Hashed": 268, "DatabaseSize": 1})
    e.add("RecencyDecay", "(summary)",
          "Recency analysis: 11 recent, 1 historical (>180d demoted), 1 unknown-timestamp",
          "INFO", "other",
          {"ThresholdDays": 180, "RecentFindings": 11,
           "HistoricalFindings": 1, "UnknownTimestampFindings": 1})

    # --- WARN -------------------------------------------------------------
    e.add("ShimCache",
          r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
          "Access denied", "WARN", "other", {})

    # --- HISTORICAL -------------------------------------------------------
    e.add("Installed", "XIM APEX",
          "[xim apex] XIM APEX (legacy)", "INFO", "input",
          {"Pattern": "xim apex", "Name": "XIM APEX",
           "InstallDate": "2021-06-12",
           "MostRecentTimestamp": "2021-06-12T00:00:00",
           "AgeDays": 1_809, "RecencyClass": "historical",
           "OriginalSeverity": "MEDIUM"})

    return e


def build_input_processes() -> list[ScoredItem]:
    home = r"C:\Users\Jordan"
    return [
        ScoredItem(
            name="HidHideClient.exe", score="HIGH", kind="input",
            pattern="hidhide",
            reason="matches 'hidhide' (input-device keyword)",
            extra={"ProcessId": "5104", "ParentProcessId": "4288",
                   "Started": _ago(hours=8),
                   "ExecutablePath": r"C:\Program Files\Nefarius Software Solutions\HidHide\x64\HidHideClient.exe",
                   "CommandLine": r'"C:\Program Files\Nefarius Software Solutions\HidHide\x64\HidHideClient.exe"'},
        ),
        ScoredItem(
            name="reWASDEngine.exe", score="HIGH", kind="input",
            pattern="rewasdengine",
            reason="matches 'rewasdengine' (input-device keyword)",
            extra={"ProcessId": "6248", "ParentProcessId": "984",
                   "Started": _ago(hours=8),
                   "ExecutablePath": r"C:\Program Files\reWASD\reWASDEngine.exe",
                   "CommandLine": r'"C:\Program Files\reWASD\reWASDEngine.exe" --service'},
        ),
        ScoredItem(
            name="XIM Matrix Manager.exe", score="HIGH", kind="input",
            pattern="xim matrix",
            reason="matches 'xim matrix' (input-device keyword)",
            extra={"ProcessId": "9320", "ParentProcessId": "4288",
                   "Started": _ago(hours=8),
                   "ExecutablePath": r"C:\Program Files (x86)\XIM Technologies\XIM Matrix Manager\XIM Matrix Manager.exe",
                   "CommandLine": r'"C:\Program Files (x86)\XIM Technologies\XIM Matrix Manager\XIM Matrix Manager.exe"'},
        ),
        ScoredItem(
            name="explorer.exe", score="CLEAN", kind="other",
            extra={"ProcessId": "4288", "ParentProcessId": "4128",
                   "Started": _ago(days=1),
                   "ExecutablePath": r"C:\Windows\explorer.exe",
                   "CommandLine": r"C:\Windows\Explorer.EXE"},
            reason="standard system location",
        ),
        ScoredItem(
            name="svchost.exe", score="CLEAN", kind="other",
            extra={"ProcessId": "1248", "ParentProcessId": "984",
                   "Started": _ago(days=1),
                   "ExecutablePath": r"C:\Windows\System32\svchost.exe",
                   "CommandLine": r"C:\Windows\System32\svchost.exe -k NetworkService"},
            reason="standard system location",
        ),
        ScoredItem(
            name="chrome.exe", score="LOW", kind="other",
            extra={"ProcessId": "12384", "ParentProcessId": "4288",
                   "Started": _ago(hours=2),
                   "ExecutablePath": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                   "CommandLine": r'"C:\Program Files\Google\Chrome\Application\chrome.exe"'},
            reason="runs from Program Files",
        ),
    ]


def build_input_services() -> list[ScoredItem]:
    return [
        ScoredItem(
            name="HidHide", score="HIGH", kind="input",
            pattern="hidhide",
            reason="matches 'hidhide' (input-device keyword)",
            extra={"DisplayName": "HidHide Service", "State": "Running",
                   "StartMode": "Auto",
                   "PathName": r"C:\Windows\System32\drivers\HidHide.sys",
                   "StartName": "LocalSystem", "ProcessId": "4"},
        ),
        ScoredItem(
            name="ViGEmBus", score="MEDIUM", kind="dual-use",
            pattern="vigembus",
            reason="matches 'vigembus' (dual-use tool)",
            extra={"DisplayName": "Virtual Gamepad Emulation Bus",
                   "State": "Running", "StartMode": "Manual",
                   "PathName": r"C:\Windows\System32\drivers\ViGEmBus.sys",
                   "StartName": "LocalSystem", "ProcessId": "4"},
        ),
        ScoredItem(
            name="vgc", score="CLEAN", kind="other",
            extra={"DisplayName": "vgc", "State": "Stopped",
                   "StartMode": "Manual",
                   "PathName": r'"C:\Program Files\Riot Vanguard\vgc.exe"',
                   "StartName": "LocalSystem", "ProcessId": "0"},
            reason="standard system location",
        ),
    ]


# ---------------------------------------------------------------------------
# PC MODE — CLEAN  (fabricated user: Alex)
# ---------------------------------------------------------------------------
def build_clean_engine() -> Engine:
    e = _make_engine()

    e.add("ProcessModules", "(scan)",
          "Scanned 6021 DLL modules across all running processes",
          "INFO", "other", {"ModulesScanned": 6021})
    e.add("KnownHashes", "(scan)",
          "Hashed 284 executables, checked against 1 known-bad SHA256 sample(s)",
          "INFO", "other", {"Hashed": 284, "DatabaseSize": 1})
    e.add("RecencyDecay", "(summary)",
          "Recency analysis: 0 recent, 2 historical (>180d demoted), 1 unknown-timestamp",
          "INFO", "other",
          {"ThresholdDays": 180, "RecentFindings": 0,
           "HistoricalFindings": 2, "UnknownTimestampFindings": 1})

    # WARN — typical access-denied artifact (BAM requires SYSTEM, not admin)
    e.add("BAM", r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
          "Access denied", "WARN", "other", {})

    # HISTORICAL — proves the lifecycle still has a track when verdict is
    # green but a long-ago artifact remains.
    e.add("Installed", "XIM Manager 2018",
          "[xim] XIM Manager 2018", "INFO", "input",
          {"Pattern": "xim", "Name": "XIM Manager 2018",
           "InstallDate": "2018-11-04",
           "MostRecentTimestamp": "2018-11-04T00:00:00",
           "AgeDays": 2_750, "RecencyClass": "historical",
           "OriginalSeverity": "MEDIUM"})

    return e


def build_clean_processes() -> list[ScoredItem]:
    return [
        ScoredItem(name="explorer.exe", score="CLEAN", kind="other",
                   reason="standard system location",
                   extra={"ProcessId": "4288", "ParentProcessId": "4128",
                          "Started": _ago(days=1),
                          "ExecutablePath": r"C:\Windows\explorer.exe",
                          "CommandLine": r"C:\Windows\Explorer.EXE"}),
        ScoredItem(name="svchost.exe", score="CLEAN", kind="other",
                   reason="standard system location",
                   extra={"ProcessId": "1248", "ParentProcessId": "984",
                          "Started": _ago(days=1),
                          "ExecutablePath": r"C:\Windows\System32\svchost.exe",
                          "CommandLine": r"C:\Windows\System32\svchost.exe -k NetworkService"}),
        ScoredItem(name="steam.exe", score="LOW", kind="other",
                   reason="runs from Program Files (x86)",
                   extra={"ProcessId": "8472", "ParentProcessId": "4288",
                          "Started": _ago(hours=4),
                          "ExecutablePath": r"C:\Program Files (x86)\Steam\steam.exe",
                          "CommandLine": r'"C:\Program Files (x86)\Steam\steam.exe" -silent'}),
        ScoredItem(name="chrome.exe", score="LOW", kind="other",
                   reason="runs from Program Files",
                   extra={"ProcessId": "12384", "ParentProcessId": "4288",
                          "Started": _ago(hours=3),
                          "ExecutablePath": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                          "CommandLine": r'"C:\Program Files\Google\Chrome\Application\chrome.exe"'}),
    ]


def build_clean_services() -> list[ScoredItem]:
    return [
        ScoredItem(name="vgc", score="CLEAN", kind="other",
                   reason="standard system location",
                   extra={"DisplayName": "vgc", "State": "Running",
                          "StartMode": "Auto",
                          "PathName": r'"C:\Program Files\Riot Vanguard\vgc.exe"'}),
    ]


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def _emit(out_dir: Path, *, basename: str, verdict: str,
          engine: Engine, processes: list[ScoredItem],
          services: list[ScoredItem], lol_db_used: bool) -> None:
    """Shared emit path: derive verdict counts, build ctx + spec, write
    both .txt and _visual.html via the production formatters."""
    high_cheats = [f for f in engine.findings
                   if f.severity == "HIGH" and f.kind == "cheat"
                   and f.metadata.get("RecencyClass") != "historical"]
    high_input = [f for f in engine.findings
                  if f.severity == "HIGH" and f.kind == "input"
                  and f.metadata.get("RecencyClass") != "historical"]
    medium_any = [f for f in engine.findings
                  if f.severity == "MEDIUM"
                  and f.metadata.get("RecencyClass") != "historical"]
    historical = [f for f in engine.findings
                  if f.metadata.get("RecencyClass") == "historical"]
    historical_high = [f for f in historical
                       if f.metadata.get("OriginalSeverity") == "HIGH"]

    proc_high_cheat = [p for p in processes if p.score == "HIGH" and p.kind == "cheat"]
    proc_high_input = [p for p in processes if p.score == "HIGH" and p.kind == "input"]
    proc_medium = [p for p in processes if p.score == "MEDIUM"]
    svc_high_cheat = [s for s in services if s.score == "HIGH" and s.kind == "cheat"]
    svc_high_input = [s for s in services if s.score == "HIGH" and s.kind == "input"]
    svc_medium = [s for s in services if s.score == "MEDIUM"]

    total_cheat_high = len(high_cheats) + len(proc_high_cheat) + len(svc_high_cheat)
    total_input_high = len(high_input) + len(proc_high_input) + len(svc_high_input)
    total_medium = len(medium_any) + len(proc_medium) + len(svc_medium)

    ctx = ReportContext(
        engine=engine, processes=processes, services=services,
        verdict=verdict,
        total_cheat_high=total_cheat_high,
        total_input_high=total_input_high,
        total_medium=total_medium,
        named_cheats=collect_named_items(engine, processes, services, "cheat", "HIGH"),
        named_input=collect_named_items(engine, processes, services, "input", "HIGH"),
        historical_findings=historical,
        historical_high=historical_high,
        medium_findings=medium_any,
        proc_medium=proc_medium,
        svc_medium=svc_medium,
        lol_db_used=lol_db_used,
    )

    spec = ReportSpec(
        title=f"ALIBI {SCANNER_VERSION} - CONSOLIDATED REPORT",
        quick_read_block=_pc_quick_read,
        limitations=_PC_LIMITATIONS,
        threshold_days=RECENCY_THRESHOLD_DAYS,
    )

    text_path = out_dir / f"{basename}.txt"
    html_path = out_dir / f"{basename}_visual.html"
    text_path.write_text(build_text_report(spec, ctx), encoding="utf-8")
    write_html(str(html_path), render_html(
        engine=engine, processes=processes, services=services,
        verdict=verdict,
        threshold_days=RECENCY_THRESHOLD_DAYS,
        report_title=f"Alibi {SCANNER_VERSION}",
        mode_label="pc-mode",
        lol_db_used=lol_db_used,
    ))
    print(f"  wrote: {text_path.name}")
    print(f"  wrote: {html_path.name}")


def emit_cheats(out_dir: Path) -> None:
    _emit(out_dir, basename="pc-mode-cheats-detected",
          verdict="CHEATS DETECTED",
          engine=build_cheats_engine(),
          processes=build_cheats_processes(),
          services=build_cheats_services(),
          lol_db_used=True)


def emit_input(out_dir: Path) -> None:
    _emit(out_dir, basename="pc-mode-input-devices-detected",
          verdict="INPUT DEVICES DETECTED",
          engine=build_input_engine(),
          processes=build_input_processes(),
          services=build_input_services(),
          lol_db_used=False)


def emit_clean(out_dir: Path) -> None:
    _emit(out_dir, basename="pc-mode-clean",
          verdict="CLEAN",
          engine=build_clean_engine(),
          processes=build_clean_processes(),
          services=build_clean_services(),
          lol_db_used=False)


if __name__ == "__main__":
    out_dir = _HERE
    print(f"Generating synthetic examples into {out_dir}")
    emit_cheats(out_dir)
    emit_input(out_dir)
    emit_clean(out_dir)
    print("Done.")
