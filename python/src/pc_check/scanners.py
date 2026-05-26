"""All 21 scan functions plus invoke_all_scans.

Faithful port of forensic-common.ps1 Scan-*. Each function takes an Engine
(which holds the composite keyword arrays and the findings list), reads
Windows artifacts read-only, and emits Findings.

Notes on stdlib-only choices:
  - Registry: winreg via reg.py.
  - WMI/CIM: subprocess shell-out to PowerShell (driverquery is a native exe;
    snapshots use Get-CimInstance; event logs use wevtutil).
  - Hashing: hashlib.
  - No third-party libs. Everything the reviewer needs to read is here.
"""
from __future__ import annotations

import csv
import fnmatch
import hashlib
import io
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from pc_check.findings import SEV_HIGH, SEV_INFO, SEV_MEDIUM, SEV_WARN
from pc_check.keywords import (
    APPDATA_PATTERNS,
    DLL_INJECTOR_NAMES,
    DRIVER_PUBLISHER_ALLOWLIST,
    KNOWN_CHEAT_HASHES,
    LUA_CHEAT_KEYWORDS,
    NETWORK_ATTACK_HIGH,
    NETWORK_ATTACK_MEDIUM,
    VISION_AIMBOT_AI_PC,
)
from pc_check.reg import iter_subkeys, iter_values, key_exists, open_key, read_all_values, read_value
from pc_check.utils import (
    Engine,
    classify_path_risk,
    convert_filetime_bytes,
    iso,
    match_allowlist,
    match_keyword,
    score_and_add,
)

try:
    import winreg  # type: ignore[import-not-found]
except ImportError:
    winreg = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _user_profile() -> str:
    return os.environ.get("USERPROFILE", os.path.expanduser("~"))


def _appdata() -> str:
    return os.environ.get("APPDATA", os.path.join(_user_profile(), "AppData", "Roaming"))


def _localappdata() -> str:
    return os.environ.get("LOCALAPPDATA", os.path.join(_user_profile(), "AppData", "Local"))


def _system_root() -> str:
    return os.environ.get("SystemRoot", r"C:\Windows")


def _file_stat(path: str) -> os.stat_result | None:
    try:
        return os.stat(path)
    except OSError:
        return None


def _iso_from_mtime(stat: os.stat_result | None) -> str:
    if not stat:
        return ""
    return datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%dT%H:%M:%S")


def _iso_from_ctime(stat: os.stat_result | None) -> str:
    if not stat:
        return ""
    return datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%dT%H:%M:%S")


def _safe_walk(root: str) -> Iterable[tuple[str, list[str], list[str]]]:
    if not os.path.isdir(root):
        return
    yield from os.walk(root, onerror=lambda _e: None)


def _enumerate_files(
    root: str,
    *,
    ext_lower: tuple[str, ...] | None = None,
    max_size_mb: int | None = None,
    cap: int | None = None,
) -> list[tuple[str, os.stat_result]]:
    out: list[tuple[str, os.stat_result]] = []
    for dirpath, _dirnames, filenames in _safe_walk(root):
        for name in filenames:
            if ext_lower is not None:
                lo = name.lower()
                if not any(lo.endswith(e) for e in ext_lower):
                    continue
            full = os.path.join(dirpath, name)
            st = _file_stat(full)
            if not st:
                continue
            if max_size_mb is not None and st.st_size >= max_size_mb * 1024 * 1024:
                continue
            out.append((full, st))
            if cap is not None and len(out) >= cap:
                return out
    return out


def _read_zone_identifier(path: str) -> dict[str, str] | None:
    """Read the Zone.Identifier NTFS alternate data stream. Returns HostUrl /
    ReferrerUrl if found. Stdlib-only via the ':Zone.Identifier' suffix.
    """
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    out: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip()
            if k in ("HostUrl", "ReferrerUrl"):
                out[k] = v
    return out or None


# ---------------------------------------------------------------------------
# Scan-Prefetch
# ---------------------------------------------------------------------------
def scan_prefetch(engine: Engine) -> None:
    print("  [*] Prefetch...")
    pf = os.path.join(_system_root(), "Prefetch")
    if not os.path.isdir(pf):
        return
    try:
        names = os.listdir(pf)
    except OSError:
        engine.add("Prefetch", pf, "Access denied (run as admin)", SEV_WARN, "other")
        return
    for name in names:
        if not name.lower().endswith(".pf"):
            continue
        full = os.path.join(pf, name)
        st = _file_stat(full)
        meta = {
            "FirstSeen": _iso_from_ctime(st),
            "LastModified": _iso_from_mtime(st),
        }
        base = os.path.splitext(name)[0]
        score_and_add(engine, "Prefetch", full, base, "", meta)


# ---------------------------------------------------------------------------
# Scan-BAM (last execution timestamps)
# ---------------------------------------------------------------------------
def scan_bam(engine: Engine) -> None:
    print("  [*] BAM (last execution timestamps)...")
    bases = [
        r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        r"HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings",
    ]
    for base in bases:
        if not key_exists(base):
            continue
        try:
            sids = list(iter_subkeys(base))
        except OSError:
            engine.add("BAM", base, "Access denied", SEV_WARN, "other")
            continue
        for sid in sids:
            sid_path = base + "\\" + sid
            for vn, data, _typ in iter_values(sid_path):
                if vn in ("SequenceNumber", "Version"):
                    continue
                last_run = convert_filetime_bytes(data if isinstance(data, (bytes, bytearray)) else None)
                meta = {
                    "Executable": vn,
                    "LastExecution": iso(last_run),
                    "UserSID": sid,
                }
                suffix = f" - last run: {iso(last_run)}" if last_run else ""
                score_and_add(engine, "BAM", sid, f"{vn}{suffix}", "", meta)


# ---------------------------------------------------------------------------
# Scan-InstalledSoftware
# ---------------------------------------------------------------------------
_INSTALLED_ROOTS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
]


def _iter_installed() -> Iterable[dict[str, Any]]:
    for root in _INSTALLED_ROOTS:
        if not key_exists(root):
            continue
        for sub in iter_subkeys(root):
            props = read_all_values(root + "\\" + sub)
            if props.get("DisplayName"):
                yield props


def _normalize_install_date(raw: Any) -> str:
    if not raw:
        return ""
    s = str(raw)
    if re.fullmatch(r"\d{8}", s):
        try:
            return datetime.strptime(s, "%Y%m%d").strftime("%Y-%m-%d")
        except ValueError:
            return s
    return s


def scan_installed_software(engine: Engine) -> None:
    print("  [*] Installed software...")
    for a in _iter_installed():
        meta = {
            "Name": a.get("DisplayName", ""),
            "Version": a.get("DisplayVersion", ""),
            "Publisher": a.get("Publisher", ""),
            "InstallDate": _normalize_install_date(a.get("InstallDate")),
            "InstallLocation": a.get("InstallLocation", ""),
            "SizeKB": a.get("EstimatedSize", ""),
        }
        score_and_add(engine, "Installed", str(a.get("DisplayName", "")), str(a.get("DisplayName", "")), "", meta)


# ---------------------------------------------------------------------------
# Scan-RecentFiles
# ---------------------------------------------------------------------------
def _lnk_target(lnk_path: str) -> str | None:
    """Crude .lnk target parser — extracts the LinkTarget from the shell-link
    structure. Returns None on any parse error. Pure stdlib via struct.

    This is *good enough* for surfacing the target name into a finding meta
    field; a malformed .lnk simply yields no target. Reviewer can still see
    the .lnk filename itself.
    """
    try:
        with open(lnk_path, "rb") as fh:
            data = fh.read(8192)
    except OSError:
        return None
    if len(data) < 0x4C or data[0:4] != b"L\x00\x00\x00":
        return None
    # Look for a likely path string in the body (UTF-16LE or ASCII drive prefix).
    import struct as _struct
    try:
        flags = _struct.unpack_from("<I", data, 0x14)[0]
    except _struct.error:
        return None
    # Skip the header (76 bytes). If HasLinkTargetIDList (flag bit 0) is set,
    # skip the IDList block.
    pos = 76
    if flags & 0x1:
        if pos + 2 > len(data):
            return None
        idlist_size = _struct.unpack_from("<H", data, pos)[0]
        pos += 2 + idlist_size
    if not (flags & 0x2):  # HasLinkInfo
        return None
    if pos + 4 > len(data):
        return None
    link_info_size = _struct.unpack_from("<I", data, pos)[0]
    link_info = data[pos:pos + link_info_size]
    if len(link_info) < 0x20:
        return None
    try:
        local_base_path_offset = _struct.unpack_from("<I", link_info, 0x10)[0]
        common_path_offset = _struct.unpack_from("<I", link_info, 0x18)[0]
    except _struct.error:
        return None
    if local_base_path_offset and local_base_path_offset < len(link_info):
        end = link_info.find(b"\x00", local_base_path_offset)
        base = link_info[local_base_path_offset:end if end != -1 else None]
        common = b""
        if common_path_offset and common_path_offset < len(link_info):
            cend = link_info.find(b"\x00", common_path_offset)
            common = link_info[common_path_offset:cend if cend != -1 else None]
        try:
            return (base + common).decode("mbcs", errors="replace")
        except (UnicodeDecodeError, LookupError):
            return (base + common).decode("utf-8", errors="replace")
    return None


def scan_recent_files(engine: Engine) -> None:
    print("  [*] Recent files...")
    recent = os.path.join(_appdata(), "Microsoft", "Windows", "Recent")
    if not os.path.isdir(recent):
        return
    for full, st in _enumerate_files(recent):
        target = None
        if full.lower().endswith(".lnk"):
            target = _lnk_target(full)
        meta = {
            "Target": target or "",
            "LastWrite": _iso_from_mtime(st),
        }
        score_and_add(engine, "Recent", full, os.path.basename(full), "", meta)


# ---------------------------------------------------------------------------
# Scan-MUICache
# ---------------------------------------------------------------------------
_MUI_KEY = r"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"


def scan_muicache(engine: Engine) -> None:
    print("  [*] MUICache...")
    if not key_exists(_MUI_KEY):
        return
    for name, data, _typ in iter_values(_MUI_KEY):
        if name.startswith("PS"):
            continue
        meta = {"Value": name, "Data": str(data) if data is not None else ""}
        score_and_add(engine, "MUICache", "HKCU\\...\\MuiCache", name, "", meta)


# ---------------------------------------------------------------------------
# Scan-USBHistory
# ---------------------------------------------------------------------------
_USB_KEY = r"HKLM\SYSTEM\CurrentControlSet\Enum\USB"
_PROP_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"


def scan_usb_history(engine: Engine) -> None:
    print("  [*] USB device history...")
    if not key_exists(_USB_KEY):
        return
    try:
        vendors = list(iter_subkeys(_USB_KEY))
    except OSError:
        engine.add("USB", _USB_KEY, "Access denied", SEV_WARN, "other")
        return
    for vendor in vendors:
        vendor_path = _USB_KEY + "\\" + vendor
        try:
            devs = list(iter_subkeys(vendor_path))
        except OSError:
            continue
        for dev in devs:
            dev_path = vendor_path + "\\" + dev
            props = read_all_values(dev_path)
            blob = f"{props.get('FriendlyName','')} | {props.get('DeviceDesc','')} | {props.get('Mfg','')} | {vendor}"
            hit_c = match_keyword(blob, engine.keywords_high_cheats)
            hit_i = match_keyword(blob, engine.keywords_high_input)
            hit_m = match_keyword(blob, engine.keywords_medium)
            if not (hit_c or hit_i or hit_m):
                continue

            first_install = last_arrival = last_removal = None
            props_root = dev_path + "\\Properties\\" + _PROP_GUID
            for sub, var in (
                ("0064\\00000000", "first_install"),
                ("0065\\00000000", "last_arrival"),
                ("0066\\00000000", "last_removal"),
            ):
                full = props_root + "\\" + sub
                if key_exists(full):
                    blob_data = read_value(full, "")
                    ft = convert_filetime_bytes(blob_data if isinstance(blob_data, (bytes, bytearray)) else None)
                    if ft:
                        if var == "first_install":
                            first_install = ft
                        elif var == "last_arrival":
                            last_arrival = ft
                        else:
                            last_removal = ft

            if hit_c:
                sev, kind, pat = SEV_HIGH, "cheat", hit_c
            elif hit_i:
                sev, kind, pat = SEV_HIGH, "input", hit_i
            else:
                sev, kind, pat = SEV_MEDIUM, "dual-use", hit_m

            if sev == SEV_HIGH and not (first_install or last_arrival or last_removal):
                sev = SEV_MEDIUM
                if kind == "input":
                    kind = "dual-use"

            meta = {
                "Pattern": pat,
                "FriendlyName": props.get("FriendlyName", ""),
                "VID_PID": vendor,
                "FirstInstall": iso(first_install),
                "LastArrival": iso(last_arrival),
                "LastRemoval": iso(last_removal),
            }
            engine.add("USB", vendor, f"[{pat}] {props.get('FriendlyName','')}", sev, kind, meta)


# ---------------------------------------------------------------------------
# Scan-DriverSigning (BCD flags)
# ---------------------------------------------------------------------------
def scan_driver_signing(engine: Engine) -> None:
    print("  [*] BCD driver-signing flags...")
    try:
        result = subprocess.run(
            ["bcdedit.exe", "/enum", "{current}"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        engine.add("BCD", "bcdedit", "Error", SEV_WARN, "other")
        return
    if result.returncode != 0 and not result.stdout:
        engine.add("BCD", "bcdedit", "Cannot read (admin needed)", SEV_WARN, "other")
        return
    out = result.stdout or ""
    for line in out.splitlines():
        low = line.lower().strip()
        if low.startswith("testsigning") and "yes" in low:
            engine.add("BCD", "testsigning",
                       "TEST SIGNING ENABLED - unsigned drivers can load",
                       SEV_HIGH, "cheat")
        elif low.startswith("nointegritychecks") and "yes" in low:
            engine.add("BCD", "nointegritychecks",
                       "Driver integrity checks DISABLED",
                       SEV_HIGH, "cheat")


# ---------------------------------------------------------------------------
# Scan-Drivers + LOLDrivers cross-reference
# ---------------------------------------------------------------------------
def _run_driverquery() -> list[dict[str, str]]:
    try:
        result = subprocess.run(
            ["driverquery.exe", "/si", "/fo", "csv"],
            capture_output=True, text=True, timeout=120, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if not result.stdout:
        return []
    reader = csv.DictReader(io.StringIO(result.stdout))
    return list(reader)


def _run_cim_drivers() -> list[dict[str, str]]:
    cmd = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-Command",
        "Get-CimInstance Win32_SystemDriver | Select-Object Name,Description,PathName | "
        "ConvertTo-Csv -NoTypeInformation",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    if not result.stdout:
        return []
    reader = csv.DictReader(io.StringIO(result.stdout))
    return list(reader)


def _normalize_sys_path(raw: str) -> str:
    if not raw:
        return ""
    s = raw
    s = re.sub(r"^\\SystemRoot\\", _system_root() + "\\", s, flags=re.IGNORECASE)
    s = re.sub(r"^\\\?\?\\", "", s)
    return s


def _sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest().lower()
    except OSError:
        return None


def scan_drivers(engine: Engine) -> None:
    print("  [*] Driver enumeration + LOLDrivers cross-reference...")

    rows: list[dict[str, str]] = []
    for d in _run_driverquery():
        rows.append({
            "DeviceName": d.get("Module Name", "") or d.get("DeviceName", "") or d.get("Display Name", ""),
            "Manufacturer": d.get("Driver Type", "") or d.get("Manufacturer", "") or d.get("Description", ""),
            "IsSigned": d.get("Is Signed", "") or d.get("IsSigned", ""),
            "FileName": "",
            "FilePath": "",
            "SHA256": "",
        })

    if not rows:
        engine.add("Drivers", "driverquery", "driverquery failed", SEV_WARN, "other")

    # Enrich from Win32_SystemDriver for the actual .sys path.
    for cim in _run_cim_drivers():
        name = (cim.get("Name") or "").strip()
        path = _normalize_sys_path((cim.get("PathName") or "").strip())
        matched = None
        for row in rows:
            if (row["DeviceName"] or "").lower() == name.lower():
                matched = row
                break
        if matched:
            matched["FilePath"] = path
            matched["FileName"] = os.path.basename(path)
        else:
            rows.append({
                "DeviceName": name,
                "Manufacturer": cim.get("Description", "") or "",
                "IsSigned": "",
                "FileName": os.path.basename(path) if path else "",
                "FilePath": path,
                "SHA256": "",
            })

    # Hash drivers in non-standard locations.
    for row in rows:
        fp = row["FilePath"]
        if not fp or not os.path.isfile(fp):
            continue
        bucket = classify_path_risk(fp)
        if bucket in ("user-writable", "unknown", "typical"):
            h = _sha256_file(fp)
            if h:
                row["SHA256"] = h

    for row in rows:
        meta = {
            "DeviceName": row["DeviceName"],
            "Manufacturer": row["Manufacturer"],
            "IsSigned": row["IsSigned"],
            "FileName": row["FileName"],
            "FilePath": row["FilePath"],
        }

        # Rule 1: cheat/input keyword match.
        score_and_add(
            engine, "Drivers", row["DeviceName"],
            f"{row['DeviceName']} {row['Manufacturer']} {row['FileName']}",
            "", meta,
        )

        # Rule 2: unsigned driver check.
        if row["IsSigned"] in ("FALSE", "False", "False ", "FALSE "):
            allow = False
            if row["Manufacturer"]:
                for t in DRIVER_PUBLISHER_ALLOWLIST:
                    if t.lower() in row["Manufacturer"].lower():
                        allow = True
                        break
            if (not row["Manufacturer"] or row["Manufacturer"] == "N/A") and \
                    re.match(r"^(USB|HID|WUDF|Microsoft|Bluetooth)", row["DeviceName"] or ""):
                allow = True
            if not allow:
                engine.add("Drivers", row["DeviceName"],
                           f"UNSIGNED: {row['DeviceName']}", SEV_MEDIUM, "dual-use", dict(meta))

        # Rule 3: LOLDrivers cross-reference.
        if not engine.lol_db:
            continue
        file_index = engine.lol_db.get("FileIndex", {})
        hash_index = engine.lol_db.get("HashIndex", {})
        lol_hit: dict[str, str] | None = None
        if row["FileName"]:
            fn_key = row["FileName"].lower()
            if fn_key in file_index:
                lol_hit = dict(file_index[fn_key])
                lol_hit["MatchedBy"] = "Filename"
        if not lol_hit and row["SHA256"] and row["SHA256"] in hash_index:
            lol_hit = dict(hash_index[row["SHA256"]])
            lol_hit["MatchedBy"] = "SHA256"
        if not lol_hit:
            continue

        lol_meta = dict(meta)
        lol_meta.update({
            "LOLDrivers_Id": lol_hit.get("Id", ""),
            "LOLDrivers_Category": lol_hit.get("Category", ""),
            "LOLDrivers_Tags": lol_hit.get("Tags", ""),
            "LOLDrivers_MatchBy": lol_hit["MatchedBy"],
            "SHA256": row["SHA256"],
            "LOLDrivers_URL": f"https://www.loldrivers.io/drivers/{lol_hit.get('Id','')}/",
        })

        cat = (lol_hit.get("Category") or "").lower()
        if "malicious" in cat:
            engine.add("LOLDrivers", row["FilePath"],
                       f"MALICIOUS DRIVER (LOLDrivers): {row['FileName']} [{lol_hit['MatchedBy']} match]",
                       SEV_HIGH, "cheat", lol_meta)
        elif lol_hit["MatchedBy"] == "SHA256":
            engine.add("LOLDrivers", row["FilePath"],
                       f"VULNERABLE DRIVER - hash confirmed (BYOVD risk): {row['FileName']}",
                       SEV_HIGH, "cheat", lol_meta)
        else:
            engine.add("LOLDrivers", row["FilePath"],
                       f"VULNERABLE DRIVER - filename match (BYOVD risk): {row['FileName']}",
                       SEV_MEDIUM, "dual-use", lol_meta)


# ---------------------------------------------------------------------------
# Scan-Downloads
# ---------------------------------------------------------------------------
def scan_downloads(engine: Engine) -> None:
    print("  [*] Downloads folder...")
    dl = os.path.join(_user_profile(), "Downloads")
    if not os.path.isdir(dl):
        return
    for full, st in _enumerate_files(dl):
        zone = _read_zone_identifier(full)
        meta = {
            "FileName": os.path.basename(full),
            "SizeBytes": st.st_size,
            "Created": _iso_from_ctime(st),
            "LastWrite": _iso_from_mtime(st),
            "DownloadedFrom": zone.get("HostUrl", "") if zone else "(no source)",
        }
        suffix = f" - from: {zone['HostUrl']}" if zone and zone.get("HostUrl") else ""
        score_and_add(engine, "Downloads", full, f"{os.path.basename(full)}{suffix}", "", meta)


# ---------------------------------------------------------------------------
# Scan-Services-Trace (registry pass; runtime-state goes through get_service_snapshot)
# ---------------------------------------------------------------------------
_SVC_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services"


def scan_services_trace(engine: Engine) -> None:
    print("  [*] Services (keyword pass)...")
    if not key_exists(_SVC_KEY):
        engine.add("Services", _SVC_KEY, "Access denied", SEV_WARN, "other")
        return
    try:
        names = list(iter_subkeys(_SVC_KEY))
    except OSError:
        engine.add("Services", _SVC_KEY, "Access denied", SEV_WARN, "other")
        return
    for svc in names:
        path = _SVC_KEY + "\\" + svc
        props = read_all_values(path)
        meta = {
            "ServiceName": svc,
            "DisplayName": props.get("DisplayName", ""),
            "ImagePath": props.get("ImagePath", ""),
        }
        blob = f"{svc} | {meta['DisplayName']} | {meta['ImagePath']}"
        score_and_add(engine, "Services", svc, blob, "", meta)


# ---------------------------------------------------------------------------
# Scan-DMABuildArtifacts
# ---------------------------------------------------------------------------
_DMA_ROOTS = ("Documents", "Desktop", "Downloads", "source", "Projects")


def scan_dma_build_artifacts(engine: Engine) -> None:
    print("  [*] DMA build artifacts...")
    for sub in _DMA_ROOTS:
        root = os.path.join(_user_profile(), sub)
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in _safe_walk(root):
            for name in filenames:
                if name.lower().endswith("_top.bin"):
                    full = os.path.join(dirpath, name)
                    st = _file_stat(full)
                    engine.add("DMA", full, f"pcileech firmware build output: {name}",
                               SEV_HIGH, "cheat",
                               {"FileName": name, "FullPath": full,
                                "Created": _iso_from_ctime(st)})
            for d in dirnames:
                if "pcileech" in d.lower():
                    full = os.path.join(dirpath, d)
                    st = _file_stat(full)
                    engine.add("DMA", full, f"pcileech directory: {d}",
                               SEV_HIGH, "cheat",
                               {"Directory": full, "Created": _iso_from_ctime(st)})


# ---------------------------------------------------------------------------
# Scan-ApplicationData
# ---------------------------------------------------------------------------
def scan_application_data(engine: Engine) -> None:
    print("  [*] Application data dirs...")
    roots = [_appdata(), _localappdata(), os.path.join(_user_profile(), "Documents")]
    roots = [r for r in roots if r and os.path.isdir(r)]
    for root in roots:
        for app in APPDATA_PATTERNS:
            pattern = app["pattern"]
            label = app["label"]
            try:
                entries = os.listdir(root)
            except OSError:
                continue
            for entry in entries:
                if not fnmatch.fnmatch(entry, pattern):
                    continue
                full = os.path.join(root, entry)
                if not os.path.isdir(full):
                    continue
                files = _enumerate_files(full)
                if not files:
                    engine.add("AppData", full, f"{label} data dir (empty)",
                               SEV_MEDIUM, "input",
                               {"Label": label, "Directory": full, "FileCount": 0})
                    continue
                mtimes = [s.st_mtime for _p, s in files]
                oldest = datetime.fromtimestamp(min(mtimes))
                newest = datetime.fromtimestamp(max(mtimes))
                span_days = (newest - oldest).days
                distinct_days = len({datetime.fromtimestamp(m).date() for m in mtimes})
                engine.add("AppData", full,
                           f"{label} - {len(files)} files, {distinct_days} distinct days",
                           SEV_HIGH, "input",
                           {
                               "Label": label, "Directory": full,
                               "FileCount": len(files),
                               "DistinctActivityDays": distinct_days,
                               "ActivitySpanDays": span_days,
                               "OldestWrite": oldest.strftime("%Y-%m-%dT%H:%M:%S"),
                               "NewestWrite": newest.strftime("%Y-%m-%dT%H:%M:%S"),
                           })


# ---------------------------------------------------------------------------
# Scan-ShimCache
# ---------------------------------------------------------------------------
_SHIMCACHE_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"


def scan_shimcache(engine: Engine) -> None:
    print("  [*] ShimCache...")
    if not key_exists(_SHIMCACHE_KEY):
        engine.add("ShimCache", _SHIMCACHE_KEY, "Not present or admin needed", SEV_WARN, "other")
        return
    blob = read_value(_SHIMCACHE_KEY, "AppCompatCache")
    if not blob:
        return
    size = len(blob) if isinstance(blob, (bytes, bytearray)) else 0
    engine.add("ShimCache", _SHIMCACHE_KEY, "AppCompatCache blob present",
               SEV_INFO, "other",
               {"BlobSizeBytes": size,
                "Note": "Binary format. Parse offline with AppCompatCacheParser for full executable history."})


# ---------------------------------------------------------------------------
# Scan-UserScriptContents
# ---------------------------------------------------------------------------
_USER_SCRIPT_EXTS = (".bat", ".cmd", ".ps1", ".vbs", ".wsf", ".psm1", ".lua", ".ahk")
_USER_SCRIPT_EXCLUDE = {
    "forensic-scan.ps1", "console-rig-audit.ps1",
    "generate-visual-companion.ps1", "forensic-common.ps1",
    "generate-visual-companion-console.ps1",
}


def _user_script_roots() -> list[str]:
    base = [
        os.path.join(_user_profile(), "Desktop"),
        os.path.join(_user_profile(), "Documents"),
        os.path.join(_user_profile(), "Downloads"),
    ]
    for extra in ("source", "Projects", "Scripts", "Tools", "Cheats", "Game", "Games", "bin"):
        p = os.path.join(_user_profile(), extra)
        if os.path.isdir(p):
            base.append(p)
    return [r for r in base if os.path.isdir(r)]


def scan_user_script_contents(engine: Engine) -> None:
    print("  [*] User-folder script contents (reads .bat / .cmd / .ps1 / .lua / .ahk)...")
    roots = _user_script_roots()
    files: list[tuple[str, os.stat_result]] = []
    for root in roots:
        for full, st in _enumerate_files(root, ext_lower=_USER_SCRIPT_EXTS, max_size_mb=10):
            name_lc = os.path.basename(full).lower()
            if name_lc in _USER_SCRIPT_EXCLUDE:
                continue
            files.append((full, st))

    cap = 2000
    if len(files) > cap:
        engine.add("UserScripts", "(scan)",
                   f"Found {len(files)} scripts in user folders; scanning first {cap} by modification time",
                   SEV_WARN, "other",
                   {"Found": len(files), "Scanned": cap})
        files.sort(key=lambda x: x[1].st_mtime, reverse=True)
        files = files[:cap]

    user_profile = _user_profile()
    for full, st in files:
        try:
            with open(full, "rb") as fh:
                data = fh.read(min(st.st_size, 204800))
        except OSError:
            continue
        content = ""
        try:
            content = data.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            content = data.decode("ascii", errors="replace")
        if not content.strip():
            continue
        rel = full
        if user_profile and full.lower().startswith(user_profile.lower()):
            rel = "~" + full[len(user_profile):]

        base_meta = {
            "FileName": os.path.basename(full),
            "FullPath": full,
            "SizeBytes": st.st_size,
            "LastWrite": _iso_from_mtime(st),
        }

        for patterns, kind, sev, label in (
            (engine.keywords_high_cheats, "cheat", SEV_HIGH, "cheat-brand in script"),
            (engine.keywords_high_input, "input", SEV_HIGH, "input-device in script"),
            (engine.keywords_script_high, "cheat", SEV_HIGH, "high-risk command in script"),
            (engine.keywords_mouse_macro, "cheat", SEV_HIGH, "mouse-macro / anti-recoil script"),
            (engine.keywords_medium, "dual-use", SEV_MEDIUM, "dual-use in script"),
        ):
            hit = match_keyword(content, patterns)
            if hit:
                meta = dict(base_meta)
                meta["Pattern"] = hit
                meta["MatchKind"] = label
                engine.add("UserScripts", full,
                           f"[{hit}] {rel} - {label}",
                           sev, kind, meta)
                break


# ---------------------------------------------------------------------------
# Scan-ObscuredFileNames
# ---------------------------------------------------------------------------
_OBSCURED_EXTS = (".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".lua", ".ahk", ".sys", ".bin")
_SHORT_NAME_ALLOW = {"go", "vc", "7z", "c", "x"}


def scan_obscured_filenames(engine: Engine) -> None:
    print("  [*] Obscured filenames (hex / numeric-only .exe / .dll / .lua in user folders)...")
    roots = _user_script_roots()
    for root in roots:
        for full, st in _enumerate_files(root, ext_lower=_OBSCURED_EXTS, max_size_mb=100):
            name, ext = os.path.splitext(os.path.basename(full))
            reason = ""
            if re.fullmatch(r"0x[0-9a-fA-F]+", name):
                reason = f"0x-prefix hex name ({name}{ext})"
            elif re.fullmatch(r"[0-9a-fA-F]{8,}", name) and re.search(r"[a-fA-F]", name):
                reason = f"raw hex name ({name}{ext})"
            elif re.fullmatch(r"\d{4,}", name):
                reason = f"pure-numeric name ({name}{ext})"
            elif re.fullmatch(r"[a-zA-Z0-9]{1,2}", name) and name.lower() not in _SHORT_NAME_ALLOW:
                reason = f"ultra-short obscured name ({name}{ext})"
            if reason:
                engine.add("ObscuredNames", full,
                           f"Obscured filename: {reason}",
                           SEV_MEDIUM, "dual-use",
                           {
                               "FileName": os.path.basename(full),
                               "FullPath": full,
                               "Pattern": reason,
                               "SizeBytes": st.st_size,
                               "LastWrite": _iso_from_mtime(st),
                           })


# ---------------------------------------------------------------------------
# Scan-ProcessModules
# ---------------------------------------------------------------------------
def _enumerate_process_modules() -> list[dict[str, Any]]:
    """Shell out to PowerShell to get (Name, Id, Path, Modules.Path, Modules.ModuleName)
    for each process. Returns one dict per (process, module) pair.
    """
    cmd = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-Command",
        # Limit to 600 modules per process to mirror the PS cap.
        "Get-Process | ForEach-Object { "
        "  $proc = $_; "
        "  try { "
        "    $mods = $proc.Modules | Select-Object -First 600; "
        "    foreach ($m in $mods) { "
        "      [pscustomobject]@{ "
        "        ProcessName = $proc.Name; "
        "        ProcessId = $proc.Id; "
        "        ProcessPath = $proc.Path; "
        "        ModuleName = $m.ModuleName; "
        "        ModulePath = $m.FileName "
        "      } "
        "    } "
        "  } catch {} "
        "} | ConvertTo-Csv -NoTypeInformation",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=240, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    if not result.stdout:
        return []
    return list(csv.DictReader(io.StringIO(result.stdout)))


def scan_process_modules(engine: Engine) -> None:
    print("  [*] Process modules (DLLs loaded into running processes)...")
    rows = _enumerate_process_modules()
    if not rows:
        return
    total = 0
    for row in rows:
        proc_name = row.get("ProcessName", "")
        proc_id = row.get("ProcessId", "")
        proc_path = row.get("ProcessPath", "") or ""
        mod_name = row.get("ModuleName", "") or ""
        mod_path = row.get("ModulePath", "") or ""
        if proc_name in ("Idle", "System", "Registry", "Memory Compression"):
            continue
        if not mod_path:
            continue
        if mod_path == proc_path:
            continue
        total += 1
        hit_c = match_keyword(f"{mod_name} {mod_path}", engine.keywords_high_cheats)
        if hit_c:
            engine.add("ProcessModules", f"{proc_name} (PID {proc_id})",
                       f"[{hit_c}] {mod_name} loaded into {proc_name}",
                       SEV_HIGH, "cheat",
                       {"Pattern": hit_c, "ProcessName": proc_name, "ProcessId": proc_id,
                        "ModuleName": mod_name, "ModulePath": mod_path})
            continue
        hit_i = match_keyword(f"{mod_name} {mod_path}", engine.keywords_high_input)
        if hit_i:
            engine.add("ProcessModules", f"{proc_name} (PID {proc_id})",
                       f"[{hit_i}] {mod_name} loaded into {proc_name}",
                       SEV_HIGH, "input",
                       {"Pattern": hit_i, "ProcessName": proc_name, "ProcessId": proc_id,
                        "ModuleName": mod_name, "ModulePath": mod_path})
            continue
        bucket = classify_path_risk(mod_path)
        if bucket == "user-writable":
            if not match_allowlist(f"{mod_path} {mod_name}"):
                engine.add("ProcessModules", f"{proc_name} (PID {proc_id})",
                           f"DLL loaded from user-writable path: {mod_name} loaded into {proc_name}",
                           SEV_MEDIUM, "dual-use",
                           {
                               "ProcessName": proc_name, "ProcessId": proc_id,
                               "ModuleName": mod_name, "ModulePath": mod_path,
                               "Reason": "DLL loaded from user-writable location, not on known-good vendor allowlist - common pattern for injected cheat DLLs",
                           })
    engine.add("ProcessModules", "(scan)",
               f"Scanned {total} DLL modules across all running processes",
               SEV_INFO, "other", {"ModulesScanned": total})


# ---------------------------------------------------------------------------
# Scan-KnownHashes
# ---------------------------------------------------------------------------
def scan_known_hashes(engine: Engine) -> None:
    print("  [*] Known cheat hashes (SHA256 of user-folder executables)...")
    if not KNOWN_CHEAT_HASHES:
        return
    lookup = {h["sha256"].lower(): h for h in KNOWN_CHEAT_HASHES}

    roots = _user_script_roots()
    for extra in (_appdata(), _localappdata()):
        if extra and os.path.isdir(extra):
            roots.append(extra)

    candidates: list[tuple[str, os.stat_result]] = []
    for root in roots:
        for full, st in _enumerate_files(root, ext_lower=(".exe", ".dll"), max_size_mb=100):
            if st.st_size > 0:
                candidates.append((full, st))

    cap = 500
    if len(candidates) > cap:
        candidates.sort(key=lambda x: x[1].st_mtime, reverse=True)
        engine.add("KnownHashes", "(scan)",
                   f"Found {len(candidates)} executables in user folders; hashing newest {cap}",
                   SEV_INFO, "other", {"Found": len(candidates), "Hashed": cap})
        candidates = candidates[:cap]

    hashed = 0
    for full, st in candidates:
        h = _sha256_file(full)
        if not h:
            continue
        hashed += 1
        if h in lookup:
            info = lookup[h]
            engine.add("KnownHashes", full,
                       f"[{info['name']}] hash match - confirmed cheat sample",
                       SEV_HIGH, "cheat",
                       {
                           "Pattern": info["name"], "SHA256": h,
                           "FileName": os.path.basename(full), "FullPath": full,
                           "SizeBytes": st.st_size,
                           "LastWrite": _iso_from_mtime(st),
                           "KnownSampleOf": info["name"],
                           "HashSource": info["source"],
                       })

    engine.add("KnownHashes", "(scan)",
               f"Hashed {hashed} executables, checked against {len(KNOWN_CHEAT_HASHES)} known-bad SHA256 sample(s)",
               SEV_INFO, "other",
               {"Hashed": hashed, "DatabaseSize": len(KNOWN_CHEAT_HASHES)})


# ---------------------------------------------------------------------------
# Scan-LuaScripts
# ---------------------------------------------------------------------------
def scan_lua_scripts(engine: Engine) -> None:
    print("  [*] Lua scripts (name + path keyword match)...")
    roots = [
        os.path.join(_user_profile(), "Documents"),
        os.path.join(_user_profile(), "Desktop"),
        os.path.join(_user_profile(), "Downloads"),
        os.path.join(_user_profile(), "AppData", "Roaming"),
        os.path.join(_user_profile(), "AppData", "Local"),
        os.path.join(_user_profile(), "source"),
        os.path.join(_user_profile(), "Projects"),
        os.path.join(_user_profile(), "Games"),
    ]
    roots = [r for r in roots if os.path.isdir(r)]

    lua_keywords_lc = [k.lower() for k in LUA_CHEAT_KEYWORDS]

    for root in roots:
        for full, st in _enumerate_files(root, ext_lower=(".lua",)):
            zone = _read_zone_identifier(full)
            meta = {
                "FileName": os.path.basename(full),
                "FullPath": full,
                "SizeBytes": st.st_size,
                "Created": _iso_from_ctime(st),
                "LastWrite": _iso_from_mtime(st),
                "DownloadedFrom": zone.get("HostUrl", "") if zone else "(no source)",
            }
            lc = f"{os.path.basename(full)} {full}".lower()

            hit = match_keyword(lc, lua_keywords_lc)
            if hit:
                meta["Pattern"] = hit
                engine.add("LuaScript", full, f"[{hit}] {os.path.basename(full)}",
                           SEV_HIGH, "cheat", meta)
                continue
            hit_c = match_keyword(lc, engine.keywords_high_cheats)
            if hit_c:
                meta["Pattern"] = hit_c
                engine.add("LuaScript", full, f"[{hit_c}] {os.path.basename(full)}",
                           SEV_HIGH, "cheat", meta)
                continue
            hit_i = match_keyword(lc, engine.keywords_high_input)
            if hit_i:
                meta["Pattern"] = hit_i
                engine.add("LuaScript", full, f"[{hit_i}] {os.path.basename(full)}",
                           SEV_HIGH, "input", meta)
                continue
            if not match_allowlist(full):
                engine.add("LuaScript", full,
                           f"Unrecognized Lua script (no cheat indicator): {os.path.basename(full)}",
                           SEV_INFO, "other", meta)


# ---------------------------------------------------------------------------
# Scan-DLLInjectionTimestamps — uses wevtutil for event logs
# ---------------------------------------------------------------------------
def _query_event_log_xml(log: str, *, max_events: int = 5000, xpath: str | None = None) -> list[str]:
    """Query an event log via wevtutil; return one XML-event-string per event.
    Returns empty list if log isn't accessible (typical for non-admin or no Sysmon).
    """
    cmd = ["wevtutil.exe", "qe", log, f"/c:{max_events}", "/f:xml", "/rd:true"]
    if xpath:
        cmd.append(f"/q:{xpath}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    # wevtutil emits one <Event>…</Event> per line (CRLF-joined elements within).
    out = result.stdout or ""
    if not out.strip():
        return []
    # Robust split on Event close tag.
    parts = re.split(r"</Event>\s*", out)
    return [p + "</Event>" for p in parts if p.strip()]


_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _parse_event_data(xml_str: str) -> tuple[dict[str, str], str]:
    """Return ({EventData Name → text}, TimeCreated SystemTime)."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {}, ""
    data: dict[str, str] = {}
    time_created = ""
    for elem in root.iter():
        tag = elem.tag.split("}", 1)[-1]
        if tag == "TimeCreated":
            time_created = elem.attrib.get("SystemTime", "")
        if tag == "Data":
            name = elem.attrib.get("Name", "")
            text = (elem.text or "").strip()
            if name:
                data[name] = text
    return data, time_created


def _trim_systemtime(ts: str) -> str:
    if not ts:
        return ""
    return ts.replace("T", "T").split(".", 1)[0]


def scan_dll_injection_timestamps(engine: Engine) -> None:
    print("  [*] DLL injection timestamps (Sysmon + Event Log + Prefetch)...")
    injector_pat = "|".join(re.escape(k) for k in DLL_INJECTOR_NAMES)
    injector_re = re.compile(injector_pat, re.IGNORECASE)

    found: list[dict[str, str]] = []

    # Source 1: Sysmon EID 7
    sysmon_events = _query_event_log_xml(
        "Microsoft-Windows-Sysmon/Operational",
        max_events=5000,
        xpath="*[System[EventID=7]]",
    )
    if not sysmon_events:
        engine.add("DLLInject", "Sysmon",
                   "Sysmon not available (not installed or access denied) - install for full DLL-load telemetry",
                   SEV_WARN, "other")
    for xml in sysmon_events:
        data, ts = _parse_event_data(xml)
        img = data.get("ImageLoaded", "")
        if not img:
            continue
        name = os.path.basename(img).lower()
        if not injector_re.search(name):
            continue
        found.append({
            "Source": "Sysmon EID 7",
            "Timestamp": _trim_systemtime(ts),
            "ImageLoaded": img,
            "TargetProc": data.get("Image", ""),
            "ProcessId": data.get("ProcessId", ""),
            "Hashes": data.get("Hashes", ""),
            "Signed": data.get("Signed", ""),
            "Signature": data.get("Signature", ""),
        })

    # Source 2: Security EID 4688
    for xml in _query_event_log_xml("Security", max_events=10000, xpath="*[System[EventID=4688]]"):
        data, ts = _parse_event_data(xml)
        new_proc = data.get("NewProcessName", "")
        if not new_proc:
            continue
        name = os.path.basename(new_proc).lower()
        if not injector_re.search(name):
            continue
        found.append({
            "Source": "Security EID 4688",
            "Timestamp": _trim_systemtime(ts),
            "ImageLoaded": new_proc,
            "TargetProc": data.get("ParentProcessName", ""),
            "ProcessId": data.get("NewProcessId", ""),
            "Hashes": "",
            "Signed": "",
            "Signature": "",
        })

    # Source 3: Application log (message text match — uses PowerShell since
    # wevtutil XML doesn't include the rendered message body without a
    # publisher manifest. Cheap fallback only.)
    cmd_app = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-Command",
        "Get-WinEvent -LogName Application -MaxEvents 5000 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Message -match '" + injector_pat.replace("'", "''") + "' } | "
        "Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation",
    ]
    try:
        result = subprocess.run(cmd_app, capture_output=True, text=True, timeout=120, check=False)
        if result.stdout:
            for row in csv.DictReader(io.StringIO(result.stdout)):
                ts = (row.get("TimeCreated") or "").strip()
                msg = (row.get("Message") or "").strip()
                if not msg:
                    continue
                snippet = msg[:200]
                found.append({
                    "Source": "Application EventLog",
                    "Timestamp": ts,
                    "ImageLoaded": f"EventLog message match: {snippet}",
                    "TargetProc": "",
                    "ProcessId": "",
                    "Hashes": "", "Signed": "", "Signature": "",
                })
    except (OSError, subprocess.SubprocessError):
        pass

    # Source 4: Prefetch cross-reference
    pf = os.path.join(_system_root(), "Prefetch")
    if os.path.isdir(pf):
        try:
            for name in os.listdir(pf):
                if not name.lower().endswith(".pf"):
                    continue
                base = os.path.splitext(name)[0].lower()
                if not injector_re.search(base):
                    continue
                full = os.path.join(pf, name)
                st = _file_stat(full)
                found.append({
                    "Source": "Prefetch",
                    "Timestamp": _iso_from_mtime(st),
                    "ImageLoaded": full,
                    "TargetProc": "", "ProcessId": "",
                    "Hashes": "", "Signed": "",
                    "Signature": f"FirstSeen: {_iso_from_ctime(st)}",
                })
        except OSError:
            pass

    if not found:
        engine.add("DLLInject", "EventLog",
                   "No DLL injector events found in available event sources",
                   SEV_INFO, "other",
                   {"Note": "Checked: Sysmon EID 7, Security EID 4688, Application log, Prefetch"})
        return

    # Dedupe on (ImageLoaded, Timestamp)
    seen: dict[str, dict[str, str]] = {}
    for ev in found:
        key = f"{ev['ImageLoaded']}|{ev['Timestamp']}"
        if key not in seen:
            seen[key] = ev

    for ev in sorted(seen.values(), key=lambda e: e["Timestamp"], reverse=True):
        meta = {
            "Source": ev["Source"],
            "Timestamp": ev["Timestamp"],
            "ImageLoaded": ev["ImageLoaded"],
            "TargetProcess": ev["TargetProc"],
            "ProcessId": ev["ProcessId"],
        }
        if ev["Hashes"]:
            meta["Hashes"] = ev["Hashes"]
        if ev["Signed"]:
            meta["Signed"] = ev["Signed"]
        if ev["Signature"]:
            meta["Signature"] = ev["Signature"]
        raw = ev["ImageLoaded"]
        if "/" in raw or "\\" in raw:
            parts = re.split(r"[\\/]", raw)
            img_name = parts[-1] if parts else raw
        elif len(raw) > 80:
            img_name = raw[:80] + "..."
        else:
            img_name = raw
        engine.add("DLLInject", ev["Source"],
                   f"Injector activity: {img_name} @ {ev['Timestamp']}",
                   SEV_MEDIUM, "dual-use", meta)


# ---------------------------------------------------------------------------
# Scan-NetworkAttackTools
# ---------------------------------------------------------------------------
def _score_network_blob(blob: str) -> dict[str, str] | None:
    if not blob or not blob.strip():
        return None
    lc = blob.lower()
    for kw in NETWORK_ATTACK_HIGH:
        if kw.lower() in lc:
            return {"sev": SEV_HIGH, "kind": "cheat", "pat": kw}
    for kw in NETWORK_ATTACK_MEDIUM:
        if kw.lower() in lc:
            return {"sev": SEV_MEDIUM, "kind": "dual-use", "pat": kw}
    return None


def scan_network_attack_tools(engine: Engine) -> None:
    print("  [*] Network attack / DDoS tools...")

    # Source 1: Prefetch
    pf = os.path.join(_system_root(), "Prefetch")
    if os.path.isdir(pf):
        try:
            for name in os.listdir(pf):
                if not name.lower().endswith(".pf"):
                    continue
                base = os.path.splitext(name)[0]
                s = _score_network_blob(base)
                if not s:
                    continue
                full = os.path.join(pf, name)
                st = _file_stat(full)
                engine.add("NetAttack", full,
                           f"[{s['pat']}] DDoS/attack tool in Prefetch: {base}",
                           s["sev"], s["kind"],
                           {
                               "Pattern": s["pat"],
                               "PrefetchFile": name,
                               "FirstSeen": _iso_from_ctime(st),
                               "LastRun": _iso_from_mtime(st),
                           })
        except OSError:
            engine.add("NetAttack", pf, "Prefetch access denied (run as admin)", SEV_WARN, "other")

    # Source 2: BAM
    for base in (
        r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        r"HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings",
    ):
        if not key_exists(base):
            continue
        try:
            sids = list(iter_subkeys(base))
        except OSError:
            continue
        for sid in sids:
            sid_path = base + "\\" + sid
            for vn, data, _typ in iter_values(sid_path):
                if vn in ("SequenceNumber", "Version"):
                    continue
                s = _score_network_blob(vn)
                if not s:
                    continue
                last_run = convert_filetime_bytes(data if isinstance(data, (bytes, bytearray)) else None)
                engine.add("NetAttack", sid,
                           f"[{s['pat']}] DDoS/attack tool execution: {vn}",
                           s["sev"], s["kind"],
                           {
                               "Pattern": s["pat"],
                               "Executable": vn,
                               "LastExecution": iso(last_run),
                               "UserSID": sid,
                           })

    # Source 3: Installed
    for a in _iter_installed():
        s = _score_network_blob(f"{a.get('DisplayName','')} {a.get('Publisher','')}")
        if not s:
            continue
        engine.add("NetAttack", str(a.get("DisplayName", "")),
                   f"[{s['pat']}] DDoS/attack tool installed: {a.get('DisplayName','')}",
                   s["sev"], s["kind"],
                   {
                       "Pattern": s["pat"],
                       "Name": a.get("DisplayName", ""),
                       "Publisher": a.get("Publisher", ""),
                       "InstallDate": _normalize_install_date(a.get("InstallDate")),
                       "Version": a.get("DisplayVersion", ""),
                   })

    # Source 4: Downloads
    dl = os.path.join(_user_profile(), "Downloads")
    if os.path.isdir(dl):
        for full, st in _enumerate_files(dl):
            s = _score_network_blob(os.path.basename(full))
            if not s:
                continue
            zone = _read_zone_identifier(full)
            engine.add("NetAttack", full,
                       f"[{s['pat']}] DDoS/attack tool in Downloads: {os.path.basename(full)}",
                       s["sev"], s["kind"],
                       {
                           "Pattern": s["pat"],
                           "FileName": os.path.basename(full),
                           "SizeBytes": st.st_size,
                           "Created": _iso_from_ctime(st),
                           "LastWrite": _iso_from_mtime(st),
                           "DownloadedFrom": zone.get("HostUrl", "") if zone else "(no source)",
                       })

    # Source 5: MUICache
    if key_exists(_MUI_KEY):
        for name, data, _typ in iter_values(_MUI_KEY):
            if name.startswith("PS"):
                continue
            s = _score_network_blob(name)
            if not s:
                continue
            engine.add("NetAttack", "HKCU\\...\\MuiCache",
                       f"[{s['pat']}] DDoS/attack tool ever launched: {name}",
                       s["sev"], s["kind"],
                       {"Pattern": s["pat"], "Value": name, "Data": str(data) if data is not None else ""})

    # Source 6: Recent
    recent = os.path.join(_appdata(), "Microsoft", "Windows", "Recent")
    if os.path.isdir(recent):
        for full, st in _enumerate_files(recent):
            s = _score_network_blob(os.path.basename(full))
            if not s:
                continue
            target = _lnk_target(full) if full.lower().endswith(".lnk") else None
            engine.add("NetAttack", full,
                       f"[{s['pat']}] DDoS/attack tool in Recent files: {os.path.basename(full)}",
                       s["sev"], s["kind"],
                       {"Pattern": s["pat"], "Target": target or "",
                        "LastWrite": _iso_from_mtime(st)})


# ---------------------------------------------------------------------------
# Scan-AIVisionArtifacts
# ---------------------------------------------------------------------------
_ARDUINO_HID_RE = re.compile(
    r"(Mouse\.move|HID-Project|MouseAbsolute|Keyboard\.press.*Mouse)",
    re.IGNORECASE,
)


def _read_text(path: str, *, max_bytes: int = 524288) -> str:
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def scan_ai_vision_artifacts(engine: Engine) -> None:
    print("  [*] AI-vision aimbot artifacts (ONNX / YOLO / external HID)...")
    roots = [
        os.path.join(_user_profile(), "Documents"),
        os.path.join(_user_profile(), "Desktop"),
        os.path.join(_user_profile(), "Downloads"),
        os.path.join(_user_profile(), "source"),
        os.path.join(_user_profile(), "Projects"),
        os.path.join(_user_profile(), "AppData", "Local"),
        os.path.join(_user_profile(), "AppData", "Roaming"),
    ]
    roots = [r for r in roots if os.path.isdir(r)]

    onnx_files: list[tuple[str, os.stat_result]] = []
    brand_hits: list[tuple[str, os.stat_result]] = []
    arduino_hits: list[tuple[str, os.stat_result]] = []
    py_dep_hits: list[tuple[str, int]] = []

    for root in roots:
        onnx_files.extend(_enumerate_files(root, ext_lower=(".onnx",), cap=200))
        # Brand-name executables / py scripts.
        for full, st in _enumerate_files(root, ext_lower=(".exe", ".py"), max_size_mb=200):
            hit = match_keyword(f"{os.path.basename(full)} {os.path.dirname(full)}",
                                VISION_AIMBOT_AI_PC)
            if hit:
                meta = {
                    "Pattern": hit, "FileName": os.path.basename(full),
                    "FullPath": full, "SizeBytes": st.st_size,
                    "Created": _iso_from_ctime(st), "LastWrite": _iso_from_mtime(st),
                }
                engine.add("AIVision", full,
                           f"[{hit}] AI-vision aimbot executable: {os.path.basename(full)}",
                           SEV_HIGH, "cheat", meta)
                brand_hits.append((full, st))
        # Arduino sketches.
        for full, st in _enumerate_files(root, ext_lower=(".ino",), cap=100):
            content = _read_text(full)
            if _ARDUINO_HID_RE.search(content):
                arduino_hits.append((full, st))
        # Python ML dependency markers.
        for full, _st in _enumerate_files(root, ext_lower=("requirements.txt", "pyproject.toml", ".cfg"), cap=200):
            base = os.path.basename(full).lower()
            if base not in ("requirements.txt", "pyproject.toml") and not base.endswith(".cfg"):
                continue
            content = _read_text(full)
            score = 0
            if re.search(r"ultralytics", content, re.IGNORECASE):
                score += 1
            if re.search(r"\btorch\b", content, re.IGNORECASE):
                score += 1
            if re.search(r"\bmss\b", content, re.IGNORECASE):
                score += 1
            if re.search(r"pyautogui|pydirectinput|pynput", content, re.IGNORECASE):
                score += 1
            if re.search(r"opencv-python|cv2", content, re.IGNORECASE):
                score += 1
            if re.search(r"onnxruntime", content, re.IGNORECASE):
                score += 1
            if score >= 3:
                py_dep_hits.append((full, score))

    for onnx_path, st in onnx_files:
        onnx_dir = os.path.dirname(onnx_path)
        meta = {
            "FileName": os.path.basename(onnx_path),
            "FullPath": onnx_path,
            "SizeBytes": st.st_size,
            "Created": _iso_from_ctime(st),
            "LastWrite": _iso_from_mtime(st),
        }
        # Co-located brand executable?
        colocated_brand = next(
            (b for b, _ in brand_hits
             if b.startswith(onnx_dir) or onnx_path.startswith(os.path.dirname(b))),
            None,
        )
        if colocated_brand:
            meta["CoLocated"] = colocated_brand
            engine.add("AIVision", onnx_path,
                       f"ONNX model co-located with AI-aimbot executable: {os.path.basename(onnx_path)}",
                       SEV_HIGH, "cheat", meta)
            continue
        colocated_arduino = next(
            (a for a, _ in arduino_hits
             if a.startswith(onnx_dir) or onnx_path.startswith(os.path.dirname(a))),
            None,
        )
        if colocated_arduino:
            meta["CoLocatedArduino"] = colocated_arduino
            engine.add("AIVision", onnx_path,
                       f"ONNX model co-located with Arduino HID sketch: {os.path.basename(onnx_path)}",
                       SEV_HIGH, "cheat", meta)
            continue
        colocated_deps = next(
            ((p, sc) for p, sc in py_dep_hits
             if p.startswith(onnx_dir) or onnx_path.startswith(os.path.dirname(p))),
            None,
        )
        if colocated_deps:
            meta["CoLocatedDeps"] = colocated_deps[0]
            meta["DepsScore"] = colocated_deps[1]
            engine.add("AIVision", onnx_path,
                       f"ONNX model + Python ML deps (ultralytics/torch/mss/pyautogui) at {onnx_dir}",
                       SEV_MEDIUM, "dual-use", meta)
            continue
        engine.add("AIVision", onnx_path,
                   f"ONNX model present (no aimbot constellation): {os.path.basename(onnx_path)}",
                   SEV_INFO, "other", meta)

    for ino_path, st in arduino_hits:
        ino_dir = os.path.dirname(ino_path)
        nearby_onnx = next(
            (o for o, _ in onnx_files
             if o.startswith(ino_dir) or ino_path.startswith(os.path.dirname(o))),
            None,
        )
        if not nearby_onnx:
            engine.add("AIVision", ino_path,
                       f"Arduino HID sketch (no ONNX constellation): {os.path.basename(ino_path)}",
                       SEV_INFO, "other",
                       {"FileName": os.path.basename(ino_path), "FullPath": ino_path,
                        "LastWrite": _iso_from_mtime(st)})


# ---------------------------------------------------------------------------
# invoke_all_scans
# ---------------------------------------------------------------------------
def invoke_all_scans(engine: Engine) -> None:
    """Run the full standard scan sequence. Mirrors Invoke-AllScans."""
    scan_prefetch(engine)
    scan_bam(engine)
    scan_installed_software(engine)
    scan_recent_files(engine)
    scan_muicache(engine)
    scan_usb_history(engine)
    scan_driver_signing(engine)
    scan_drivers(engine)
    scan_downloads(engine)
    scan_services_trace(engine)
    scan_dma_build_artifacts(engine)
    scan_application_data(engine)
    scan_shimcache(engine)
    scan_user_script_contents(engine)
    scan_obscured_filenames(engine)
    scan_process_modules(engine)
    scan_known_hashes(engine)
    scan_lua_scripts(engine)
    scan_dll_injection_timestamps(engine)
    scan_network_attack_tools(engine)
    scan_ai_vision_artifacts(engine)
