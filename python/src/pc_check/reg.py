r"""Thin wrappers around `winreg` so the rest of the codebase doesn't have
to deal with HKEY constants, missing-key OSError, or path-string parsing.

Mirrors how forensic-common.ps1 uses HKLM:\... / HKCU:\... PSDrive paths.
On non-Windows systems (CI lint runs on Linux), winreg is unavailable;
the functions degrade to no-ops so import doesn't blow up.
"""
from __future__ import annotations

from typing import Any, Iterator

try:  # noqa: SIM105
    import winreg  # type: ignore[import-not-found]
    _WINREG_AVAILABLE = True
except ImportError:  # pragma: no cover - non-Windows lint path
    winreg = None  # type: ignore[assignment]
    _WINREG_AVAILABLE = False


HKLM = "HKLM"
HKCU = "HKCU"
HKCR = "HKCR"
HKU = "HKU"

_PREFIX_MAP = {
    "HKLM": "HKLM",
    "HKCU": "HKCU",
    "HKCR": "HKCR",
    "HKU": "HKU",
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKEY_CURRENT_USER": "HKCU",
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKEY_USERS": "HKU",
}


def _root_const(prefix: str):
    if not _WINREG_AVAILABLE:
        return None
    return {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
    }[prefix]


def parse_key(path: str) -> tuple[Any, str] | None:
    """Convert "HKLM\\Foo\\Bar" → (HKEY_LOCAL_MACHINE, "Foo\\Bar"). Returns
    None on non-Windows.
    """
    if not _WINREG_AVAILABLE:
        return None
    head, _, tail = path.replace("/", "\\").partition("\\")
    prefix = _PREFIX_MAP.get(head.upper().replace("HKEY:", "HKEY_"))
    if not prefix:
        prefix = _PREFIX_MAP.get(head.upper())
    if not prefix:
        return None
    return _root_const(prefix), tail


def open_key(path: str, *, write: bool = False) -> Any:
    """Open a key by full path; raises OSError if missing or access-denied."""
    if not _WINREG_AVAILABLE:
        raise OSError("winreg not available on this platform")
    parsed = parse_key(path)
    if not parsed:
        raise OSError(f"Could not parse registry path: {path}")
    root, sub = parsed
    access = winreg.KEY_READ
    # Try 64-bit view first on 64-bit Windows; fall through to default if not.
    try:
        return winreg.OpenKey(root, sub, 0, access | getattr(winreg, "KEY_WOW64_64KEY", 0))
    except OSError:
        return winreg.OpenKey(root, sub, 0, access)


def key_exists(path: str) -> bool:
    try:
        h = open_key(path)
    except OSError:
        return False
    h.Close()
    return True


def iter_subkeys(path: str) -> Iterator[str]:
    if not _WINREG_AVAILABLE:
        return
    try:
        h = open_key(path)
    except OSError:
        return
    try:
        i = 0
        while True:
            try:
                yield winreg.EnumKey(h, i)
            except OSError:
                break
            i += 1
    finally:
        h.Close()


def iter_values(path: str) -> Iterator[tuple[str, Any, int]]:
    """Yields (name, data, type) for every value under the key."""
    if not _WINREG_AVAILABLE:
        return
    try:
        h = open_key(path)
    except OSError:
        return
    try:
        i = 0
        while True:
            try:
                name, data, typ = winreg.EnumValue(h, i)
            except OSError:
                break
            yield name, data, typ
            i += 1
    finally:
        h.Close()


def read_value(path: str, name: str) -> Any:
    if not _WINREG_AVAILABLE:
        return None
    try:
        h = open_key(path)
    except OSError:
        return None
    try:
        try:
            value, _typ = winreg.QueryValueEx(h, name)
            return value
        except OSError:
            return None
    finally:
        h.Close()


def read_all_values(path: str) -> dict[str, Any]:
    return {name: data for name, data, _typ in iter_values(path)}
