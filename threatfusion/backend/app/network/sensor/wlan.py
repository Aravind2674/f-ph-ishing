"""
Wi-Fi scanning that works on any Windows language (revamp T2d)
==============================================================

The old scanner parsed ``netsh wlan show networks`` with English labels (``Signal``, ``Channel``) — on a Windows in another language it
found nothing and said nothing.  Two backends now share one result type:

``native``  The Windows **Native Wifi API** (``wlanapi.dll``, through ``ctypes``): ``WlanGetNetworkBssList`` for every BSSID (MAC, RSSI,
            link quality, centre frequency → channel) and ``WlanGetAvailableNetworkList`` for each SSID's authentication / cipher.  No text
            parsing at all, so no language dependence.  Used first.
``netsh``   ``netsh wlan show networks mode=bssid`` parsed by **structure and value shape**, never by label text: ``SSID <n> : name`` and
            ``BSSID <n> : <mac>`` (acronyms are not translated), a value that is ``NN %`` is the signal, the first plain integer after a
            BSSID line is the channel, and authentication / encryption are recognised by their (untranslated) technical values.  A value it
            cannot recognise is ``None`` — unknown, never guessed.  Fallback when the native API is unavailable.

The connected network (used to watch your own network automatically) is read from ``netsh wlan show interfaces`` by the same rules.

Failures are classified, not hidden (:class:`WifiUnavailable`): ``not_windows`` · ``no_wlan_service`` · ``no_interface`` ·
``access_denied`` (Windows 11 24H2 and later refuse Wi-Fi scans to desktop apps while **Location** is off) · ``failed`` (verbatim detail).
Each carries a one-line fix.  Nothing is invented: an empty list means "scanned, nothing visible".
"""

from __future__ import annotations

import logging
import platform
import re
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

LOCATION_FIX = ("Windows blocks Wi-Fi scans for apps without Location permission: Settings → Privacy & security → Location → turn on "
                "Location services and “Let desktop apps access your location”.")
_MAC = r"[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5}"
_MAC_RE = re.compile(rf"^{_MAC}$")


class WifiUnavailable(Exception):
    """Wi-Fi scanning cannot work right now; ``code`` is machine-readable, ``fix`` is one line a person can act on."""

    def __init__(self, code: str, message: str, fix: Optional[str] = None) -> None:
        super().__init__(message)
        self.code, self.message, self.fix = code, message, fix


@dataclass
class AccessPoint:
    ssid: str
    bssid: str                               # aa:bb:cc:dd:ee:ff — lower-case, colon-separated
    signal_percent: Optional[int] = None
    rssi_dbm: Optional[int] = None
    channel: Optional[int] = None
    band_ghz: Optional[float] = None
    security: Optional[str] = None           # "WPA2-PSK/CCMP", "Open/None", … ; None = unknown

    @property
    def oui(self) -> str:
        return oui_of(self.bssid)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["oui"] = self.oui
        return d


@dataclass
class WifiScan:
    aps: list[AccessPoint] = field(default_factory=list)
    connected_ssid: Optional[str] = None
    connected_bssid: Optional[str] = None
    backend: str = ""
    interface: Optional[str] = None


_CANON_AUTH = {
    "open": "Open", "shared": "WEP-Shared", "owe": "OWE", "802.1x": "802.1X-Enterprise",
    "wpa": "WPA-Enterprise", "wpa-enterprise": "WPA-Enterprise", "wpa-psk": "WPA-Personal", "wpa-personal": "WPA-Personal", "wpa-none": "WPA-None",
    "wpa2": "WPA2-Enterprise", "wpa2-enterprise": "WPA2-Enterprise", "rsna": "WPA2-Enterprise",
    "wpa2-psk": "WPA2-Personal", "wpa2-personal": "WPA2-Personal", "rsna-psk": "WPA2-Personal",
    "wpa3": "WPA3-Enterprise", "wpa3-enterprise": "WPA3-Enterprise", "wpa3-enterprise 192": "WPA3-Enterprise",
    "wpa3-sae": "WPA3-Personal", "wpa3-personal": "WPA3-Personal",
}


_CANON_CIPHER = {"none": "None", "ccmp": "CCMP", "tkip": "TKIP", "gcmp": "GCMP", "gcmp-256": "GCMP-256", "wep": "WEP", "wep40": "WEP-40",
                 "wep-40": "WEP-40", "wep104": "WEP-104", "wep-104": "WEP-104"}


def canonical_security(auth: Optional[str], cipher: Optional[str]) -> Optional[str]:
    """One spelling for an authentication / cipher pair, so ``WPA2-PSK`` (native API) and ``WPA2-Personal`` (netsh) are the same thing and
    switching backends can never look like a security change.  ``None`` when the authentication is not recognised (unknown, not guessed)."""
    if not auth:
        return None
    a = _CANON_AUTH.get(auth.strip().lower())
    if a is None:
        return None
    c = (cipher or "").strip()
    c = _CANON_CIPHER.get(c.lower(), c.upper())
    return f"{a}/{c}" if c else a


def normalize_bssid(text: Optional[str]) -> Optional[str]:
    """``AA-BB-CC-DD-EE-FF`` / ``aa:bb:cc:dd:ee:ff`` → ``aa:bb:cc:dd:ee:ff``; ``None`` if it is not a MAC address."""
    t = (text or "").strip()
    if not _MAC_RE.match(t):
        return None
    return t.replace("-", ":").lower()


def oui_of(bssid: str) -> str:
    """The vendor prefix (first three bytes) of a BSSID."""
    return ":".join(bssid.split(":")[:3])


def channel_from_khz(khz: int) -> tuple[Optional[int], Optional[float]]:
    """(channel, band in GHz) from a centre frequency in kHz."""
    mhz = khz / 1000.0
    if 2400 <= mhz <= 2500:
        return (14 if round(mhz) == 2484 else int(round((mhz - 2407) / 5))), 2.4
    if 5150 <= mhz < 5925:
        return int(round((mhz - 5000) / 5)), 5.0
    if 5925 <= mhz <= 7125:
        return int(round((mhz - 5950) / 5)), 6.0
    return None, None


# ── netsh, parsed by structure ───────────────────────────────────────────────
_SSID_LINE = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*?)\s*$")
_BSSID_LINE = re.compile(rf"^\s*\S*BSSID\s+\d+\s*:\s*({_MAC})\s*$")
_VALUE = re.compile(r"^\s*[^:]+?\s*:\s*(.+?)\s*$")
_PERCENT = re.compile(r"^(\d{1,3})\s*%$")
_INT = re.compile(r"^\d{1,3}$")
_AUTH = re.compile(r"^(WPA3(?:-(?:SAE|Enterprise|Personal)(?: 192)?)?|WPA2(?:-(?:Personal|Enterprise|PSK))?|WPA(?:-(?:Personal|Enterprise|PSK))?|OWE|Open|Shared|RSNA(?:-PSK)?|802\.1X)$", re.I)
_CIPHER = re.compile(r"^(CCMP|GCMP(?:-256)?|TKIP|WEP(?:-?(?:40|104))?|None)$", re.I)


def parse_netsh_networks(text: str) -> list[AccessPoint]:
    """Access points from ``netsh wlan show networks mode=bssid`` output, in any language (see the module docstring)."""
    aps: list[AccessPoint] = []
    ssid, auth, cipher = "", None, None
    current: Optional[dict[str, Any]] = None

    def flush() -> None:
        nonlocal current
        if current is not None:
            aps.append(AccessPoint(ssid=ssid, bssid=current["bssid"], signal_percent=current.get("signal"), channel=current.get("channel"),
                                   band_ghz=current.get("band"), security=canonical_security(auth, cipher)))
            current = None

    for line in text.splitlines():
        m = _SSID_LINE.match(line)
        if m:
            flush()
            ssid, auth, cipher = m.group(1), None, None
            continue
        m = _BSSID_LINE.match(line)
        if m:
            flush()
            current = {"bssid": normalize_bssid(m.group(1))}
            continue
        v = _VALUE.match(line)
        if not v:
            continue
        value = v.group(1).strip()
        if current is None:                                         # still in the SSID header block: authentication / encryption
            if auth is None and _AUTH.match(value):
                auth = value
            elif cipher is None and _CIPHER.match(value):
                cipher = value
            continue
        pct = _PERCENT.match(value)
        if pct and "signal" not in current:
            current["signal"] = min(100, int(pct.group(1)))
        elif _INT.match(value) and "channel" not in current:        # the first plain integer after a BSSID line is the channel
            current["channel"] = int(value)
        elif re.match(r"^(2\.4|5|6)(\.\d+)?\s*GHz$", value, re.I) and "band" not in current:
            current["band"] = float(re.match(r"^(\d+(?:\.\d+)?)", value).group(1))
    flush()
    return [a for a in aps if a.bssid]


def parse_netsh_connection(text: str) -> tuple[Optional[str], Optional[str]]:
    """``(ssid, bssid)`` of the connected network from ``netsh wlan show interfaces`` output; ``(None, None)`` when not connected."""
    ssid = bssid = None
    for line in text.splitlines():
        m = re.search(rf"\bBSSID\s*:\s*({_MAC})\s*$", line)           # the label is "BSSID" or "AP BSSID", never translated
        if m:
            bssid = normalize_bssid(m.group(1))
            continue
        m = re.match(r"^\s*SSID\s*:\s*(.+?)\s*$", line)
        if m and ssid is None:
            ssid = m.group(1)
    return (ssid, bssid) if ssid and bssid else (None, None)


def _run_netsh(args: list[str], runner: Callable[..., Any] = subprocess.run, timeout: float = 30.0) -> tuple[int, str]:
    proc = runner(["netsh", "wlan", *args], capture_output=True, encoding="utf-8", errors="ignore", timeout=timeout)
    return int(proc.returncode), (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")


def scan_with_netsh(runner: Callable[..., Any] = subprocess.run) -> WifiScan:
    try:
        rc, out = _run_netsh(["show", "networks", "mode=bssid"], runner)
    except FileNotFoundError:
        raise WifiUnavailable("not_windows", "netsh is not available on this system.", "Wi-Fi scanning needs Windows (or the native API).")
    except subprocess.TimeoutExpired:
        raise WifiUnavailable("failed", "netsh did not answer within 30 s.", "Check that the WLAN AutoConfig service is running.")
    aps = parse_netsh_networks(out)
    if rc != 0 and not aps:
        first = next((ln.strip() for ln in out.splitlines() if ln.strip()), "netsh failed without a message")[:200]
        raise WifiUnavailable("access_denied" if rc != 0 else "failed", f"netsh could not list networks (exit code {rc}): {first}", LOCATION_FIX)
    try:
        rc2, out2 = _run_netsh(["show", "interfaces"], runner, 15.0)
        ssid, bssid = parse_netsh_connection(out2) if rc2 == 0 else (None, None)
    except Exception:
        ssid = bssid = None
    return WifiScan(aps=aps, connected_ssid=ssid, connected_bssid=bssid, backend="netsh")


# ── the Native Wifi API ──────────────────────────────────────────────────────
_AUTH_NAMES = {1: "Open", 2: "Shared", 3: "WPA", 4: "WPA-PSK", 5: "WPA-None", 6: "WPA2", 7: "WPA2-PSK", 8: "WPA3", 9: "WPA3-SAE", 10: "OWE"}
_CIPHER_NAMES = {0: "None", 1: "WEP40", 2: "TKIP", 4: "CCMP", 5: "WEP104", 6: "BIP", 8: "GCMP", 9: "GCMP-256", 256: "WEP"}
_ERROR_ACCESS_DENIED, _ERROR_SERVICE_NOT_ACTIVE, _ERROR_NOT_FOUND = 5, 1062, 1168


def _security_text(auth: int, cipher: int) -> Optional[str]:
    return canonical_security(_AUTH_NAMES.get(auth), _CIPHER_NAMES.get(cipher))


class NativeWlanApi:
    """A thin ``ctypes`` wrapper over ``wlanapi.dll``: opens a handle, lists interfaces, reads BSS and available-network lists.

    Kept separate from :func:`scan_native` so tests can swap it for a fake (no adapter needed)."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self.ct, self.wt = ctypes, wintypes
        self.dll = ctypes.WinDLL("wlanapi.dll")

        class GUID(ctypes.Structure):
            _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

        class DOT11_SSID(ctypes.Structure):
            _fields_ = [("uSSIDLength", wintypes.ULONG), ("ucSSID", ctypes.c_ubyte * 32)]

        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", ctypes.c_wchar * 256), ("isState", ctypes.c_int)]

        class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD), ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]

        class WLAN_RATE_SET(ctypes.Structure):
            _fields_ = [("uRateSetLength", wintypes.ULONG), ("usRateSet", wintypes.USHORT * 126)]

        class WLAN_BSS_ENTRY(ctypes.Structure):
            _fields_ = [("dot11Ssid", DOT11_SSID), ("uPhyId", wintypes.ULONG), ("dot11Bssid", ctypes.c_ubyte * 6), ("dot11BssType", ctypes.c_int),
                        ("dot11BssPhyType", ctypes.c_int), ("lRssi", ctypes.c_long), ("uLinkQuality", wintypes.ULONG),
                        ("bInRegDomain", ctypes.c_ubyte), ("usBeaconPeriod", wintypes.USHORT), ("ullTimestamp", ctypes.c_ulonglong),
                        ("ullHostTimestamp", ctypes.c_ulonglong), ("usCapabilityInformation", wintypes.USHORT),
                        ("ulChCenterFrequency", wintypes.ULONG), ("wlanRateSet", WLAN_RATE_SET), ("ulIeOffset", wintypes.ULONG),
                        ("ulIeSize", wintypes.ULONG)]

        class WLAN_BSS_LIST(ctypes.Structure):
            _fields_ = [("dwTotalSize", wintypes.DWORD), ("dwNumberOfItems", wintypes.DWORD), ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]

        class WLAN_AVAILABLE_NETWORK(ctypes.Structure):
            _fields_ = [("strProfileName", ctypes.c_wchar * 256), ("dot11Ssid", DOT11_SSID), ("dot11BssType", ctypes.c_int),
                        ("uNumberOfBssids", wintypes.ULONG), ("bNetworkConnectable", wintypes.BOOL), ("wlanNotConnectableReason", wintypes.DWORD),
                        ("uNumberOfPhyTypes", wintypes.ULONG), ("dot11PhyTypes", ctypes.c_int * 8), ("bMorePhyTypes", wintypes.BOOL),
                        ("wlanSignalQuality", wintypes.ULONG), ("bSecurityEnabled", wintypes.BOOL), ("dot11DefaultAuthAlgorithm", ctypes.c_int),
                        ("dot11DefaultCipherAlgorithm", ctypes.c_int), ("dwFlags", wintypes.DWORD), ("dwReserved", wintypes.DWORD)]

        class WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure):
            _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD), ("Network", WLAN_AVAILABLE_NETWORK * 1)]

        self.GUID, self.INFO_LIST, self.BSS_LIST, self.NET_LIST = GUID, WLAN_INTERFACE_INFO_LIST, WLAN_BSS_LIST, WLAN_AVAILABLE_NETWORK_LIST
        self.BSS_ENTRY, self.NET = WLAN_BSS_ENTRY, WLAN_AVAILABLE_NETWORK
        self.handle = wintypes.HANDLE()

    # each method returns plain Python data; ``code`` != 0 is raised as WifiUnavailable by the caller
    def open(self) -> int:
        negotiated = self.wt.DWORD()
        return int(self.dll.WlanOpenHandle(2, None, self.ct.byref(negotiated), self.ct.byref(self.handle)))

    def close(self) -> None:
        try:
            self.dll.WlanCloseHandle(self.handle, None)
        except Exception:
            pass

    def interfaces(self) -> tuple[int, list[tuple[Any, str]]]:
        ptr = self.ct.POINTER(self.INFO_LIST)()
        code = int(self.dll.WlanEnumInterfaces(self.handle, None, self.ct.byref(ptr)))
        if code != 0:
            return code, []
        try:
            n = ptr.contents.dwNumberOfItems
            arr = (type(ptr.contents.InterfaceInfo[0]) * n).from_address(self.ct.addressof(ptr.contents.InterfaceInfo))
            out = [(self.GUID.from_buffer_copy(arr[i].InterfaceGuid), arr[i].strInterfaceDescription) for i in range(n)]
        finally:
            self.dll.WlanFreeMemory(ptr)
        return 0, out

    def trigger_scan(self, guid: Any) -> None:
        try:
            self.dll.WlanScan(self.handle, self.ct.byref(guid), None, None, None)      # asynchronous; results are read from the cache
        except Exception:
            pass

    def bss_list(self, guid: Any) -> tuple[int, list[dict[str, Any]]]:
        ptr = self.ct.POINTER(self.BSS_LIST)()
        code = int(self.dll.WlanGetNetworkBssList(self.handle, self.ct.byref(guid), None, 3, False, None, self.ct.byref(ptr)))
        if code != 0:
            return code, []
        out: list[dict[str, Any]] = []
        try:
            n = ptr.contents.dwNumberOfItems
            arr = (self.BSS_ENTRY * n).from_address(self.ct.addressof(ptr.contents.wlanBssEntries))
            for e in arr:
                length = min(int(e.dot11Ssid.uSSIDLength), 32)
                raw = bytes(e.dot11Ssid.ucSSID[:length])
                out.append({"ssid": raw.decode("utf-8", errors="replace"), "bssid": ":".join(f"{b:02x}" for b in e.dot11Bssid),
                            "rssi": int(e.lRssi), "quality": int(e.uLinkQuality), "khz": int(e.ulChCenterFrequency)})
        finally:
            self.dll.WlanFreeMemory(ptr)
        return 0, out

    def available(self, guid: Any) -> tuple[int, list[dict[str, Any]]]:
        ptr = self.ct.POINTER(self.NET_LIST)()
        code = int(self.dll.WlanGetAvailableNetworkList(self.handle, self.ct.byref(guid), 2, None, self.ct.byref(ptr)))   # 2 = include all BSS
        if code != 0:
            return code, []
        out: list[dict[str, Any]] = []
        try:
            n = ptr.contents.dwNumberOfItems
            arr = (self.NET * n).from_address(self.ct.addressof(ptr.contents.Network))
            for e in arr:
                length = min(int(e.dot11Ssid.uSSIDLength), 32)
                out.append({"ssid": bytes(e.dot11Ssid.ucSSID[:length]).decode("utf-8", errors="replace"),
                            "secure": bool(e.bSecurityEnabled), "auth": int(e.dot11DefaultAuthAlgorithm), "cipher": int(e.dot11DefaultCipherAlgorithm)})
        finally:
            self.dll.WlanFreeMemory(ptr)
        return 0, out


def scan_native(api: Any = None, *, connection: Optional[Callable[[], tuple[Optional[str], Optional[str]]]] = None) -> WifiScan:
    """Scan through the Native Wifi API.  ``api`` is :class:`NativeWlanApi` (or a fake with the same methods)."""
    if api is None:
        if platform.system() != "Windows":
            raise WifiUnavailable("not_windows", "The Native Wifi API exists only on Windows.", "Wi-Fi scanning needs Windows.")
        try:
            api = NativeWlanApi()
        except Exception as exc:                                    # DLL missing / struct set-up failed
            raise WifiUnavailable("failed", f"The Native Wifi API could not be loaded: {type(exc).__name__}: {exc}")
    code = api.open()
    if code == _ERROR_SERVICE_NOT_ACTIVE:
        raise WifiUnavailable("no_wlan_service", "The WLAN AutoConfig service is not running.", "Start it: services.msc → WLAN AutoConfig → Start.")
    if code != 0:
        raise WifiUnavailable("failed", f"WlanOpenHandle failed with Windows error {code}.")
    try:
        code, interfaces = api.interfaces()
        if code != 0:
            raise WifiUnavailable("failed", f"WlanEnumInterfaces failed with Windows error {code}.")
        if not interfaces:
            raise WifiUnavailable("no_interface", "No Wi-Fi adapter was found.", "Plug in or enable a Wi-Fi adapter.")
        guid, description = interfaces[0]
        api.trigger_scan(guid)
        code, bss = api.bss_list(guid)
        if code == _ERROR_ACCESS_DENIED:
            raise WifiUnavailable("access_denied", "Windows refused the Wi-Fi scan (access denied).", LOCATION_FIX)
        if code != 0:
            raise WifiUnavailable("failed", f"WlanGetNetworkBssList failed with Windows error {code}.")
        code, available = api.available(guid)
        security: dict[str, set[str]] = {}
        if code == 0:
            for n in available:
                text = _security_text(n["auth"], n["cipher"]) if n["secure"] else "Open/None"
                if text:
                    security.setdefault(n["ssid"], set()).add(text)
        aps = []
        for b in bss:
            channel, band = channel_from_khz(b["khz"])
            sec = security.get(b["ssid"])
            aps.append(AccessPoint(ssid=b["ssid"], bssid=b["bssid"], signal_percent=max(0, min(100, b["quality"])), rssi_dbm=b["rssi"],
                                   channel=channel, band_ghz=band, security="/".join(sorted(sec)) if sec else None))
    finally:
        api.close()
    ssid, bssid = (connection() if connection is not None else _connected_via_netsh())
    return WifiScan(aps=aps, connected_ssid=ssid, connected_bssid=bssid, backend="native", interface=description)


def _connected_via_netsh() -> tuple[Optional[str], Optional[str]]:
    try:
        rc, out = _run_netsh(["show", "interfaces"], timeout=15.0)
        return parse_netsh_connection(out) if rc == 0 else (None, None)
    except Exception:
        return None, None


def scan(prefer: str = "native") -> WifiScan:
    """One scan: the Native Wifi API first, ``netsh`` if the native call cannot be made.  An access-denied (Location) failure is final —
    ``netsh`` would be refused for the same reason — everything else falls back."""
    if prefer == "native" and platform.system() == "Windows":
        try:
            return scan_native()
        except WifiUnavailable as exc:
            if exc.code in ("access_denied", "no_interface", "no_wlan_service"):
                raise
            logger.info("Native Wifi API unavailable (%s); falling back to netsh", exc.message)
    if platform.system() != "Windows":
        raise WifiUnavailable("not_windows", "Wi-Fi scanning is implemented for Windows (Native Wifi API / netsh).", "Run the backend on Windows to watch Wi-Fi.")
    return scan_with_netsh()
