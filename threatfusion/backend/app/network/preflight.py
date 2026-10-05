"""
Capture preflight (A3-1)
========================

Before the monitor claims to be watching anything it checks what the machine can actually do and says *why* when it cannot.
The audited behaviour was a sensor thread that died quietly (or a status of ``available: true`` for a sniffer that had never seen a
packet), so a user with no Npcap saw an empty alert list and concluded the network was clean.

States (``CaptureState``) — every one is shown in the UI with a one-line reason and the fix:

* ``no_scapy``        scapy cannot be imported.
* ``no_npcap``        Windows only: no Npcap / WinPcap runtime (``wpcap.dll``) is installed.
* ``not_elevated``    the capture handle could not be opened for lack of privileges (the probe *tries* to open it — Npcap can be
                      installed to allow non-administrators, so "am I admin?" alone would give the wrong answer; it is reported as a detail).
* ``no_interface``    no usable interface, or the configured ``NETWORK_CAPTURE_INTERFACE`` does not exist.
* ``ready``           every check passed; capture has not been started.
* ``running``         capture is running and packets have been seen.
* ``no_packets_seen`` capture is running but nothing arrived for a while: the wrong interface, a switch port that does not carry
                      other devices' traffic (see the scope note), or a driver that hands up nothing.
* ``error``           something else failed (the message is verbatim).

Every probe is an injectable function so the logic is tested without a network card.  The real probes are best-effort and are
labelled as such: a probe that cannot decide returns ``None`` and the check is skipped, never assumed to have passed.
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

NO_PACKETS_AFTER_SECONDS = 20.0         # a capture that has seen nothing for this long is reported, not assumed healthy


class CaptureState(str, Enum):
    NO_SCAPY = "no_scapy"
    NO_NPCAP = "no_npcap"
    NOT_ELEVATED = "not_elevated"
    NO_INTERFACE = "no_interface"
    READY = "ready"
    RUNNING = "running"
    NO_PACKETS_SEEN = "no_packets_seen"
    ERROR = "error"


_FIX = {
    CaptureState.NO_SCAPY: "Install scapy (pip install scapy) in the backend environment.",
    CaptureState.NO_NPCAP: "Install Npcap from https://npcap.com/ (free for personal use) and restart the backend.",
    CaptureState.NOT_ELEVATED: "Run the backend from an Administrator terminal (Windows), as root or with CAP_NET_RAW (Linux/macOS: sudo), "
                               "or reinstall Npcap without “Restrict access to Administrators only”.",
    CaptureState.NO_INTERFACE: "Set NETWORK_CAPTURE_INTERFACE to one of the interface names listed here (leave it empty to use the default route's interface).",
    CaptureState.NO_PACKETS_SEEN: "Check that the selected interface is the one carrying traffic. A laptop sees only its own traffic plus broadcasts; "
                                  "watching other devices needs gateway / mirror-port placement or Zeek / Suricata logs.",
}

# Interface names that are filter/driver bindings or pseudo-devices, not something a user would capture on.
_PSEUDO = ("-wfp", "-qos", "-npcap", "-virtualbox", "wan miniport", "kernel debug", "ras async", "loopback", "pseudo-interface", "isatap", "teredo")
_VIRTUAL = ("vmware", "virtualbox", "hyper-v", "vethernet", "docker", "vmnet", "virtual", "tap-", "tun", "wsl")


@dataclass
class InterfaceInfo:
    name: str
    description: str = ""
    mac: Optional[str] = None
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    virtual: bool = False
    usable: bool = True


@dataclass
class CapturePreflight:
    state: CaptureState
    ok: bool
    reason: str
    fix: Optional[str] = None
    selected_interface: Optional[str] = None
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value, "ok": self.ok, "reason": self.reason, "fix": self.fix,
            "selected_interface": self.selected_interface,
            "interfaces": [i.__dict__ for i in self.interfaces],
            "details": self.details,
        }


# ── probes ──────────────────────────────────────────────────────────────────

def _scapy_version() -> str:
    """Import scapy (or raise).  A Windows machine without Npcap still *imports* scapy — it then lacks a capture backend."""
    import scapy                                                        # noqa: WPS433
    from scapy.all import conf                                          # noqa: F401,WPS433  (loads the platform backend)
    return str(scapy.__version__)


def _npcap_present() -> Optional[bool]:
    """Windows: is a pcap runtime installed?  ``None`` on other platforms (libpcap is not required there: scapy uses AF_PACKET)."""
    if platform.system() != "Windows":
        return None
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return any((Path(root) / rel).exists() for rel in (r"System32\Npcap\wpcap.dll", r"System32\wpcap.dll"))


def _is_elevated() -> Optional[bool]:
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())          # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:                                                   # pragma: no cover - platform specific
        return None


def _list_interfaces() -> list[InterfaceInfo]:
    from scapy.interfaces import get_working_ifaces                     # noqa: WPS433

    out: list[InterfaceInfo] = []
    for i in get_working_ifaces():
        name = str(getattr(i, "name", "") or "")
        desc = str(getattr(i, "description", "") or "")
        ips = getattr(i, "ips", None) or {}
        v4 = [ip for ip in (ips.get(4, []) if hasattr(ips, "get") else []) if ip]
        v6 = [ip for ip in (ips.get(6, []) if hasattr(ips, "get") else []) if ip]
        low = f"{name} {desc}".lower()
        out.append(InterfaceInfo(
            name=name, description=desc, mac=(getattr(i, "mac", None) or None), ipv4=v4, ipv6=v6,
            virtual=any(v in low for v in _VIRTUAL),
            usable=not any(p in low for p in _PSEUDO) and bool(v4 or v6),
        ))
    return out


def _default_interface() -> Optional[str]:
    try:
        from scapy.all import conf                                      # noqa: WPS433

        return str(conf.iface.name) if getattr(conf, "iface", None) else None
    except Exception:
        return None


def _open_probe(interface: Optional[str]) -> Optional[str]:
    """Try to open a capture handle for a moment.  Returns ``None`` on success or the (verbatim) error text."""
    try:
        from scapy.all import sniff                                     # noqa: WPS433

        sniff(iface=interface, timeout=0.5, count=1, store=False)
        return None
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


@dataclass
class Probes:
    scapy_version: Callable[[], str] = _scapy_version
    npcap_present: Callable[[], Optional[bool]] = _npcap_present
    is_elevated: Callable[[], Optional[bool]] = _is_elevated
    list_interfaces: Callable[[], list[InterfaceInfo]] = _list_interfaces
    default_interface: Callable[[], Optional[str]] = _default_interface
    open_probe: Optional[Callable[[Optional[str]], Optional[str]]] = _open_probe
    system: str = field(default_factory=platform.system)


_DENIED = ("permission", "denied", "not permitted", "operation not permitted", "access is denied", "privilege", "administrator")
_NO_DEVICE = ("no such device", "not found", "no such interface", "invalid adapter", "unknown interface", "does not exist")


def classify_open_error(message: str) -> CaptureState:
    low = message.lower()
    if any(w in low for w in _DENIED):
        return CaptureState.NOT_ELEVATED
    if any(w in low for w in _NO_DEVICE):
        return CaptureState.NO_INTERFACE
    return CaptureState.ERROR


def run_preflight(configured_interface: str = "", probes: Optional[Probes] = None, *, probe_open: bool = True) -> CapturePreflight:
    """Run the checks in the order a user would fix them and return the first failure (or ``ready``)."""
    p = probes or Probes()
    details: dict[str, Any] = {"platform": p.system}
    elevated = p.is_elevated()
    details["elevated"] = elevated

    def fail(state: CaptureState, reason: str, interfaces: Optional[list[InterfaceInfo]] = None, selected: Optional[str] = None) -> CapturePreflight:
        return CapturePreflight(state, False, reason, _FIX.get(state), selected, interfaces or [], details)

    try:
        details["scapy"] = p.scapy_version()
    except Exception as exc:
        return fail(CaptureState.NO_SCAPY, f"scapy is not available: {exc}")

    npcap = p.npcap_present()
    details["npcap"] = npcap
    if npcap is False:
        return fail(CaptureState.NO_NPCAP, "Npcap (the Windows packet-capture driver) is not installed, so no packet can be captured.")

    try:
        interfaces = p.list_interfaces()
    except Exception as exc:
        return fail(CaptureState.ERROR, f"could not list network interfaces: {exc}")
    usable = [i for i in interfaces if i.usable]
    details["interface_count"] = len(interfaces)
    if not usable:
        return fail(CaptureState.NO_INTERFACE, "No usable network interface was found (none has an IP address).", interfaces)

    wanted = (configured_interface or "").strip()
    selected: Optional[str]
    if wanted:
        match = next((i for i in interfaces if i.name.lower() == wanted.lower() or wanted.lower() in i.description.lower()), None)
        if match is None:
            return fail(CaptureState.NO_INTERFACE, f"The configured interface “{wanted}” does not exist on this machine.", interfaces)
        selected = match.name
    else:
        default = p.default_interface()
        selected = default if default and any(i.name == default for i in usable) else usable[0].name
        details["interface_source"] = "default route" if default == selected else "first usable"

    if probe_open and p.open_probe is not None:
        err = p.open_probe(selected)
        details["open_probe"] = "ok" if err is None else err[:300]
        if err is not None:
            state = classify_open_error(err)
            if state is CaptureState.ERROR:
                return fail(CaptureState.ERROR, f"Opening the capture handle failed: {err[:200]}", interfaces, selected)
            if state is CaptureState.NOT_ELEVATED:
                return fail(state, "The capture handle could not be opened: this account lacks the privileges for packet capture.", interfaces, selected)
            return fail(state, f"The capture interface could not be opened ({err[:120]}).", interfaces, selected)

    return CapturePreflight(CaptureState.READY, True, "Capture prerequisites are met; no capture is running yet.", None, selected, interfaces, details)


def effective_state(pre: CapturePreflight, *, sensors_running: bool, packets_seen: int, seconds_running: float,
                    no_packets_after: float = NO_PACKETS_AFTER_SECONDS) -> tuple[CaptureState, str, Optional[str]]:
    """The state the UI shows: the preflight outcome, upgraded to ``running`` / ``no_packets_seen`` once capture is live."""
    if not pre.ok:
        return pre.state, pre.reason, pre.fix
    if not sensors_running:
        return CaptureState.READY, pre.reason, None
    if packets_seen > 0:
        return CaptureState.RUNNING, f"Capturing on {pre.selected_interface}; {packets_seen} packets seen.", None
    if seconds_running >= no_packets_after:
        return (CaptureState.NO_PACKETS_SEEN,
                f"Capture on {pre.selected_interface} has been running {int(seconds_running)} s without seeing a single packet.",
                _FIX[CaptureState.NO_PACKETS_SEEN])
    return CaptureState.RUNNING, f"Capture started on {pre.selected_interface}; waiting for the first packet.", None
