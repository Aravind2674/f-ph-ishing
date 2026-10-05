"""A3-1: the capture preflight names the reason capture cannot work — each failure state is reachable and has a fix."""

from __future__ import annotations

from typing import Optional

import pytest

from app.network.preflight import (
    CaptureState,
    InterfaceInfo,
    Probes,
    classify_open_error,
    effective_state,
    run_preflight,
)

WIFI = InterfaceInfo(name="Wi-Fi", description="Intel(R) Wi-Fi 6 AX201", mac="10:91:d1:09:ba:e1", ipv4=["192.168.0.111"], usable=True)
ETH = InterfaceInfo(name="Ethernet", description="Realtek PCIe GbE", ipv4=["192.168.1.5"], usable=True)
PSEUDO = InterfaceInfo(name="Wi-Fi-WFP Native MAC Layer LightWeight Filter-0000", description="WFP", usable=False)


def probes(**over) -> Probes:
    base = dict(
        scapy_version=lambda: "2.7.0", npcap_present=lambda: True, is_elevated=lambda: True,
        list_interfaces=lambda: [WIFI, ETH, PSEUDO], default_interface=lambda: "Wi-Fi", open_probe=lambda iface: None, system="Windows",
    )
    base.update(over)
    return Probes(**base)


def test_everything_present_is_ready_and_picks_the_default_route_interface() -> None:
    pre = run_preflight("", probes())
    assert pre.state is CaptureState.READY and pre.ok and pre.fix is None
    assert pre.selected_interface == "Wi-Fi" and pre.details["interface_source"] == "default route"
    assert [i.name for i in pre.interfaces if i.usable] == ["Wi-Fi", "Ethernet"], "filter bindings are listed but not offered"


def test_missing_scapy() -> None:
    def boom() -> str:
        raise ImportError("No module named 'scapy'")

    pre = run_preflight("", probes(scapy_version=boom))
    assert pre.state is CaptureState.NO_SCAPY and not pre.ok and "pip install scapy" in pre.fix and "No module named" in pre.reason


def test_missing_npcap_on_windows_and_not_applicable_elsewhere() -> None:
    pre = run_preflight("", probes(npcap_present=lambda: False))
    assert pre.state is CaptureState.NO_NPCAP and "npcap.com" in pre.fix
    on_linux = run_preflight("", probes(npcap_present=lambda: None, system="Linux"))
    assert on_linux.state is CaptureState.READY, "libpcap is not required on Linux: the check is skipped, not failed"


@pytest.mark.parametrize("message", ["PermissionError: [Errno 1] Operation not permitted", "OSError: Access is denied", "Permission denied (need root)"])
def test_not_elevated_comes_from_actually_trying_to_open_the_handle(message: str) -> None:
    pre = run_preflight("", probes(is_elevated=lambda: False, open_probe=lambda iface: message))
    assert pre.state is CaptureState.NOT_ELEVATED and "Administrator" in pre.fix
    assert pre.details["elevated"] is False and message[:20] in pre.details["open_probe"]


def test_a_non_admin_account_that_can_open_the_handle_is_not_blocked() -> None:
    """Npcap can be installed to allow non-administrators: 'not admin' alone must not fail the check."""
    pre = run_preflight("", probes(is_elevated=lambda: False))
    assert pre.state is CaptureState.READY and pre.details["elevated"] is False


def test_no_usable_interface() -> None:
    pre = run_preflight("", probes(list_interfaces=lambda: [PSEUDO]))
    assert pre.state is CaptureState.NO_INTERFACE and "NETWORK_CAPTURE_INTERFACE" in pre.fix
    empty = run_preflight("", probes(list_interfaces=lambda: []))
    assert empty.state is CaptureState.NO_INTERFACE


def test_a_configured_interface_that_does_not_exist_is_named() -> None:
    pre = run_preflight("eth9", probes())
    assert pre.state is CaptureState.NO_INTERFACE and "eth9" in pre.reason
    assert [i.name for i in pre.interfaces] == ["Wi-Fi", "Ethernet", PSEUDO.name], "the choices are listed so the user can fix the setting"
    assert run_preflight("ethernet", probes()).selected_interface == "Ethernet"            # case-insensitive
    assert run_preflight("Intel(R) Wi-Fi", probes()).selected_interface == "Wi-Fi"        # or part of the description


def test_open_errors_are_classified_and_unknown_ones_are_reported_verbatim() -> None:
    assert classify_open_error("No such device exists (SIOCGIFHWADDR)") is CaptureState.NO_INTERFACE
    pre = run_preflight("", probes(open_probe=lambda iface: "RuntimeError: driver exploded"))
    assert pre.state is CaptureState.ERROR and "driver exploded" in pre.reason


def test_the_open_probe_can_be_skipped() -> None:
    called = []
    pre = run_preflight("", probes(open_probe=lambda iface: called.append(iface) or "boom"), probe_open=False)
    assert pre.state is CaptureState.READY and not called


def test_listing_interfaces_failing_is_an_error_not_a_crash() -> None:
    def boom() -> list[InterfaceInfo]:
        raise OSError("pcap_findalldevs failed")

    pre = run_preflight("", probes(list_interfaces=boom))
    assert pre.state is CaptureState.ERROR and "pcap_findalldevs" in pre.reason


def test_the_dict_form_is_json_serialisable() -> None:
    import json

    d = run_preflight("", probes()).to_dict()
    json.dumps(d)
    assert d["state"] == "ready" and d["interfaces"][0]["name"] == "Wi-Fi"


# ── the state the UI shows once capture is live ─────────────────────────────
def pre_ok() -> "object":
    return run_preflight("", probes())


def test_effective_state_ready_running_and_no_packets_seen() -> None:
    pre = pre_ok()
    assert effective_state(pre, sensors_running=False, packets_seen=0, seconds_running=0)[0] is CaptureState.READY
    assert effective_state(pre, sensors_running=True, packets_seen=0, seconds_running=3)[0] is CaptureState.RUNNING       # still waiting
    assert effective_state(pre, sensors_running=True, packets_seen=57, seconds_running=3)[0] is CaptureState.RUNNING
    state, reason, fix = effective_state(pre, sensors_running=True, packets_seen=0, seconds_running=45)
    assert state is CaptureState.NO_PACKETS_SEEN and "45 s" in reason and "mirror-port" in fix


def test_a_failed_preflight_keeps_its_state_whatever_the_sensors_say() -> None:
    pre = run_preflight("", probes(npcap_present=lambda: False))
    assert effective_state(pre, sensors_running=True, packets_seen=10, seconds_running=99)[0] is CaptureState.NO_NPCAP


def test_the_real_probes_run_and_never_raise() -> None:
    """On the machine running the tests (with or without Npcap / admin rights) the real probes return a state, not an exception."""
    pre = run_preflight("", probe_open=False)
    assert isinstance(pre.state, CaptureState) and pre.reason
    assert pre.state is not CaptureState.ERROR or "interfaces" in pre.reason or pre.details
