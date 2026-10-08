"""
ThreatFusion – Network Layer API
=================================

Exposes the live network-monitoring surface to the frontend:

* ``GET  /network/status``           – honest per-sensor health (capture state, packets, drops).
* ``GET  /network/preflight``        – can this machine capture, and if not why and how to fix it.
* ``GET  /network/interfaces``       – the capture interfaces and which one is used.
* ``POST /network/interface``        – pick the capture interface (monitor must be stopped).
* ``GET  /network/alerts``           – scored alerts (filter by severity).
* ``GET  /network/alerts/{id}``      – one alert's full evidence breakdown.
* ``GET  /network/devices``          – learned per-device baselines.
* ``GET  /network/devices/{mac}``    – one device's profile.
* ``GET  /network/stream``           – Server-Sent Events feed of new alerts (resumes from ``Last-Event-ID``).
* ``POST /network/monitor/start``    – run the preflight, then begin real capture (nothing starts if it fails).
* ``POST /network/monitor/stop``     – stop capture.

Streaming uses **SSE** (there was no existing WebSocket/SSE transport in the
app, and the brief specifies SSE as the default in that case).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from fastapi.responses import StreamingResponse

from app.core.auth import issue_stream_ticket, require_token, require_token_or_ticket, STREAM_TICKET_TTL_SECONDS
from app.network.models import DeviceProfile, MonitorStatus, NetworkAlert
from app.network.service import MonitorRunning, UnknownInterface, get_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network", tags=["network"], dependencies=[Depends(require_token)])


@router.get("/status", response_model=MonitorStatus, summary="Monitor health")
async def get_status() -> MonitorStatus:
    """Return whether monitoring is running and each sensor's honest status."""
    return await get_service().status()


@router.get("/preflight", summary="Can this machine capture packets?")
async def get_preflight(refresh: bool = Query(False, description="Re-run the checks instead of using the answer cached for 15 s")) -> dict:
    """State, reason and one-line fix: no_scapy · no_npcap · not_elevated · no_interface · ready · error."""
    svc = get_service()
    return (await svc.preflight(force=refresh)).to_dict()


@router.get("/interfaces", summary="Capture interfaces")
async def get_interfaces() -> dict:
    """Every interface scapy can see, the one capture uses, and where that choice came from (Settings, env, default route)."""
    return await get_service().interfaces()


class InterfaceChoice(BaseModel):
    name: str = Field("", max_length=200, description="Interface name from GET /network/interfaces; empty = automatic")


@router.post("/interface", summary="Pick the capture interface")
async def set_interface(body: InterfaceChoice) -> dict:
    try:
        return await get_service().set_interface(body.name)
    except MonitorRunning as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    except UnknownInterface as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/monitor/start", response_model=MonitorStatus, summary="Start capture")
async def start_monitor() -> MonitorStatus:
    """Run the preflight, then begin real ARP / DNS / TLS / Wi-Fi capture. If the machine cannot capture nothing starts and the
    status carries the reason and the fix."""
    svc = get_service()
    await svc.start()
    return await svc.status()


@router.post("/monitor/stop", response_model=MonitorStatus, summary="Stop capture")
async def stop_monitor() -> MonitorStatus:
    """Stop all sensors and the correlation consumer."""
    svc = get_service()
    await svc.stop()
    return await svc.status()


@router.get("/alerts", response_model=list[NetworkAlert], summary="List alerts")
async def list_alerts(
    severity: str | None = Query(None, description="Filter: Low/Medium/High/Critical"),
    limit: int = Query(200, ge=1, le=1000),
) -> list[NetworkAlert]:
    """Return scored alerts, newest first, optionally filtered by severity."""
    return get_service().get_alerts(severity=severity, limit=limit)


@router.get("/alerts/{alert_id}", response_model=NetworkAlert, summary="Alert detail")
async def get_alert(alert_id: str) -> NetworkAlert:
    """Return the full evidence breakdown for a single alert."""
    alert = get_service().get_alert(alert_id)
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    return alert


@router.get("/devices", response_model=list[DeviceProfile], summary="List devices")
async def list_devices() -> list[DeviceProfile]:
    """Return every device baseline learned from real observed traffic."""
    return await get_service().store.list_devices()


@router.get("/devices/{mac}", response_model=DeviceProfile, summary="Device profile")
async def get_device(mac: str) -> DeviceProfile:
    """Return a single device's learned behaviour profile."""
    profile = await get_service().store.get_profile(mac.lower())
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device '{mac}' not found.",
        )
    return profile


@router.get("/aps", summary="Access points seen in Wi-Fi scans")
async def list_access_points(limit: int = Query(500, ge=1, le=2000)) -> list[dict]:
    """Every access point remembered from the Wi-Fi scans, with the vendor prefix, security mode, channels used and whether it is confirmed
    (``known``), flagged, or part of a watched network (the connected network and ``NETWORK_MONITORED_SSIDS``)."""
    svc = get_service()
    watched = svc.engine.watched_ssids()
    rows = await svc.aps.list(limit)
    for r in rows:
        r["watched"] = (r["ssid"] or "").lower() in watched
    return rows


class KnownAp(BaseModel):
    bssid: str = Field(..., max_length=17, description="aa:bb:cc:dd:ee:ff")
    known: bool = Field(True, description="True = this is my access point; False = take the confirmation back")


@router.post("/aps/known", summary="Confirm (or un-confirm) an access point")
async def mark_access_point(body: KnownAp) -> dict:
    """A confirmed access point is never reported again and its vendor prefix becomes part of the accepted set for its network."""
    from app.network.sensor.wlan import normalize_bssid

    bssid = normalize_bssid(body.bssid)
    if bssid is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="That is not a BSSID (expected aa:bb:cc:dd:ee:ff).")
    if not await get_service().aps.set_known(bssid, body.known):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No access point {bssid} has been seen.")
    return {"bssid": bssid, "known": body.known}


@router.delete("/data", summary="Erase all stored network data")
async def delete_network_data() -> dict:
    """Erase every stored device profile, per-device domain history and alert (irreversible).

    Also clears the cached third-party lookups (A1-1): that cache holds every hostname the network layer looked up.
    Requires the API token and a JSON content type like every mutating route.
    """
    from app.core.hub import hub
    counts = await get_service().delete_all_data()
    counts["cached_lookups"] = await hub.cache.clear()
    return counts


@router.post("/stream-ticket", summary="Issue a single-use ticket for the SSE stream")
async def stream_ticket() -> dict:
    """EventSource cannot send an Authorization header; trade the token for a 30 s one-time ticket."""
    return {"ticket": issue_stream_ticket(), "expires_in": STREAM_TICKET_TTL_SECONDS}


# The SSE stream authenticates with a Bearer token OR a ticket, so it lives on its own router
# (the main router above requires the Bearer token on every route).
stream_router = APIRouter(prefix="/network", tags=["network"], dependencies=[Depends(require_token_or_ticket)])


def _last_id(header: Optional[str], query: Optional[int]) -> Optional[int]:
    """The sequence number the client last saw: the standard ``Last-Event-ID`` header, or ``?last_event_id=`` (a client that opens a
    fresh EventSource with a fresh ticket cannot rely on the browser's automatic header)."""
    if query is not None:
        return query
    try:
        return int(header) if header is not None and header.strip() != "" else None
    except ValueError:
        return None


@stream_router.get("/stream", summary="Live alert stream (SSE)")
async def stream_alerts(
    request: Request,
    last_event_id: Optional[int] = Query(None, ge=0, description="Resume after this alert sequence number"),
    last_event_id_header: Optional[str] = Header(None, alias="Last-Event-ID"),
) -> StreamingResponse:
    """Server-Sent Events stream that pushes each new alert as it is scored, each with an ``id:`` so a reconnect can resume."""
    svc = get_service()
    queue = svc.subscribe(_last_id(last_event_id_header, last_event_id))

    async def event_generator():
        # Initial comment establishes the stream promptly for the browser.
        yield "retry: 3000\n: connected\n\n"          # no id here: the resume point only advances with a delivered alert
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    seq, alert = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    # Heartbeat keeps intermediaries from closing the idle stream.
                    yield ": keep-alive\n\n"
                    continue
                payload = alert.model_dump(mode="json")
                yield f"id: {seq}\nevent: alert\ndata: {json.dumps(payload)}\n\n"
        finally:
            svc.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

@stream_router.get("/packets", summary="Live raw packet stream (SSE)")
async def stream_packets(request: Request) -> StreamingResponse:
    """Server-Sent Events stream for raw captured packets/events."""
    svc = get_service()
    queue = svc.subscribe_packets()

    async def packet_generator():
        yield "retry: 3000\n: connected\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
                    continue
                payload = event.model_dump(mode="json")
                yield f"event: packet\ndata: {json.dumps(payload)}\n\n"
        finally:
            svc.unsubscribe_packets(queue)

    return StreamingResponse(
        packet_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
