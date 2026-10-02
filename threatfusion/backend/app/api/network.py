"""
ThreatFusion – Network Layer API
=================================

Exposes the live network-monitoring surface to the frontend:

* ``GET  /network/status``           – honest per-sensor health.
* ``GET  /network/alerts``           – scored alerts (filter by severity).
* ``GET  /network/alerts/{id}``      – one alert's full evidence breakdown.
* ``GET  /network/devices``          – learned per-device baselines.
* ``GET  /network/devices/{mac}``    – one device's profile.
* ``GET  /network/stream``           – Server-Sent Events feed of new alerts.
* ``POST /network/monitor/start``    – begin real capture.
* ``POST /network/monitor/stop``     – stop capture.

Streaming uses **SSE** (there was no existing WebSocket/SSE transport in the
app, and the brief specifies SSE as the default in that case).
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from app.core.auth import issue_stream_ticket, require_token, require_token_or_ticket, STREAM_TICKET_TTL_SECONDS
from app.network.models import DeviceProfile, MonitorStatus, NetworkAlert
from app.network.service import get_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/network", tags=["network"], dependencies=[Depends(require_token)])


@router.get("/status", response_model=MonitorStatus, summary="Monitor health")
async def get_status() -> MonitorStatus:
    """Return whether monitoring is running and each sensor's honest status."""
    return await get_service().status()


@router.post("/monitor/start", response_model=MonitorStatus, summary="Start capture")
async def start_monitor() -> MonitorStatus:
    """Begin real packet/DNS/ARP/WiFi capture (needs Npcap + elevation)."""
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


@router.post("/stream-ticket", summary="Issue a single-use ticket for the SSE stream")
async def stream_ticket() -> dict:
    """EventSource cannot send an Authorization header; trade the token for a 30 s one-time ticket."""
    return {"ticket": issue_stream_ticket(), "expires_in": STREAM_TICKET_TTL_SECONDS}


# The SSE stream authenticates with a Bearer token OR a ticket, so it lives on its own router
# (the main router above requires the Bearer token on every route).
stream_router = APIRouter(prefix="/network", tags=["network"], dependencies=[Depends(require_token_or_ticket)])


@stream_router.get("/stream", summary="Live alert stream (SSE)")
async def stream_alerts(request: Request) -> StreamingResponse:
    """Server-Sent Events stream that pushes each new alert as it is scored."""
    svc = get_service()
    queue = svc.subscribe()

    async def event_generator():
        # Initial comment establishes the stream promptly for the browser.
        yield ": connected\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    alert = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    # Heartbeat keeps intermediaries from closing the idle stream.
                    yield ": keep-alive\n\n"
                    continue
                payload = alert.model_dump(mode="json")
                yield f"event: alert\ndata: {json.dumps(payload)}\n\n"
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
