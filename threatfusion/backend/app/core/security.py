"""
Request-level guards: Host allow-list and JSON-only mutations (A0-8)
=====================================================================

A pure-ASGI middleware that runs before routing:

* **Host allow-list** — a request whose ``Host`` header is not a configured local name
  (``ALLOWED_HOSTS``, default ``localhost,127.0.0.1,[::1]``; the port is ignored) is refused with 400.
  This is the defence against DNS rebinding: after a rebind the browser still sends the *attacker's*
  hostname in ``Host``, so the page can no longer read our responses as "same origin".
* **JSON-only mutations** — ``POST``/``PUT``/``PATCH``/``DELETE`` must carry
  ``Content-Type: application/json`` or get 415.  A cross-site HTML ``<form>`` or a ``no-cors``
  ``fetch`` can only send ``text/plain`` / form types without a CORS preflight, so it can no longer
  trigger body-less endpoints such as ``POST /network/monitor/start``.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import get_settings

_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def normalise_host(value: str) -> str:
    """``"LocalHost:8000"`` / ``"[::1]:8000"`` -> ``"localhost"`` / ``"::1"`` (port ignored)."""
    value = (value or "").strip().lower()
    if not value:
        return ""
    try:
        return urlsplit("//" + value).hostname or ""
    except ValueError:
        return ""


class SecurityMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        host = normalise_host(headers.get("host", ""))
        if host not in get_settings().allowed_hosts:
            await self._reject(scope, receive, send, 400, "Invalid Host header")
            return

        if scope["type"] == "http" and scope["method"] in _MUTATING:
            content_type = headers.get("content-type", "").split(";")[0].strip().lower()
            if content_type != "application/json":
                await self._reject(scope, receive, send, 415,
                                   "Mutating requests must use Content-Type: application/json")
                return

        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(scope: Scope, receive: Receive, send: Send, status: int, detail: str) -> None:
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)
