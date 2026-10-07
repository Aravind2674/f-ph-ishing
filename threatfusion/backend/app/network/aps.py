"""
Access points, remembered — and what counts as a suspicious one (revamp T2d)
===========================================================================

The old scanner called every BSSID it had not seen since start-up a "rogue AP".  On a campus (one SSID, hundreds of access points, all
from one vendor) that is a stream of false alarms, and the baseline vanished at every restart.  Now every access point is stored
(``net_aps``) and judged against **its own network**:

* A network is its **SSID**.  The BSSIDs that carry it and share a **vendor prefix (OUI)** are one deployment — the 200th AP of the
  same wireless system is *not* news.
* Only a **watched** network is judged: the SSIDs you list in ``NETWORK_MONITORED_SSIDS`` and the network you are connected to.  A stranger's
  new access point next door is not your concern, and is simply recorded.
* Findings, each with the evidence that produced it:

  ``unexpected_oui``      a **new BSSID** for a watched SSID whose vendor prefix has never carried that SSID — different hardware claiming
                          your network's name (the signature of a pocket evil-twin).
  ``security_mismatch``   the SSID is advertised with a **security mode** it has never had (an open twin of a WPA2 network, or a BSSID
                          that switched).  Unknown security (``None``) is never compared.
  ``unexpected_channel``  a known BSSID on a channel it has never used, after at least ``CHANNEL_MIN_SIGHTINGS`` sightings (access points
                          change channel, so this is the weakest signal and the lowest severity).

* ``known`` — you can confirm an access point (``POST /network/aps/known``): it is never reported again, and its vendor prefix becomes
  part of the accepted set for its SSID.  A BSSID that was *reported* is marked ``flagged`` and is **not** part of the accepted set until
  you confirm it — otherwise one twin would make a second twin from the same hardware look ordinary.
* The very first scan on an empty store only learns (nothing can be "new" yet).  The false-positive rate on *your* network is something
  to measure by running it there; ``docs/REVAMP.md`` records what was measured and where.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

import aiosqlite

logger = logging.getLogger(__name__)

CHANNEL_MIN_SIGHTINGS = 5
MAX_CHANNEL_HISTORY = 8

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS net_aps (
    bssid TEXT PRIMARY KEY,
    ssid TEXT NOT NULL,
    oui TEXT NOT NULL,
    security TEXT,
    channels TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    sightings INTEGER NOT NULL DEFAULT 0,
    known INTEGER NOT NULL DEFAULT 0,
    flagged INTEGER NOT NULL DEFAULT 0,
    last_signal INTEGER,
    last_channel INTEGER
);
CREATE INDEX IF NOT EXISTS idx_net_aps_ssid ON net_aps(ssid COLLATE NOCASE);
"""


@dataclass
class ApFinding:
    kind: str                                  # unexpected_oui | security_mismatch | unexpected_channel
    ssid: str
    bssid: str
    ap: dict[str, Any]
    evidence: dict[str, Any] = field(default_factory=dict)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ApStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._ready = False

    async def init(self) -> None:
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(CREATE_SQL)
            await db.commit()
        self._ready = True

    async def list(self, limit: int = 500) -> list[dict[str, Any]]:
        if not self._ready:
            await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM net_aps ORDER BY last_seen DESC LIMIT ?", (limit,)) as cur:
                rows = await cur.fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["channels"] = json.loads(d["channels"] or "[]")
            d["known"] = bool(d["known"])
            d["flagged"] = bool(d["flagged"])
            out.append(d)
        return out

    async def count(self) -> int:
        if not self._ready:
            await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute("SELECT COUNT(*) FROM net_aps") as cur:
                return int((await cur.fetchone())[0])

    async def set_known(self, bssid: str, known: bool) -> bool:
        """Confirm (or un-confirm) an access point. ``False`` if the BSSID has never been seen."""
        if not self._ready:
            await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            cur = await db.execute("UPDATE net_aps SET known = ?, flagged = CASE WHEN ? THEN 0 ELSE flagged END WHERE bssid = ?",
                                   (1 if known else 0, 1 if known else 0, bssid.lower()))
            await db.commit()
            return cur.rowcount > 0

    async def purge_older_than(self, cutoff_iso: str) -> int:
        if not self._ready:
            await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            cur = await db.execute("DELETE FROM net_aps WHERE last_seen < ? AND known = 0", (cutoff_iso,))     # an access point you confirmed is kept
            await db.commit()
            return cur.rowcount

    async def delete_all(self) -> int:
        if not self._ready:
            await self.init()
        async with aiosqlite.connect(self._db_path) as db:
            cur = await db.execute("DELETE FROM net_aps")
            await db.commit()
            return cur.rowcount

    async def observe(self, aps: Iterable[dict[str, Any]], watched: set[str], *, now: Optional[str] = None) -> list[ApFinding]:
        """Record one scan and return what is suspicious about it.  ``watched`` holds lower-cased SSIDs."""
        if not self._ready:
            await self.init()
        stamp = now or _now()
        findings: list[ApFinding] = []
        aps = [a for a in aps if a.get("bssid")]
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT COUNT(*) FROM net_aps") as cur:
                learning = int((await cur.fetchone())[0]) == 0           # the first scan ever only learns
            for ap in aps:
                bssid, ssid = ap["bssid"].lower(), ap.get("ssid") or ""
                oui = ap.get("oui") or ":".join(bssid.split(":")[:3])
                async with db.execute("SELECT * FROM net_aps WHERE bssid = ?", (bssid,)) as cur:
                    row = await cur.fetchone()
                channels = json.loads(row["channels"]) if row else []
                # new *for this name*: a BSSID never seen, or one that used to carry a different SSID (a renamed neighbour is the cheapest twin)
                new_here = row is None or (row["ssid"] or "").lower() != ssid.lower()
                judged = bool(ssid) and ssid.lower() in watched and not learning and not (row and row["known"])
                if judged:
                    peers = []
                    async with db.execute("SELECT oui, security, known FROM net_aps WHERE ssid = ? COLLATE NOCASE AND bssid != ? "
                                          "AND (flagged = 0 OR known = 1)", (ssid, bssid)) as cur:
                        peers = list(await cur.fetchall())
                    known_ouis = sorted({p["oui"] for p in peers})
                    known_secs = sorted({p["security"] for p in peers if p["security"]})
                    security = ap.get("security")
                    if new_here and peers and oui not in known_ouis:
                        findings.append(ApFinding("unexpected_oui", ssid, bssid, ap, {
                            "observed_oui": oui, "known_ouis": known_ouis, "known_bssids": len(peers), "known_security": known_secs}))
                    if security and ((new_here and peers and known_secs and security not in known_secs)
                                     or (not new_here and row["security"] and security != row["security"])):
                        findings.append(ApFinding("security_mismatch", ssid, bssid, ap, {
                            "observed_security": security, "known_security": known_secs if new_here else [row["security"]],
                            "previous_security_of_this_bssid": None if new_here else row["security"]}))
                    ch = ap.get("channel")
                    if not new_here and ch and channels and ch not in channels and row["sightings"] >= CHANNEL_MIN_SIGHTINGS:
                        findings.append(ApFinding("unexpected_channel", ssid, bssid, ap, {
                            "observed_channel": ch, "channels_used_before": channels, "sightings": row["sightings"]}))
                flagged_now = any(f.bssid == bssid and f.kind in ("unexpected_oui", "security_mismatch") for f in findings)
                ch = ap.get("channel")
                if ch and ch not in channels:
                    channels = (channels + [ch])[-MAX_CHANNEL_HISTORY:]
                if row is None:
                    await db.execute(
                        "INSERT INTO net_aps (bssid, ssid, oui, security, channels, first_seen, last_seen, sightings, known, flagged, last_signal, last_channel) "
                        "VALUES (?,?,?,?,?,?,?,1,0,?,?,?)",
                        (bssid, ssid, oui, ap.get("security"), json.dumps(channels), stamp, stamp, 1 if flagged_now else 0,
                         ap.get("signal_percent"), ap.get("channel")))
                else:
                    await db.execute(
                        "UPDATE net_aps SET ssid = ?, security = COALESCE(?, security), channels = ?, last_seen = ?, sightings = sightings + 1, "
                        "flagged = CASE WHEN ? THEN 1 ELSE flagged END, last_signal = ?, last_channel = COALESCE(?, last_channel) WHERE bssid = ?",
                        (ssid, ap.get("security"), json.dumps(channels), stamp, 1 if flagged_now else 0, ap.get("signal_percent"),
                         ap.get("channel"), bssid))
            await db.commit()
        return findings
