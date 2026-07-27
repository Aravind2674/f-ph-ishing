"""
ThreatFusion – Per-Device Behavioural Baseline Store
=====================================================

Persists rolling behaviour profiles for every device seen on the monitored
network, built **exclusively from real observed traffic** (differentiator
#3).  There is no seed data and no synthetic priors: a device's "normal"
is whatever it has actually been observed doing.

Storage
-------
SQLite via ``aiosqlite`` — the same engine the App Layer already uses for
scan history (see ``app.main``). Three tables:

* ``net_devices``         – one row per MAC (identity + counters).
* ``net_device_domains``  – (mac, domain) → observation count.
* ``net_device_ports``    – (mac, port) → observation count.

A device baseline is considered *established* once it has accumulated at
least ``BASELINE_MIN_OBSERVATIONS`` DNS observations.  Only then do we let
"this domain is new for this device" drive a behavioural-deviation alert —
before that, we are still learning and would rather stay quiet than
manufacture a deviation from an empty profile.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import aiosqlite

from app.network.models import BaselineComparison, DeviceProfile

logger = logging.getLogger(__name__)


CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS net_devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    dns_observations INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS net_device_domains (
    mac TEXT NOT NULL,
    domain TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (mac, domain)
);

CREATE TABLE IF NOT EXISTS net_device_ports (
    mac TEXT NOT NULL,
    port INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (mac, port)
);

CREATE INDEX IF NOT EXISTS idx_net_domains_mac ON net_device_domains(mac);
CREATE INDEX IF NOT EXISTS idx_net_ports_mac ON net_device_ports(mac);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BaselineStore:
    """Async CRUD over the per-device behaviour tables.

    Parameters
    ----------
    db_path : str
        Filesystem path to the SQLite database file.
    min_observations : int
        DNS observations required before a profile is "established".
    """

    def __init__(self, db_path: str, min_observations: int = 15) -> None:
        self._db_path = db_path
        self._min_observations = min_observations

    async def init(self) -> None:
        """Create tables if they don't yet exist."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.executescript(CREATE_TABLES_SQL)
            await db.commit()
        logger.info("BaselineStore initialised at %s", self._db_path)

    # ------------------------------------------------------------------
    # Device identity
    # ------------------------------------------------------------------

    async def is_known_device(self, mac: str) -> bool:
        """Return True if we have ever seen this MAC before."""
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT 1 FROM net_devices WHERE mac = ?", (mac,)
            ) as cur:
                return await cur.fetchone() is not None

    async def observe_device(
        self, mac: str, ip: Optional[str] = None, hostname: Optional[str] = None,
        vendor: Optional[str] = None,
    ) -> bool:
        """Record that a device was seen. Returns True if it was brand-new.

        This is the single source of the "new device joined" signal: the
        return value is authoritative because it reflects an actual INSERT
        vs UPDATE against persisted state.
        """
        now = _now_iso()
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT mac FROM net_devices WHERE mac = ?", (mac,)
            ) as cur:
                existing = await cur.fetchone()

            if existing is None:
                await db.execute(
                    "INSERT INTO net_devices (mac, ip, hostname, vendor, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (mac, ip, hostname, vendor, now, now),
                )
                await db.commit()
                logger.info("New device recorded: %s (ip=%s)", mac, ip)
                return True

            # Update last_seen and hydrate ip/hostname/vendor if newly known.
            await db.execute(
                "UPDATE net_devices SET last_seen = ?, "
                "ip = COALESCE(?, ip), "
                "hostname = COALESCE(?, hostname), "
                "vendor = COALESCE(?, vendor) "
                "WHERE mac = ?",
                (now, ip, hostname, vendor, mac),
            )
            await db.commit()
            return False

    # ------------------------------------------------------------------
    # DNS behaviour
    # ------------------------------------------------------------------

    async def record_dns(self, mac: str, domain: str, ip: Optional[str] = None) -> None:
        """Fold a real observed DNS query into the device's profile."""
        now = _now_iso()
        domain = domain.lower().rstrip(".")
        async with aiosqlite.connect(self._db_path) as db:
            # Ensure the device row exists so counters are consistent.
            async with db.execute(
                "SELECT mac FROM net_devices WHERE mac = ?", (mac,)
            ) as cur:
                if await cur.fetchone() is None:
                    await db.execute(
                        "INSERT INTO net_devices (mac, ip, first_seen, last_seen, dns_observations) "
                        "VALUES (?, ?, ?, ?, 0)",
                        (mac, ip, now, now),
                    )

            await db.execute(
                "UPDATE net_devices SET dns_observations = dns_observations + 1, "
                "last_seen = ?, ip = COALESCE(?, ip) WHERE mac = ?",
                (now, ip, mac),
            )

            await db.execute(
                "INSERT INTO net_device_domains (mac, domain, count, first_seen, last_seen) "
                "VALUES (?, ?, 1, ?, ?) "
                "ON CONFLICT(mac, domain) DO UPDATE SET "
                "count = count + 1, last_seen = excluded.last_seen",
                (mac, domain, now, now),
            )
            await db.commit()

    async def record_port(self, mac: str, port: int) -> None:
        """Fold a real observed destination port into the device's profile."""
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "INSERT INTO net_device_ports (mac, port, count) VALUES (?, ?, 1) "
                "ON CONFLICT(mac, port) DO UPDATE SET count = count + 1",
                (mac, port),
            )
            await db.commit()

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    async def _domain_known_before(self, db: aiosqlite.Connection, mac: str, domain: str) -> bool:
        """Whether the device has contacted this domain more than once.

        We treat the *current* observation (already recorded) as count>=1,
        so "known before this event" means the stored count is >= 2.
        """
        async with db.execute(
            "SELECT count FROM net_device_domains WHERE mac = ? AND domain = ?",
            (mac, domain),
        ) as cur:
            row = await cur.fetchone()
        return row is not None and row[0] >= 2

    async def compare_dns(self, mac: str, domain: str) -> BaselineComparison:
        """Compare a freshly observed domain against the learned profile.

        IMPORTANT: call this *after* ``record_dns`` so the profile reflects
        reality. The "new domain" decision is based on whether the domain
        was known *before* this observation (stored count >= 2 means it was
        seen at least once previously).
        """
        domain = domain.lower().rstrip(".")
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT dns_observations FROM net_devices WHERE mac = ?", (mac,)
            ) as cur:
                dev = await cur.fetchone()
            observations = int(dev[0]) if dev else 0
            device_known = dev is not None

            async with db.execute(
                "SELECT COUNT(*) FROM net_device_domains WHERE mac = ?", (mac,)
            ) as cur:
                distinct = (await cur.fetchone())[0]

            async with db.execute(
                "SELECT domain FROM net_device_domains WHERE mac = ? "
                "ORDER BY count DESC LIMIT 8",
                (mac,),
            ) as cur:
                sample = [r[0] for r in await cur.fetchall()]

            known_before = await self._domain_known_before(db, mac, domain)

        established = observations >= self._min_observations
        is_new = not known_before

        if not established:
            detail = (
                f"Still learning this device's baseline "
                f"({observations}/{self._min_observations} observations); "
                f"not enough history to flag deviations yet."
            )
        elif is_new:
            detail = (
                f"Device normally contacts {distinct} known domain(s) "
                f"(e.g. {', '.join(sample[:3]) or 'n/a'}); "
                f"'{domain}' has not been seen before — a behavioural deviation."
            )
        else:
            detail = f"'{domain}' is within the device's learned baseline."

        return BaselineComparison(
            device_known=device_known,
            observations=observations,
            established=established,
            known_domains_sample=sample,
            known_domain_count=distinct,
            observed_domain=domain,
            is_new_domain=is_new,
            deviation_detail=detail,
        )

    async def get_profile(self, mac: str) -> Optional[DeviceProfile]:
        """Return the full persisted profile for a device, or None."""
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT mac, ip, hostname, vendor, first_seen, last_seen, dns_observations "
                "FROM net_devices WHERE mac = ?",
                (mac,),
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                return None

            async with db.execute(
                "SELECT domain FROM net_device_domains WHERE mac = ? "
                "ORDER BY count DESC LIMIT 12",
                (mac,),
            ) as cur:
                top_domains = [r[0] for r in await cur.fetchall()]

            async with db.execute(
                "SELECT COUNT(*) FROM net_device_domains WHERE mac = ?", (mac,)
            ) as cur:
                distinct = (await cur.fetchone())[0]

            async with db.execute(
                "SELECT port FROM net_device_ports WHERE mac = ? ORDER BY count DESC LIMIT 20",
                (mac,),
            ) as cur:
                ports = [int(r[0]) for r in await cur.fetchall()]

        return DeviceProfile(
            mac=row[0],
            ip=row[1],
            hostname=row[2],
            vendor=row[3],
            first_seen=datetime.fromisoformat(row[4]),
            last_seen=datetime.fromisoformat(row[5]),
            dns_observations=int(row[6]),
            distinct_domains=distinct,
            top_domains=top_domains,
            ports=ports,
        )

    async def list_devices(self) -> list[DeviceProfile]:
        """Return every profiled device, most recently seen first."""
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute(
                "SELECT mac FROM net_devices ORDER BY last_seen DESC"
            ) as cur:
                macs = [r[0] for r in await cur.fetchall()]
        profiles = []
        for mac in macs:
            p = await self.get_profile(mac)
            if p:
                profiles.append(p)
        return profiles

    async def device_count(self) -> int:
        async with aiosqlite.connect(self._db_path) as db:
            async with db.execute("SELECT COUNT(*) FROM net_devices") as cur:
                return int((await cur.fetchone())[0])
