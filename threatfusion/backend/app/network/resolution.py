"""
Which name did this IP come from? (revamp T2c)
==============================================

A DNS response says *name → addresses, for this many seconds*.  Remembering that lets a later connection to a bare address — a TLS
ClientHello with no SNI, an ARP-level observation, a flow log — be tied back to the name the device asked for, and lets one name
observed two ways (the DNS query, then the TLS SNI) be recognised as the same visit.

Rules
-----
* **TTLs are respected**: an answer is forgotten when its TTL runs out (never kept "just in case" — a name can move to another host).
  A TTL of 0 is stored for one second so the connection that follows the answer can still be explained.
* **Bounded**: at most ``max_entries`` addresses are kept; the least recently used goes first.  A malicious or just very busy network
  cannot grow it without limit.  Each address remembers at most ``MAX_NAMES_PER_IP`` names (shared hosting is common).
* Names are stored exactly as asked (lower-case, no trailing dot).  Nothing here is sent anywhere.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Callable, Iterable, Optional

MAX_NAMES_PER_IP = 8
MAX_TTL_SECONDS = 24 * 3600


class ResolutionMap:
    def __init__(self, max_entries: int = 50_000, clock: Callable[[], float] = time.time) -> None:
        self._max = max(1, max_entries)
        self._clock = clock
        self._by_ip: "OrderedDict[str, dict[str, float]]" = OrderedDict()      # ip -> {name: expires_at}

    def __len__(self) -> int:
        return len(self._by_ip)

    def add(self, name: str, ips: Iterable[str], ttl: int, *, also: Iterable[str] = ()) -> None:
        """Remember that ``name`` (and the other names in ``also``, e.g. the CNAME target) resolved to ``ips`` for ``ttl`` seconds."""
        names = [n for n in (name, *also) if n]
        if not names:
            return
        expires = self._clock() + min(max(int(ttl), 1), MAX_TTL_SECONDS)
        for ip in ips:
            if not ip:
                continue
            entry = self._by_ip.get(ip)
            if entry is None:
                entry = self._by_ip[ip] = {}
            for n in names:
                entry[n] = max(expires, entry.get(n, 0.0))
            while len(entry) > MAX_NAMES_PER_IP:
                entry.pop(min(entry, key=entry.get))              # drop the one that expires first
            self._by_ip.move_to_end(ip)
        while len(self._by_ip) > self._max:
            self._by_ip.popitem(last=False)                        # least recently used

    def names_for(self, ip: Optional[str]) -> list[str]:
        """Unexpired names that resolved to ``ip``, the longest-lived first."""
        if not ip:
            return []
        entry = self._by_ip.get(ip)
        if entry is None:
            return []
        now = self._clock()
        for n in [n for n, exp in entry.items() if exp <= now]:
            del entry[n]
        if not entry:
            del self._by_ip[ip]
            return []
        self._by_ip.move_to_end(ip)
        return sorted(entry, key=lambda n: -entry[n])

    def name_for(self, ip: Optional[str]) -> Optional[str]:
        names = self.names_for(ip)
        return names[0] if names else None
