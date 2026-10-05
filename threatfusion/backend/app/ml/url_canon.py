"""
One canonical form of a URL for the learned URL models (A2-3)
=============================================================

The audit found the URL model's score jumped from 0.13 to 0.99 when only ``https://`` was prepended: the scheme and a leading
``www.`` carry no information about whether a site is phishing, yet a character model trained on strings *as typed* learns
whatever correlates with them in its training data (here: how the dataset happened to be scraped).  The fix is to make the
model blind to them **by construction**, at training time *and* at inference time, with this one function:

* the scheme (``https://``, ``http://``, ``ftp://`` …) is dropped;
* a leading ``www.`` on the host is dropped;
* the **host is lower-cased** (DNS is case-insensitive); the path and query keep their case, because mixed-case random
  tokens in a path are a genuine lexical signal;
* userinfo (``paypal.com@evil.example``) is kept and its text lower-cased with the host — it is exactly the deception the model
  should see;
* a lone trailing ``/`` after the host is dropped (``example.com/`` and ``example.com`` are the same page);
* the fragment is kept (phishing kits sometimes put the victim's address there); whitespace is trimmed.

``canonical_url_text`` is the single source of truth: ``ml/train_*`` and the API both call it, so there is no train/serve
skew, and a test asserts scores are scheme- and ``www``-invariant (within 0.02) for the deployed model.
"""

from __future__ import annotations

import re

_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def split_canonical(raw: str) -> tuple[str, str]:
    """``(host-part, rest)`` of the canonical text: ``host-part`` is lower-case (userinfo and port included), ``rest`` starts
    with ``/``, ``?`` or ``#`` (or is empty)."""
    s = (raw or "").strip()
    s = _SCHEME.sub("", s, count=1)
    cut = len(s)
    for ch in "/?#":
        i = s.find(ch)
        if i != -1:
            cut = min(cut, i)
    host_part, rest = s[:cut].lower(), s[cut:]
    userinfo, at, hostport = host_part.rpartition("@")
    if hostport.startswith("www.") and len(hostport) > 4:
        host_part = userinfo + at + hostport[4:]
    if rest == "/":
        rest = ""
    return host_part, rest


def canonical_url_text(raw: str) -> str:
    """The canonical string the URL models read (see the module docstring)."""
    host_part, rest = split_canonical(raw)
    return host_part + rest


def hostname_of(raw: str) -> str:
    """The host name (no userinfo, no port) of the canonical form — lower-case, ``""`` if there is none."""
    host_part, _ = split_canonical(raw)
    host = host_part.rsplit("@", 1)[-1]
    if host.startswith("["):                                   # [IPv6]:port
        return host.split("]", 1)[0] + "]" if "]" in host else host
    return host.split(":", 1)[0]
