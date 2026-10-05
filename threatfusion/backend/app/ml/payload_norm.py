"""
Payload normalisation for the HTTP attack classifier (A2-4)
===========================================================

Attackers do not send ``' OR 1=1--``; they send ``%2527%2520OR%25201%253D1--``, ``&#x27; OR 1=1``, ``'/**/OR/**/1=1--``, a
full-width quote, a zero-width space in the middle of ``<script>`` — and then pad the request so the interesting part falls past
the classifier's input window.  A character model trained on plain payloads sees none of these as attacks.  This module reduces
a payload to the form a human analyst would read, **before** classification:

1. **Iterated percent-decoding** (``%2527`` → ``%27`` → ``'``), up to a few rounds, stopping when stable;
2. **HTML-entity decoding** (``&lt;``, ``&#x3c;``, ``&#60;``);
3. **Unicode NFKC** (full-width ``＜`` → ``<``, ligatures, compatibility forms);
4. removal of zero-width and control characters used to split keywords;
5. **comments become whitespace** (``/**/`` and ``/* … */`` are how ``SELECT/**/1`` hides in SQL), then whitespace is collapsed.

``windows`` slices a long text into overlapping fixed-size windows so the classifier can read *all* of it (scores are then
max-pooled over windows: one attack window is enough) instead of silently truncating at the model's input length.

Both functions are pure and deterministic; the classifier scores the raw text *and* the normalised text and the more severe
verdict wins (a defensive choice that cannot make a plain attack look benign).
"""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Iterator
from urllib.parse import unquote_plus

_INVISIBLE = re.compile("[​‌‍⁠﻿­\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]")
_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_SPACE = re.compile(r"\s+")
MAX_DECODE_ROUNDS = 4


def normalize_payload(text: str) -> str:
    """The analyst-readable form of ``text`` (see the module docstring). Idempotent."""
    s = text or ""
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = html.unescape(unquote_plus(s))
        if decoded == s:
            break
        s = decoded
    s = unicodedata.normalize("NFKC", s)
    s = _INVISIBLE.sub("", s)
    s = _COMMENT.sub(" ", s)
    return _SPACE.sub(" ", s).strip()


def windows(text: str, size: int, stride: int) -> Iterator[str]:
    """Overlapping windows covering all of ``text`` (a single window when it is short); the last one is always included."""
    if size <= 0 or stride <= 0:
        raise ValueError("size and stride must be positive")
    if len(text) <= size:
        yield text
        return
    start = 0
    while True:
        yield text[start:start + size]
        if start + size >= len(text):
            return
        start += stride
        if start + size > len(text):
            yield text[-size:]
            return
