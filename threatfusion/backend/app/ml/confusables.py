"""
Look-alike characters: Unicode TR39 skeletons, leetspeak and "two letters that look like one" (B4)
=================================================================================================

Phishing domains swap characters for ones that *look* the same to a human: a Cyrillic ``а`` for a Latin ``a``
(``pаypal.com``), a digit ``1`` for ``l`` (``paypa1``), ``rn`` for ``m`` (``arnazon``), a Greek omicron for ``o``.
Comparing a scanned label with a brand therefore starts by reducing both to a **skeleton**.

Stages (reported separately, so the evidence can say *what kind* of trick it was)
-------------------------------------------------------------------------------
1. **skeleton** — NFKC-fold (fullwidth, compatibility forms), lowercase, then map every confusable character to its
   prototype (Cyrillic ``а`` → ``a``, Greek ``ο`` → ``o``, small capitals, dotless ``ı``, digits ``0``/``1`` as in
   TR39) and strip diacritics (``à`` → ``a``).  This is the TR39 idea: two strings are *confusable* when their
   skeletons are equal.
2. **leet** — digits and symbols used as letters that TR39 does not treat as confusables: ``3``→e ``4``→a ``5``→s
   ``7``→t ``8``→b ``9``→g ``@``→a ``$``→s ``|``→l.
3. **sequences** — letter pairs that read as one letter: ``rn``→m ``vv``→w ``cl``→d.

The character table is a **curated subset** of the Unicode TR39 ``confusables.txt`` (Latin / Cyrillic / Greek /
Armenian / small-capital look-alikes seen in real phishing).  The complete file, if you have it, can be used instead:
:func:`load_confusables` parses its ``source ; target ; type`` lines (``MA`` entries) and falls back to the curated
table when the file is missing or unreadable — it never raises.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ── curated TR39 subset: confusable character -> prototype ──────────────────
_PAIRS: list[tuple[str, str]] = []


def _add(sources: str, prototypes: str) -> None:
    assert len(sources) == len(prototypes), (sources, prototypes)
    _PAIRS.extend(zip(sources, prototypes))


# Cyrillic
_add("аеорсухіјѕԁһӏԛԝкнтмвгѵүѡ", "aeopcyxijsdhlqwkhtmbrvyw")
# Greek
_add("αορνικτυχεβγηωϲϳς", "aopvikt" "uxebynwcjc")
# Latin extended / IPA / small capitals
_add("ɑɡıɩʀʏɴꜱᴀʙᴄᴅᴇɢʜᴊᴋʟᴍᴏᴘᴛᴜᴠᴡᴢƒɦʋĸʝ", "agiirynsabcdeghjklmoptuvwzfhvkj")
# Armenian
_add("օսցոհ", "ouqnh")
# TR39 treats these digits as confusables of letters
_add("01ǀ", "oll")

CURATED: dict[str, str] = dict(_PAIRS)

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
                       "$": "s", "@": "a", "!": "i", "|": "l"})
_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))


@dataclass(frozen=True)
class Substitution:
    """One character that was replaced while canonicalising (for human-readable evidence)."""

    original: str
    replacement: str
    kind: str                      # homoglyph | digit | diacritic | leet | sequence

    def describe(self) -> str:
        if len(self.original) == 1:
            name = unicodedata.name(self.original, "UNKNOWN")
            return f"'{self.original}' (U+{ord(self.original):04X} {name}) looks like '{self.replacement}'"
        return f"'{self.original}' reads as '{self.replacement}'"


class Skeletonizer:
    """TR39-style skeleton using a given confusables table (the curated one, or one parsed from ``confusables.txt``)."""

    def __init__(self, table: dict[str, str]) -> None:
        self._table = table

    def _map(self, text: str) -> tuple[str, list[Substitution]]:
        out: list[str] = []
        steps: list[Substitution] = []
        for ch in unicodedata.normalize("NFKC", text).lower():
            proto = self._table.get(ch)
            if proto is not None:
                out.append(proto)
                if proto != ch:
                    steps.append(Substitution(ch, proto, "digit" if ch.isdigit() else "homoglyph"))
                continue
            decomposed = unicodedata.normalize("NFD", ch)
            base = "".join(c for c in decomposed if not unicodedata.combining(c))
            if base != ch:
                steps.append(Substitution(ch, base, "diacritic"))
                for b in base:                                  # a stripped base can itself be a confusable
                    out.append(self._table.get(b, b))
            else:
                out.append(ch)
        return "".join(out), steps

    def skeleton(self, text: str) -> str:
        return self._map(text)[0]


_DEFAULT = Skeletonizer(CURATED)


def skeleton(text: str) -> str:
    """Stage 1: the TR39-style skeleton of ``text`` (curated table)."""
    return _DEFAULT.skeleton(text)


def leet(text: str) -> str:
    """Stage 2: leetspeak digits/symbols → letters (``micr0s0ft`` → ``microsoft``)."""
    return text.translate(_LEET)


def fold_sequences(text: str) -> str:
    """Stage 3: letter pairs that look like one letter (``arnazon`` → ``amazon``)."""
    for pair, letter in _SEQUENCES:
        text = text.replace(pair, letter)
    return text


def canonical(text: str, skeletonizer: Optional[Skeletonizer] = None) -> tuple[str, list[Substitution]]:
    """All three stages, plus a record of every substitution made."""
    sk, steps = (skeletonizer or _DEFAULT)._map(text)
    leeted_chars: list[str] = []
    for ch in sk:
        repl = ch.translate(_LEET)
        if repl != ch:
            steps.append(Substitution(ch, repl, "leet"))
        leeted_chars.append(repl)
    leeted = "".join(leeted_chars)
    folded = fold_sequences(leeted)
    if folded != leeted:
        for pair, letter in _SEQUENCES:
            if pair in leeted:
                steps.append(Substitution(pair, letter, "sequence"))
    return folded, steps


def canonical_variants(text: str, limit: int = 8) -> list[str]:
    """Canonical forms under every reading of the ambiguous digit ``1`` (``l`` *or* ``i``): ``netfl1x`` → netflix.

    TR39 maps ``1`` to ``l`` only, which misses ``netfl1x``. Bounded (``limit``) — a label stuffed with ones does not
    blow up. The plain canonical form comes first.
    """
    folded = unicodedata.normalize("NFKC", text).lower()
    ones = [i for i, ch in enumerate(folded) if ch == "1"]
    base = canonical(text)[0]
    if not ones:
        return [base]
    seen = [base]
    for mask in range(1 << min(len(ones), 3)):
        chars = list(folded)
        for bit, pos in enumerate(ones[:3]):
            chars[pos] = "i" if mask >> bit & 1 else "l"
        if len(ones) > 3:                                   # more than three ones: all remaining read as 'l'
            for pos in ones[3:]:
                chars[pos] = "l"
        variant = canonical("".join(chars))[0]
        if variant not in seen:
            seen.append(variant)
        if len(seen) >= limit:
            break
    return seen


# ── IDN / scripts ───────────────────────────────────────────────────────────
def to_unicode(label: str) -> str:
    """Decode a punycode label (``xn--pypal-4ve`` → ``pаypal``); anything undecodable is returned unchanged."""
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return label


def scripts(text: str) -> set[str]:
    """The scripts of the *letters* in ``text`` (digits and hyphens are script-neutral)."""
    found: set[str] = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            if name:
                found.add(name.split(" ", 1)[0].title())
    return found


def is_mixed_script(text: str) -> bool:
    """More than one script among the letters — the signature of a homograph attack."""
    return len(scripts(text)) > 1


# ── TR39 file loader ────────────────────────────────────────────────────────
def load_confusables(path: Path | str) -> dict[str, str]:
    """Parse Unicode's ``confusables.txt`` (``MA`` entries) into ``{char: prototype}``; fall back to :data:`CURATED`."""
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
        table: dict[str, str] = {}
        for line in text.splitlines():
            body = line.split("#", 1)[0].strip()
            if not body:
                continue
            fields = [f.strip() for f in body.split(";")]
            if len(fields) < 3 or fields[2] != "MA":
                continue
            source = "".join(chr(int(h, 16)) for h in fields[0].split())
            target = "".join(chr(int(h, 16)) for h in fields[1].split()).lower()
            if len(source) == 1 and target:
                table[source.lower()] = target
        return table or CURATED
    except (OSError, UnicodeError, ValueError):
        return CURATED
