"""B4 (confusables) — normalising look-alike characters the way Unicode TR39 "skeletons" do.

Phishing domains swap characters for ones that *look* the same: Cyrillic ``а`` for Latin ``a`` (``pаypal.com``), a
digit ``1`` for ``l`` (``paypa1``), ``rn`` for ``m`` (``arnazon``), a Greek omicron for ``o``.  Comparing a scanned label
to a brand therefore starts by reducing both to a *skeleton*: NFKC-fold, strip diacritics, then map every confusable
character to its prototype.  The mapping here is a curated subset of the Unicode TR39 ``confusables.txt`` covering the
Latin / Cyrillic / Greek / small-capital look-alikes seen in practice; the real file can be loaded instead
(``load_confusables``) when it is available.
"""

from __future__ import annotations

import pytest

from app.ml import confusables as cf


# ── skeleton: TR39-style character mapping ──────────────────────────────────
@pytest.mark.parametrize("text,expected", [
    ("paypal", "paypal"),
    ("PayPal", "paypal"),                                  # case-folded
    ("pаypal", "paypal"),                             # Cyrillic а
    ("paуpal", "paypal"),                             # Cyrillic у (looks like y)
    ("gооgle", "google"),                        # Cyrillic о о
    ("gοοgle", "google"),                        # Greek omicron
    ("ѕbі", "sbi"),                              # Cyrillic ѕ, і
    ("сitibank", "citibank"),                         # Cyrillic с
    ("amazоn", "amazon"),
    ("paypa1", "paypal"),                                  # TR39: digit one is a confusable of l
    ("g00gle", "google"),                                  # digit zero is a confusable of o
    ("ｐａｙｐａｌ", "paypal"),    # fullwidth (NFKC)
    ("pàypál", "paypal"),                        # diacritics stripped
    ("ᴘᴀʏᴘᴀʟ", "paypal"),    # small capitals ᴘᴀʏᴘᴀʟ
    ("ıciı", "icii"),                           # dotless ı -> i
])
def test_skeleton_maps_confusables_to_their_prototypes(text, expected) -> None:
    assert cf.skeleton(text) == expected


def test_skeleton_is_idempotent_and_leaves_plain_ascii_alone() -> None:
    for text in ["paypal", "hdfc-bank", "irctc", "a1b2", "xn--"]:
        once = cf.skeleton(text)
        assert cf.skeleton(once) == once
    assert cf.skeleton("example-site") == "example-site"


def test_skeleton_never_raises_on_junk() -> None:
    for text in ["", "\u0000", "‮‭", "😀domain", "a" * 500, "퟿"]:
        assert isinstance(cf.skeleton(text), str)


# ── leetspeak and sequence folding (a second, separately-reported stage) ────
@pytest.mark.parametrize("text,expected", [
    ("micr0s0ft", "microsoft"), ("faceb00k", "facebook"), ("amaz0n", "amazon"),
    ("p4ypal", "paypal"), ("sb1", "sbl"), ("g00gle", "google"), ("wh4tsapp", "whatsapp"),
    ("paypa|", "paypal"), ("p@ypal", "paypal"), ("5team", "steam"), ("7witter", "twitter"),
])
def test_leet_normalisation(text, expected) -> None:
    assert cf.leet(text) == expected


@pytest.mark.parametrize("text,expected", [
    ("arnazon", "amazon"), ("rnicrosoft", "microsoft"), ("vvhatsapp", "whatsapp"), ("clroplbox", "droplbox"),
    ("paypal", "paypal"),
])
def test_sequences_that_look_like_one_letter_are_folded(text, expected) -> None:
    assert cf.fold_sequences(text) == expected


def test_the_digit_one_can_stand_for_l_or_i_so_both_readings_are_tried() -> None:
    """``netfl1x`` is Netflix (1 = i); ``paypa1`` is PayPal (1 = l). A single mapping cannot get both right."""
    assert "netflix" in cf.canonical_variants("netfl1x")
    assert "paypal" in cf.canonical_variants("paypa1")
    assert cf.canonical_variants("paypal") == ["paypal"], "no ambiguity, one form"
    assert len(cf.canonical_variants("1" * 12)) <= 8, "bounded: never exponential"


def test_canonical_form_combines_the_stages_and_reports_what_it_changed() -> None:
    canon, steps = cf.canonical("pаypa1")
    assert canon == "paypal"
    kinds = {s.kind for s in steps}
    assert "homoglyph" in kinds and {s.original for s in steps} >= {"а"}
    canon2, steps2 = cf.canonical("paypa1")
    assert canon2 == "paypal" and steps2, "digit-for-letter is reported as a substitution"
    canon3, steps3 = cf.canonical("paypal")
    assert canon3 == "paypal" and steps3 == []


def test_substitutions_carry_human_readable_evidence() -> None:
    _, steps = cf.canonical("pаypal")
    text = steps[0].describe()
    assert "U+0430" in text and "CYRILLIC" in text and "'a'" in text


# ── IDN / punycode ──────────────────────────────────────────────────────────
def test_punycode_labels_are_decoded_before_comparison() -> None:
    assert cf.to_unicode("xn--pypal-4ve") == "pаypal"          # pаypal (Cyrillic а)
    assert cf.to_unicode("xn--bcher-kva") == "bücher"
    assert cf.to_unicode("example") == "example"
    assert cf.to_unicode("xn--") == "xn--", "an undecodable label is returned unchanged, never raises"
    assert cf.skeleton(cf.to_unicode("xn--pypal-4ve")) == "paypal"


def test_mixed_script_labels_are_flagged() -> None:
    assert cf.scripts("pаypal") == {"Latin", "Cyrillic"}
    assert cf.is_mixed_script("pаypal") is True
    assert cf.is_mixed_script("paypal") is False
    assert cf.is_mixed_script("пример") is False, "a purely Cyrillic label is not mixed"
    assert cf.is_mixed_script("paypal-123") is False, "digits and hyphens are script-neutral"


# ── TR39 file loader ────────────────────────────────────────────────────────
def test_the_real_tr39_confusables_file_can_be_loaded(tmp_path) -> None:
    sample = tmp_path / "confusables.txt"
    sample.write_text(
        "﻿# confusables.txt sample\n"
        "0430 ;\t0061 ;\tMA\t# ( а → a ) CYRILLIC SMALL LETTER A → LATIN SMALL LETTER A\n"
        "043E ;\t006F ;\tMA\t# ( о → o ) CYRILLIC SMALL LETTER O → LATIN SMALL LETTER O\n"
        "04CF ;\t006C ;\tMA\t# ( ӏ → l )\n"
        "0031 ;\t006C ;\tMA\t# ( 1 → l )\n"
        "FB01 ;\t0066 0069 ;\tMA\t# ( ﬁ → fi ) multi-character prototype\n"
        "\n# comment only\n",
        encoding="utf-8")
    table = cf.load_confusables(sample)
    assert table["а"] == "a" and table["о"] == "o" and table["1"] == "l" and table["ﬁ"] == "fi"
    mapper = cf.Skeletonizer(table)
    assert mapper.skeleton("pаypаl") == "paypal" and mapper.skeleton("fﬁ") == "ffi"


def test_a_missing_or_corrupt_file_falls_back_to_the_curated_table(tmp_path) -> None:
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"\xff\xfe\x00not a confusables file")
    assert cf.load_confusables(tmp_path / "missing.txt") == cf.CURATED
    assert cf.load_confusables(bad) == cf.CURATED
    assert cf.CURATED["а"] == "a" and len(cf.CURATED) > 60
