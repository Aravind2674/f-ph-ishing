"""A2-4 — payload normalisation, sliding windows and temperature in the HTTP attack classifier.

Acceptance: long padded inputs and comment-split inputs are classified the same as their plain forms.  (Before this change the
input was truncated at 256 characters — an attack padded past that was invisible — and only a single round of percent-decoding
was applied.)
"""

from __future__ import annotations

import pytest

from app.core.artifacts import model_path
from app.ml.payload_norm import normalize_payload, windows
from app.ml.vuln_classifier import VulnClassifier


@pytest.fixture(scope="module")
def clf() -> VulnClassifier:
    c = VulnClassifier()
    c.load(model_path("vuln_classifier.pt"))
    return c


# ── normalisation ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    ("%27%20OR%201%3D1--", "' OR 1=1--"),
    ("%2527%2520OR%25201%253D1--", "' OR 1=1--"),                         # double-encoded
    ("&lt;script&gt;alert(1)&lt;/script&gt;", "<script>alert(1)</script>"),   # HTML entities
    ("&#x3c;script&#62;", "<script>"),
    ("＜script＞alert(1)＜/script＞", "<script>alert(1)</script>"),   # full-width (NFKC)
    ("<scr​ipt>", "<script>"),                                       # zero-width space splitting a keyword
    ("'/**/OR/**/1=1--", "' OR 1=1--"),                                   # comments are whitespace
    ("SELECT/*!50000*/  1", "SELECT 1"),
    ("a\t\n  b", "a b"),
    ("", ""),
])
def test_normalisation(raw, expected) -> None:
    assert normalize_payload(raw) == expected


def test_normalisation_is_idempotent_and_never_raises() -> None:
    for raw in ["%2527%2520", "&amp;lt;", "plain", "\x00\x01", "é" * 50, "%", "&#xZZ;", None]:
        once = normalize_payload(raw)
        assert normalize_payload(once) == once


def test_decoding_is_bounded() -> None:
    nested = "%" + "25" * 30 + "27"
    assert len(normalize_payload(nested)) > 0, "a deliberately deep encoding must not loop forever"


# ── windows ─────────────────────────────────────────────────────────────────
def test_windows_cover_everything_and_include_the_tail() -> None:
    assert list(windows("short", 10, 5)) == ["short"]
    text = "".join(f"{i:04d}" for i in range(250))             # no repeated substring: index() is unambiguous
    ws = list(windows(text, 256, 128))
    assert all(len(w) <= 256 for w in ws) and ws[0] == text[:256] and ws[-1] == text[-256:]
    covered = set()
    for w in ws:
        start = text.index(w)
        covered.update(range(start, start + len(w)))
    assert covered == set(range(len(text)))
    with pytest.raises(ValueError):
        list(windows("x", 0, 1))


# ── classifier behaviour ────────────────────────────────────────────────────
def test_a_padded_attack_is_still_an_attack(clf) -> None:
    plain = clf.classify("' OR 1=1 UNION SELECT password FROM users--")
    assert plain["label"] == "sqli"
    padded = clf.classify("A" * 3000 + " ' OR 1=1 UNION SELECT password FROM users--")
    assert padded["label"] == plain["label"], "the attack fell outside the old 256-character window"
    assert padded["windows"] > 1
    leading = clf.classify("' OR 1=1 UNION SELECT password FROM users--" + " " * 3000)
    assert leading["label"] == "sqli"


@pytest.mark.parametrize("plain,variant", [
    ("' OR 1=1 UNION SELECT password FROM users--", "'/**/OR/**/1=1/**/UNION/**/SELECT/**/password/**/FROM/**/users--"),
    ("' OR 1=1 UNION SELECT password FROM users--", "%2527%2520OR%25201%253D1%2520UNION%2520SELECT%2520password%2520FROM%2520users--"),
    ("<script>alert(document.cookie)</script>", "&lt;script&gt;alert(document.cookie)&lt;/script&gt;"),
    ("<script>alert(document.cookie)</script>", "<scr​ipt>alert(document.cookie)</scr​ipt>"),
    ("../../../../etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
])
def test_obfuscated_forms_are_classified_like_the_plain_form(clf, plain, variant) -> None:
    assert clf.classify(variant)["label"] == clf.classify(plain)["label"] != "benign"


def test_benign_text_stays_benign_in_every_form(clf) -> None:
    for text in ["Barcelona", "john.smith@example.com", "2024-05-01", "The quick brown fox", "The quick brown fox jumps over the lazy dog. " * 60]:
        assert clf.classify(text)["label"] == "benign", text


def test_temperature_scaling_softens_the_confidence(clf) -> None:
    text = "' OR 1=1 UNION SELECT password FROM users--"
    cfg = clf._config
    base_t = cfg.temperature
    sharp = clf.classify(text)["confidence"]
    try:
        cfg.temperature = 4.0
        soft = clf.classify(text)["confidence"]
    finally:
        cfg.temperature = base_t
    assert soft < sharp and clf.classify(text)["confidence"] == pytest.approx(sharp)
    assert cfg.window_stride > 0


def test_a_piped_shell_command_is_not_benign(clf) -> None:
    """The audit's example: ``| whoami`` was classified benign."""
    for text in ["| whoami", "; whoami", "&& whoami", "|| id", "`id`", "$(whoami)", "; cat /etc/passwd", "| ls -la /"]:
        res = clf.classify(text)
        assert res["label"] != "benign", (text, res)


def test_the_shipped_metrics_report_held_out_per_class_recall() -> None:
    """The evaluation on corpora the model never saw is part of the artefact, and honest: no class is a perfect 1.0 there."""
    import json

    from app.core.artifacts import default_models_dir

    metrics = json.loads((default_models_dir() / "vuln_classifier_metrics.json").read_text(encoding="utf-8"))
    held = metrics["held_out"]["current_inference"]
    assert set(held["per_class"]) == {"sqli", "xss", "path-traversal", "cmdi"}
    for cls, row in held["per_class"].items():
        assert row["n"] >= 100, cls
        assert 0.0 <= row["recall_correct_class"] < 1.0, cls
    assert 0.0 <= held["benign"]["false_positive_rate"] < 0.05
    assert metrics["held_out"]["sets"]["overlap_removed"] > 0, "training overlap must be removed before measuring"
