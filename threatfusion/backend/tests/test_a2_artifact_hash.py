"""Model-artifact hashes must not depend on the checkout's line endings.

Found while checking whether the stack could be merged: the manifest had been computed on Windows, where the small JSON model files
are CRLF on disk, while git stores them with LF.  On the Linux CI runner 10 of the 13 hashed artifacts then differed from the
manifest, ``ml.hash_models --check`` failed and the loaders refused the models.  The hash of a ``.json`` artifact now ignores the line
ending; binary weights are still hashed byte for byte."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.core.artifacts import ArtifactManifest, MANIFEST_NAME, default_models_dir, sha256_file


def test_a_json_artifact_has_the_same_hash_with_lf_and_crlf(tmp_path: Path) -> None:
    lf, crlf = tmp_path / "a.json", tmp_path / "b.json"
    lf.write_bytes(b'{\n  "x": 1\n}\n')
    crlf.write_bytes(b'{\r\n  "x": 1\r\n}\r\n')
    assert sha256_file(lf) == sha256_file(crlf) == hashlib.sha256(b'{\n  "x": 1\n}\n').hexdigest()


def test_binary_weights_are_still_hashed_byte_for_byte(tmp_path: Path) -> None:
    for name in ("w.pt", "m.ubj"):
        f = tmp_path / name
        f.write_bytes(b"\x00ab\r\ncd\r\n\xff")
        assert sha256_file(f) == hashlib.sha256(b"\x00ab\r\ncd\r\n\xff").hexdigest()


def test_changing_a_json_value_still_changes_the_hash(tmp_path: Path) -> None:
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_bytes(b'{"x": 1}\n')
    b.write_bytes(b'{"x": 2}\n')
    assert sha256_file(a) != sha256_file(b), "tampering must still be detected"


def test_every_shipped_artifact_verifies_under_either_line_ending(tmp_path: Path) -> None:
    """The Linux-CI scenario: the same files checked out with LF (Linux) or CRLF (Windows autocrlf) must both match the manifest."""
    models = default_models_dir()
    manifest = ArtifactManifest.load(models / MANIFEST_NAME)
    checked = 0
    for name, expected in manifest.files.items():
        if not name.endswith(".json"):
            continue
        raw = (models / name).read_bytes().replace(b"\r\n", b"\n")
        for ending in (b"\n", b"\r\n"):
            f = tmp_path / f"{ending == b'\n'}_{name}"
            f.write_bytes(raw.replace(b"\n", ending))
            assert sha256_file(f) == expected, f"{name} with {'LF' if ending == b'\n' else 'CRLF'} endings does not match the manifest"
        checked += 1
    assert checked >= 5, "the manifest should cover the model configs, calibrations and cards"
