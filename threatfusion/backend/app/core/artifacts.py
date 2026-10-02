"""
Model-artifact integrity checks (SHA-256 manifest)
===================================================

Why this exists
---------------
The audit (AUDIT_REPORT.md §H7) noted that ``.pt`` checkpoints and the XGBoost JSON
are loaded straight from disk and scored without any proof they are the files the
authors trained.  A swapped, truncated or tampered artifact would be used silently —
and a ``.pt`` file is a pickle container, i.e. a code-execution vector if untrusted.

Design
------
* ``ml/models/manifest.json`` records the SHA-256 of every runtime artifact (weights
  *and* their ``*_config.json`` — the config carries the vocabulary and any
  normalisation constants, so tampering with it changes predictions just as much).
* Every loader calls :func:`verify_artifact` **before** reading the file.  A hash
  mismatch always refuses to load.  A file that is not listed is refused too in
  strict mode (the default), so a stray model dropped next to the real ones cannot
  be picked up by accident.
* After (re)training, regenerate the manifest with ``python -m ml.hash_models`` and
  review the diff — updating it is a deliberate, visible act in the commit.

This is an *integrity* control (detects change), not authenticity (who signed it).
Signing is a later step if artifacts ever ship outside the repo.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"
MANIFEST_SCHEMA_VERSION = 1

# Which files in ``ml/models`` are *runtime* artifacts (hashed + verified) as opposed to
# human-readable reports (``*_metrics.json``) that the app never loads.
_ARTIFACT_SUFFIXES = (".pt", ".pth")
_ARTIFACT_NAME_FRAGMENTS = ("_config.json", "fusion_model")


class ArtifactIntegrityError(RuntimeError):
    """A model artifact is missing from, or does not match, the SHA-256 manifest."""


def is_runtime_artifact(name: str) -> bool:
    """True for files the application loads (weights, configs, XGBoost JSON)."""
    if name == MANIFEST_NAME or name.endswith("_metrics.json") or name.endswith(".card.json"):
        return False
    return name.endswith(_ARTIFACT_SUFFIXES) or any(f in name for f in _ARTIFACT_NAME_FRAGMENTS)


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """Hex SHA-256 of a file, read in chunks (model files can be large)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class ArtifactManifest:
    """In-memory view of ``manifest.json``."""

    files: dict[str, str] = field(default_factory=dict)
    algorithm: str = "sha256"
    schema_version: int = MANIFEST_SCHEMA_VERSION

    @classmethod
    def load(cls, path: Path) -> "ArtifactManifest":
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ArtifactIntegrityError(
                f"model manifest not found at {path}; generate it with `python -m ml.hash_models`"
            ) from exc
        except (OSError, ValueError) as exc:
            raise ArtifactIntegrityError(f"model manifest at {path} is unreadable: {exc}") from exc
        if raw.get("algorithm") != "sha256" or not isinstance(raw.get("files"), dict):
            raise ArtifactIntegrityError(f"model manifest at {path} has an unsupported format")
        return cls(files=dict(raw["files"]), algorithm=raw["algorithm"],
                   schema_version=int(raw.get("schema_version", 0)))

    def to_json(self) -> str:
        return json.dumps(
            {"schema_version": self.schema_version, "algorithm": self.algorithm,
             "files": dict(sorted(self.files.items()))},
            indent=2,
        ) + "\n"


def _strict_default() -> bool:
    try:
        from app.core.config import get_settings

        return bool(get_settings().MODEL_HASH_STRICT)
    except Exception:  # config unavailable (e.g. offline tooling) — fail closed
        return True


def verify_artifact(path: Path | str, *, strict: Optional[bool] = None) -> None:
    """Raise :class:`ArtifactIntegrityError` unless ``path`` matches the manifest.

    Looks for ``manifest.json`` next to the artifact.  ``strict`` (default: the
    ``MODEL_HASH_STRICT`` setting, True) also refuses files the manifest does not list.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Model file not found at {path}")
    strict = _strict_default() if strict is None else strict

    manifest = ArtifactManifest.load(path.parent / MANIFEST_NAME)
    expected = manifest.files.get(path.name)
    if expected is None:
        msg = (f"{path.name} is not listed in {MANIFEST_NAME}; if this is a freshly trained "
               f"model run `python -m ml.hash_models` and commit the new manifest")
        if strict:
            raise ArtifactIntegrityError(msg)
        logger.warning("%s (continuing: MODEL_HASH_STRICT=false)", msg)
        return

    actual = sha256_file(path)
    if actual != expected:
        raise ArtifactIntegrityError(
            f"sha256 mismatch for {path.name}: manifest {expected[:12]}…, file {actual[:12]}… "
            f"— refusing to load a modified model artifact"
        )
    logger.debug("Artifact %s verified (sha256 %s…)", path.name, actual[:12])
