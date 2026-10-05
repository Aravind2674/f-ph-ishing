"""Regenerate (or check) ``ml/models/manifest.json`` — the SHA-256 integrity manifest.

    python -m ml.hash_models           # rewrite the manifest from the files on disk
    python -m ml.hash_models --check   # exit 1 if any file differs from the manifest

Run it after every (re)training and commit the manifest change together with the new
artifacts, so swapping a model is always a reviewable diff.  See
``backend/app/core/artifacts.py`` for how the application enforces it at load time.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make ``app`` importable when run as ``python -m ml.hash_models`` from threatfusion/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.core.artifacts import (  # noqa: E402
    MANIFEST_NAME,
    ArtifactManifest,
    is_runtime_artifact,
    sha256_file,
)

MODELS_DIR = Path(__file__).resolve().parent / "models"


def current_hashes() -> dict[str, str]:
    return {
        p.name: sha256_file(p)
        for p in sorted(MODELS_DIR.iterdir())
        if p.is_file() and is_runtime_artifact(p.name)
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify instead of writing")
    args = parser.parse_args()

    manifest_path = MODELS_DIR / MANIFEST_NAME
    actual = current_hashes()

    if args.check:
        expected = ArtifactManifest.load(manifest_path).files
        problems = [f"{n}: {'missing from manifest' if n not in expected else 'hash differs'}"
                    for n in actual if expected.get(n) != actual[n]]
        problems += [f"{n}: listed but file is missing" for n in expected if n not in actual]
        for line in problems:
            print("MISMATCH", line)
        print("manifest OK" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0

    manifest_path.write_text(ArtifactManifest(files=actual).to_json(), encoding="utf-8")
    print(f"wrote {manifest_path} ({len(actual)} artifacts)")
    for name, digest in actual.items():
        print(f"  {digest[:16]}…  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
