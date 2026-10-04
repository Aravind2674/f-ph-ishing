"""
Export reviewed feedback for retraining (B20)
=============================================

``python -m ml.feedback_export [--out feedback_accepted.jsonl]``

Feedback reports enter the database as ``pending`` and can only become usable after a person **accepts** them
(``POST /feedback/{id}/review``).  This exporter writes *accepted* reports only — never pending or rejected ones — one JSON object
per line with the provenance needed to audit it later (when it was reported, from where, what the verdict was, who reviewed it).
The result is an input to the A2-1 pipeline's labelling step, never a shortcut around its leakage controls: a feedback label is
one more *source*, evaluated with the same time-ordered, host-disjoint protocol, and the model card records that it was used.

Label mapping: ``false_positive`` / ``confirm_benign`` → benign (0); ``false_negative`` / ``confirm_malicious`` → malicious (1).
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Iterator, Optional

LABEL = {"false_positive": 0, "confirm_benign": 0, "false_negative": 1, "confirm_malicious": 1}


def accepted(db_path: Path) -> Iterator[dict]:
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        for row in con.execute("SELECT * FROM feedback WHERE status = 'accepted' ORDER BY created_at"):
            yield {
                "id": row["id"], "target": row["target"], "target_type": row["target_type"], "label": LABEL[row["label"]],
                "reported_as": row["label"], "reported_at": row["created_at"], "source": row["source"], "scan_id": row["scan_id"],
                "verdict_snapshot": json.loads(row["verdict_snapshot"]) if row["verdict_snapshot"] else None,
                "model_versions": json.loads(row["model_versions"]) if row["model_versions"] else None,
                "reviewed_at": row["reviewed_at"], "reviewer": row["reviewer"], "review_note": row["review_note"],
            }
    finally:
        con.close()


def export(db_path: Path, out: Path) -> int:
    n = 0
    with open(out, "w", encoding="utf-8") as f:
        for item in accepted(db_path):
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
            n += 1
    return n


def main(argv: Optional[list[str]] = None) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
    from app.core.config import get_settings

    p = argparse.ArgumentParser(prog="python -m ml.feedback_export")
    p.add_argument("--db", default=None, help="database path (default: the configured one)")
    p.add_argument("--out", default="feedback_accepted.jsonl")
    args = p.parse_args(argv)
    db = Path(args.db) if args.db else get_settings().database_path
    print(f"exported {export(db, Path(args.out))} accepted report(s) to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
