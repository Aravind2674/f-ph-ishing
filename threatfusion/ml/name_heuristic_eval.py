"""
How often does the "random-looking name" heuristic fire on real host names?  (revamp T2c)

``python -m ml.name_heuristic_eval``  (from ``threatfusion/``, after ``python -m ml.dataset build``)

The network layer flags a DNS name whose label is very long, or long *and* high in entropy (``app/network/heuristics.name_anomaly``).  A
detector like that is only worth an alert if its false-positive rate is known, so this measures it on the real host names in the
processed PhreshPhish data (unique hosts; benign = label 0, phishing = label 1) for a grid of thresholds, and prints the table that is
quoted in ``docs/REVAMP.md``.

What the numbers are, and are not: *hosts of web pages a crawler visited*, not the names a device queries over a day; and the benign
set includes popular sites that the live pipeline would skip (Tranco) before this heuristic ever runs, so the live false-positive rate on
the names that reach it is lower than the benign column — by an amount this script cannot measure.  Nothing is fitted: the thresholds
below are the ones compared, and the shipped defaults are the most conservative row.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.network.heuristics import name_anomaly  # noqa: E402

DATA = Path(__file__).resolve().parent / "data" / "processed" / "urls_v1.parquet"
GRID = [(12, 3.4), (12, 3.5), (12, 3.6), (14, 3.5), (14, 3.7), (16, 3.8)]


def host_of(canon: str) -> str:
    return canon.split("/")[0].split("@")[-1].split(":")[0].lower()


def flagged_share(hosts: pd.DataFrame, **kw) -> float:
    n = sum(1 for host, dom in zip(hosts["host"], hosts["domain"]) if name_anomaly(host, (dom or host).split(".")[0], **kw))
    return n / max(len(hosts), 1)


def main() -> None:
    df = pd.read_parquet(DATA, columns=["canon", "label", "domain"])
    df["host"] = df["canon"].map(host_of)
    hosts = df.drop_duplicates("host")[["host", "domain", "label"]]
    hosts = hosts[~hosts["host"].str.match(r"^\d+\.\d+\.\d+\.\d+$")]
    benign, phishing = hosts[hosts.label == 0], hosts[hosts.label == 1]
    print(f"unique hosts: {len(hosts):,} (benign {len(benign):,}, phishing {len(phishing):,})\n")
    print(f"{'label min length':>16} {'min bits/char':>14} {'benign flagged':>15} {'phishing flagged':>17}")
    for min_len, bits in GRID:
        kw = dict(min_len=min_len, min_entropy=bits)
        print(f"{min_len:>16} {bits:>14} {flagged_share(benign, **kw):>15.2%} {flagged_share(phishing, **kw):>17.2%}")
    kw = dict(min_len=10**9, min_entropy=99.0)                      # only the "very long label / very long name" rules
    print(f"\nlong-label (>= 40 chars) and long-name (>= 100 chars) rules alone: benign {flagged_share(benign, **kw):.2%}, "
          f"phishing {flagged_share(phishing, **kw):.2%}")


if __name__ == "__main__":
    main()
