# Phase A2 — the ML pipeline is real and measured (A2-1 … A2-6, B7, B9, part of B10)

Branch `a2-ml-validation` (stacked on `b-intel-exposure` → `a1-enrichment` → `a0-remediation`). Single commit.

## Why
The audit (`AUDIT_REPORT.md` §E) found that the models behind the headline were trained on **synthetic data with 15 % label
noise**, the deployed XGBoost actually used **3 provider features**, the neural URL model's tabular branch was trained on a
**constant vector**, a prepended `https://` moved a score from **0.13 to 0.99**, a static allow-list silently capped popular
domains at 0.15, the payload classifier truncated to 256 characters, and every reported metric came from a random split of one
corpus. This phase deletes those models and replaces them with ones whose numbers can be reproduced and whose limits are stated.

## What changed
| | Change | Where |
|---|---|---|
| A2-1 | URL-maliciousness models retrained on **real data**: PhreshPhish (CC-BY-4.0), 654,382 URLs, 2024-07 → 2025-12, metadata columns only (no page is visited, no HTML downloaded). **Time-ordered, host-disjoint** splits; tuned on validation, **tested once**; cluster-bootstrap 95 % CIs; the a-priori baseline evaluated under the identical protocol. One command: `python -m ml.evaluate --report` | `ml/collect.py`, `dataset.py`, `metrics.py`, `train_url_xgb.py`, `train_url_cnn.py`, `evaluate.py` |
| A2-2 | Model-health regression tests that **fail on the audited model** (output variance over a feature grid, features actually used, schema-version match, monotone sanity via `monotone_constraints`, scheme / `www` invariance ≤ 0.02, SHAP additivity) | `tests/test_a2_model_health.py` |
| A2-3 | URL CNN: dead tabular branch removed; **one canonical URL form** at training and serving time; calibrated; no hidden allow-list cap | `app/ml/url_canon.py`, `url_cnn.py` |
| A2-4 | Payload classifier: iterated URL/HTML decoding + NFKC + comment / zero-width stripping; **sliding windows with max-pooling** (no truncation); temperature scaling; retrained with adversarial augmentation and evaluated on corpora it never saw | `app/ml/payload_norm.py`, `vuln_classifier.py`, `ml/train_vuln.py`, `ml/payload_*.py` |
| A2-5 | Explanations: **exact TreeSHAP** (`pred_contribs`), the unit stated (log-odds) and a probability what-if per feature, additivity asserted by a test, nothing rebuilt per request | `app/ml/url_risk.py` |
| A2-6 | Model cards (`ml/models/*.card.json`: data sources + hashes, date range, feature schema, metrics with CIs, limitations), hashed in the manifest, loaded at start-up and summarised in `/health`; a **schema mismatch disables the model** | `app/ml/model_cards.py`, `app/core/artifacts.py` |
| B7 | Calibration (isotonic / Platt) + stacked logistic fusion with missingness flags; noisy-OR and mean compared under simulated outages | `app/ml/calibration.py`, `fusion.py` |
| B9 | Per-month decay + AUT, base-rate precision, permutation importance by feature and group, cheap-evasion robustness, adversarial training | `ml/evaluate.py` |

API/schema changes are **additive**: `ScanResult.url_risk` (channels, flag, threshold basis, prevalence what-ifs, baseline rules,
model version), `ml_status`, `RiskExplanation.unit / probability_delta / group`. `ml_score` / `ml_label` / `neural_score` now come
from the new models; IP and hash targets are `not_applicable` (a URL model has nothing to read).

## Results (test period 2025-09-08 → 2025-12-16, hosts disjoint from training; operating point FPR ≤ 1 % on validation)
| model | PR-AUC | ROC-AUC | recall @ FPR ≤ 1 % | ECE |
|---|---|---|---|---|
| a-priori lexical baseline | 0.824 [0.815, 0.832] | 0.789 | 0.069 | 0.078 |
| tree model (39 URL features) | 0.927 [0.920, 0.933] | 0.899 | 0.460 | 0.077 |
| character CNN | 0.960 [0.954, 0.965] | 0.942 | 0.652 | 0.045 |
| stacked fusion (B7) | 0.969 [0.964, 0.973] | 0.949 | 0.699 | 0.032 |

Full tables (with CIs), per-month decay, calibration plots, permutation importance, fusion under outages and the B4 real-data
check are in `threatfusion/ml/results/report.md`. **No metric equals 1.0; 25 of 39 features carry a meaningful permutation
importance** (acceptance: ≥ 8).

## What the numbers do *not* say (read before trusting a score)
- The benchmark is ~45 % phishing; at a realistic 0.1 % prevalence even the best channel's precision is **≈ 9 %** (derived table in the
  report). The UI states this next to the score.
- Recall at a 1 % false-positive rate is **0.46 – 0.70**, and it **decays**: the tree model's recall was 0.25 in the first test month and
  0.56 in the third (the models are fitted on older data). URL text is one weak-to-moderate signal.
- **Cheap evasions work.** A benign-looking path prefix cuts the CNN's recall from 0.65 to **0.07** (tree 0.46 → 0.15), even after adversarial
  training against *other* prefixes; padding the path also hurts. Appending a query string *raises* recall to 0.94–0.98 — a dataset artefact
  (the crawl's phishing URLs carry queries more often), i.e. a false-positive risk on real sites with query strings. Top features
  (`tld_is_common`, `query_len`) show how much of the signal is the crawl's shape. This is why the URL score is *one channel*, never the verdict.
- False-positive rate on 1,311 real benign login / checkout / account URLs: 0.3 % (baseline), 0.6 % (tree), 1.1 % (CNN), **1.8 % (fusion)** —
  above the 1 % target for the fusion on that hard subset. Documented, not tuned away.
- B4 look-alike detection on real data: **false-positive rate 0.07 %** on benign URLs and, when it flags, the named brand equals the labelled target 93 % of the time, but **recall is only 3.5 %** of brand-targeting phishing (most is on
  free hosting / generated sub-domains, which a look-alike *domain* detector cannot see by design).
- Payload classifier, held-out PayloadsAllTheThings (training overlap removed), correct-class recall: sqli 0.994 (n=783), path-traversal 0.982
  (n=1,500), **xss 0.635** (n=441; not-benign rate 0.69 — most misses are scored as another attack class), cmdi 0.85 (**n=100, optimistic**).
  The first evaluation showed cmdi at **0.14**: its only varied real training data was one templated `echo` list. Fix, chosen *after* seeing that
  number (so disclose it): 3/4 of the PayloadsAllTheThings command-injection lines (by hash) now train the model, 1/4 stays held-out, and lines of
  lone punctuation (`|`, `` ` ``) are no longer counted as examples. Those lines are variations of a few templates, so the new cmdi figure is an
  upper bound. Benign false-positive rate 0.52 % on 6,000 held-out real benign strings; held-out obfuscation families score 0.90 – 1.00 not-benign;
  in-distribution accuracy 99.6 % is an upper bound, not an estimate. The audit's `| whoami` is now `cmdi` (0.99; a bare `whoami` is still benign).
- **Not done, on purpose:** RDAP / DNS / TLS / CT / reputation as *training* features. Collecting them means one live lookup per URL against
  third parties (and a connection to the phishing host for TLS); the deployed headline stays the transparent provider-based baseline.
  `ml/collect.py` documents the plan.

## Verification
- Run on a **clean checkout of this commit** (a separate worktree, so nothing from later work can leak in): `pytest` **1153 passed, 1 skipped**;
  frontend `npm test` 70 passed, `tsc --noEmit` (app + test projects) clean, `oxlint` 0 errors (2 pre-existing warnings).
- Tests that need the shipped models read `ml/models` and the manifest (`ml.hash_models --check` runs in CI).
- Public data used: PhreshPhish (CC-BY-4.0; attribution in `ml/models/*.card.json`), SecLists (MIT), Morzeux HttpParamsDataset, PayloadsAllTheThings
  (evaluation only). Raw and processed data are git-ignored; `ml/data/raw/phreshphish/MANIFEST.json` and `ml/data/processed/PROVENANCE.json` record hashes.
- Windows real-time protection blocks a few attack-payload files (EINVAL on read): the loader skips them and records `unreadable` in the manifest.
  The antivirus was not touched.

## Needs a decision / action from you
- Review the deletion of the audited models, their training scripts and `top_domains.txt` (all in git history).
- `requirements-ml.txt` now pins `pyarrow` (HTTP range reads of the Parquet metadata) — dev/training only; the API image does not need it.
- Approve (or not) a later phase that collects page / DNS / TLS features at scale; it is the main lever on the evasion weakness.

## Acceptance checklist
- [x] A2-1 no metric = 1.0; ≥ 8 features matter; `python -m ml.evaluate --report` regenerates the table
- [x] A2-2 health tests fail on the old model (variance, features used, schema, monotone)
- [x] A2-3 scheme-invariance ≤ 0.02; FPR on benign login pages documented
- [x] A2-4 padded / comment-split inputs classify like plain; `| whoami` is not benign; held-out per-class recall reported
- [x] A2-5 additivity test (contributions + base = margin); units stated
- [x] A2-6 model cards loaded, hashed, shown in `/health`; schema mismatch disables the model
- [x] Docs updated: ROADMAP, ARCHITECTURE, AI_CONTEXT §18

🤖 Generated with [Claude Code](https://claude.com/claude-code)
