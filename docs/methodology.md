# Methodology (research plan)

> This is the living research document for Cartograph. It is intentionally started early (M0): the
> empirical evaluation is the part that distinguishes this project from a data-collection tool, so
> the methodology is designed *before* the features it measures. Sections marked **(TBD)** are filled
> in as the corresponding milestones land.

## 1. Research questions

- **RQ1 – Connectivity.** Does modeling the attack surface as a typed graph surface relationships
  (shared certificates, shared IP/ASN, shared registrant) that a flat subdomain list cannot express,
  and how many such relationships appear on real scopes?
- **RQ2 – Prioritization.** Does a transparent, feature-based exposure score concentrate objectively
  "interesting" assets (expired TLS, dangling records, dev/staging naming, wildcard exposure) near the
  top of the ranking better than an unordered list?
- **RQ3 – Reproducibility.** Given a fixed input snapshot, is the pipeline deterministic (run-to-run
  variance ~0), and how sensitive are results to each source (ablation)?

## 2. Data

- **Targets.** A sample of *public* bug-bounty scopes (programs whose recon is explicitly authorized)
  plus a small set of synthetic, self-owned targets used to validate detectors with ground truth.
  Real third-party domains are only added later and only within authorized scope.
- **Snapshotting.** Every collector caches its raw response (`.cache/`). The experiment runs against a
  *frozen snapshot*, not the live network, so results are reproducible and independent of API
  availability or rate limits at run time. **(TBD: publish snapshot manifest in M4.)**

## 3. Baseline

The baseline is the flat union of hostnames the same passive sources yield **without** the graph or
scoring layer – i.e. what a conventional "pipe subfinder into a list" workflow produces. Cartograph is
evaluated as the delta over this baseline.

## 4. Metrics

| Metric | What it captures | RQ |
|--------|------------------|----|
| Asset coverage / recall | Hosts found vs. the union across all sources | RQ1 |
| Relationship yield | # typed edges & takeover/cluster candidates invisible in a flat list | RQ1 |
| Signal-to-noise @k | Fraction of top-k scored assets that are objectively interesting | RQ2 |
| Ranking quality | Ordering of interesting assets vs. random/unordered baseline | RQ2 |
| Run-to-run variance | Determinism over a fixed snapshot (target: ~0) | RQ3 |
| Source ablation | Δ coverage / ranking when each source is removed | RQ3 |

"Objectively interesting" is defined by *documented, checkable* criteria (expired/soon-expiring TLS,
dangling CNAME, non-production naming, wildcard exposure) – never by subjective judgment. **(TBD:
finalize the criteria table in M2 alongside the scoring features.)**

## 5. Exposure scoring (to be specified in M2)

The score will be an explicit, documented function of per-node features. Design commitments:

- **No magic weights.** Every feature has a stated rationale and a bounded contribution; weights are
  reported and, where possible, calibrated against the ground-truth synthetic targets.
- **Auditability.** Each score is decomposable into its feature contributions in the output.
- **Ablatable.** Removing a feature is a supported experiment.

Candidate features (subject to revision): TLS validity/expiry, wildcard coverage, dangling-record
signals (passive), graph centrality / asset concentration, cross-source disagreement, non-production
naming patterns. **(TBD.)**

## 6. Experiment protocol (to be implemented in M4)

1. Freeze a dataset snapshot for the chosen targets.
2. Run baseline extraction and full Cartograph over the same snapshot.
3. Compute the metrics table; run source and feature ablations.
4. Repeat runs to confirm determinism.
5. Report results with plots; discuss threats to validity and limitations.

## 7. Threats to validity (running list)

- Public source coverage is uneven across targets; CT-heavy targets may look richer than they are.
- "Interesting" criteria are proxies for exploitability, not exploitability itself (by design – the
  tool is passive).
- Bug-bounty scopes change over time; snapshots mitigate but do not eliminate drift.

## 8. Ethics

All evaluation targets are authorized (public bug-bounty scope or self-owned). Only passive, public
data is used in the default pipeline. See the README "Ethics & legality" section and the scope-guard.
