# M2 Design – Exposure Scoring & Graph Analytics

**Status:** DRAFT – awaiting sign-off. No M2 code is written until this is approved.
**Demo target for the M2 experiment:** `shopify.com` (public bug-bounty program; passive collection only).
**Depends on:** M0 (graph model) + M1 (collectors/enrichers). **Feeds:** M4 (empirical evaluation).

---

## 1. Purpose

M0–M1 build a connected attack-surface graph. M2 makes it *actionable* by answering two questions the
graph implicitly contains but doesn't yet surface:

1. **Which assets deserve attention first?** → a transparent, decomposable **exposure score** per asset.
2. **What structure does the surface have?** → **graph analytics**: risk-concentration nodes, clusters,
   subdomain-takeover candidates, and change-over-time diffs.

This is the milestone that separates Cartograph from a data-collection tool. The scoring model is
therefore designed to be *defensible* (every signal justified), *auditable* (score decomposes into
contributions), and *ablatable* (each signal can be removed and measured in M4).

---

## 2. Exposure scoring model

### 2.1 Design commitments

- **Feature-based, not a black box.** Score = a bounded aggregation of named per-node features.
- **No magic weights.** Each weight has a written rationale and a *bounded* contribution, so no single
  feature can dominate by accident. Defaults are expert-set and reported; M4 calibrates them against
  synthetic ground-truth targets.
- **Decomposable.** Every asset's score carries a per-feature breakdown in the output (`score_contributions`).
- **Passive-only signals.** Every feature is computable from data already in the graph (CT, RDAP,
  Wayback, passive DNS, ASN). Nothing here probes the target.
- **A prioritization heuristic, not an exploitability proof.** A high score means "look here first,"
  not "this is vulnerable." This framing is stated in the output and docs.

### 2.2 What gets scored

Primarily **hosts** (`domain`, `subdomain`) – the assets an analyst triages. `certificate`, `ip`, `asn`,
`org`, `endpoint` nodes are *feature inputs*, not scored entities (v1).

### 2.3 Feature catalog

Each feature returns a normalized sub-score in `[0, 1]`; the aggregator applies a documented weight.
"Signal" = why it correlates with exposure/interest.

| # | Feature | Signal (rationale) | Passive source | Notes |
|---|---------|--------------------|----------------|-------|
| F1 | **TLS expired / expiring** | Expired or soon-to-expire certs flag unmaintained or forgotten hosts. | CT `not_after` | Graded: already expired = 1.0; <30d = 0.6; <90d = 0.3; else 0. |
| F2 | **Wildcard exposure** | Wildcard certs (`*.x`) broaden blast radius and often front many hosts. | CT `is_wildcard` | Host covered only by a wildcard = higher. |
| F3 | **Dangling / takeover-prone CNAME** | A host CNAME'd to a takeover-prone provider is a classic subdomain-takeover risk. | pDNS `external_cnames` + fingerprint list | Passive heuristic only; see §3.3. |
| F4 | **Asset concentration (centrality)** | Hosts that bridge clusters or sit on shared certs/IPs concentrate risk. | graph structure | Normalized degree/betweenness on shared-cert & shared-IP subgraph. |
| F5 | **Non-production naming** | `dev/staging/test/uat/qa/internal/admin` hosts are more likely weakly protected. | hostname regex | Curated, documented pattern list. |
| F6 | **Cross-source orphan / staleness** | A host in CT that never resolves (no A/AAAA in pDNS) may be stale/decommissioned – or a takeover setup. | provenance + resolves_to absence | Only counts when pDNS actually ran. |
| F7 | **Off-primary-ASN hosting** | A host resolving into an ASN other than the org's dominant ASN can be shadow IT / third-party. | ASN distribution | Dominant ASN inferred from the graph; outliers score up. |

Feature set is intentionally small and explainable for v1. New features are cheap to add (each is a pure
function) and each is ablatable in M4.

### 2.4 Aggregation

```
raw(node)      = Σ_i  weight_i * feature_i(node)          # weights documented in scoring/weights.py
exposure(node) = 100 * raw(node) / Σ_i weight_i           # normalized to 0–100, bounded
```

- Weights live in one documented module with rationale comments; no inline literals scattered in code.
- Because each `feature_i ∈ [0,1]` and weights are fixed, contributions are directly comparable and the
  score is bounded and stable.
- Output per node: `exposure` (0–100) + `score_contributions: {feature: contribution}` + human-readable
  `reasons` (top contributing features as text).

### 2.5 Calibration (defined now, executed in M4)

Default weights are expert-set. In M4 we calibrate against **synthetic, self-owned ground-truth targets**
where we know which hosts are "interesting" (we plant an expired cert, a dangling CNAME, a dev host), and
tune weights to rank them highly – then report the weights and the sensitivity. No tuning on the demo
target (that would be circular).

---

## 3. Graph analytics

### 3.1 Centrality (`analysis/centrality.py`)
Degree and betweenness centrality over the graph (and over the shared-cert / shared-IP projection) to
find **risk-concentration nodes** and **bridges** between segments. Feeds F4 and the report.

### 3.2 Clustering (`analysis/clusters.py`)
Connected components / community detection on the shared-certificate and shared-IP subgraphs to group
assets that rise and fall together (same cert, same host). Answers "what belongs to the same thing?"

### 3.3 Subdomain-takeover candidates (`analysis/takeover.py`)
**Passive heuristic, not exploitation.** Flags a host when its CNAME target matches a curated fingerprint
list of takeover-prone services (e.g. unclaimed cloud/SaaS endpoints) OR when a host resolves nowhere but
still has a dangling CNAME. Output is a *candidate list* with the reason and an explicit
"verify manually / with authorization" note. Active confirmation is out of scope here (belongs to the
opt-in M6 active module, behind the scope-guard).

### 3.4 Snapshot diff (`analysis/diff.py`)
Given two saved graphs (e.g. weekly snapshots), report added/removed nodes and edges – new subdomains,
disappeared hosts, cert changes. Enables monitoring narratives and is trivially deterministic.

---

## 4. Architecture

```
cartograph/
├── scoring/
│   ├── features.py     # pure per-node feature functions F1..F7 (each returns [0,1] + detail)
│   ├── weights.py      # documented default weights + rationale
│   ├── model.py        # aggregator, ExposureScore result, decomposition
│   └── __init__.py
├── analysis/
│   ├── centrality.py   # degree/betweenness
│   ├── clusters.py     # components / communities on shared-cert & shared-IP subgraphs
│   ├── takeover.py     # passive takeover-candidate heuristic + fingerprint list
│   ├── diff.py         # snapshot diff
│   └── __init__.py
experiments/
└── shopify/            # M4 will live here; M2 provides a `score` run over the demo target
```

**Integration.** A scoring pass runs after enrichment in `run_pipeline` (optional, flag-gated). Scores and
contributions are written onto node attributes in the graph JSON. Analytics are exposed via CLI.

**CLI additions.**
- `cartograph collect ... --score` → also compute exposure; summary prints **Top-N assets by exposure**
  with their top reasons.
- `cartograph score <graph.json>` → (re)score a saved graph.
- `cartograph analyze <graph.json> [--takeover] [--clusters] [--centrality]` → run analytics.
- `cartograph diff <old.json> <new.json>` → snapshot diff.

**Determinism.** Feature functions are pure; centrality uses fixed algorithms; ordering is stable. A
scored graph over a fixed snapshot is reproducible (extends the M1 determinism test).

---

## 5. Output (what the analyst sees)

- **Ranked table**: asset · exposure(0–100) · top reasons (e.g. "expired TLS; dev naming; off-ASN").
- **Graph JSON**: each host node gains `exposure` and `score_contributions`.
- **Analytics**: takeover-candidate list, cluster summary, centrality top-N, or diff – per command.

Example (illustrative):
```
Top exposed assets (shopify.com)
  92  staging-api.<...>     expired TLS (0.42), dev naming (0.30), off-ASN (0.20)
  78  <...>.<...>           dangling CNAME → takeover-prone (0.55), wildcard (0.23)
  ...
```

---

## 6. Testing

- Unit test **each feature** with crafted fixtures (expired vs valid cert, wildcard, dev names,
  external CNAME, orphan host, off-ASN) – pure functions, no network.
- Test the **aggregator**: bounded output, correct decomposition, weight ablation changes ranking.
- Test **analytics**: takeover heuristic on synthetic dangling CNAME; diff on two toy graphs; centrality
  on a known small graph.
- Extend the end-to-end determinism test to include scoring.

Target: keep the strict-mypy + ruff + pytest gate green.

---

## 7. Non-goals (v1 of M2)

- **No ML.** Scoring is transparent/feature-based by design; ML prioritization is a later, separate track
  (the current features become its inputs).
- **No active verification.** Takeover candidates are flagged, never confirmed by touching the target.
- **Score ≠ vulnerability.** It's a triage prioritization signal, stated explicitly in output/docs.

---

## 8. Open questions (need your call before I code)

1. **Score scale** – 0–100 (proposed) or 0–1? (Cosmetic; 0–100 reads better in tables.)
2. **Feature set for v1** – approve F1–F7 as the initial catalog, or add/drop any? (E.g. do you want an
   explicit "recently registered domain" feature from RDAP dates?)
3. **Takeover fingerprints** – start with a small curated built-in list (a dozen common providers), or
   wire in an external community fingerprint dataset (bigger, but adds a data dependency)?
4. **Scoring default: on or off?** – should `collect` score by default, or only with `--score`?
5. **Weights philosophy** – OK to ship expert-set defaults now and calibrate in M4, or do you want a
   documented calibration mini-experiment inside M2 already?

---

**Sign-off:** on your "да" + answers to §8, I'll break M2 into tasks and start with `scoring/features.py`
(pure functions + tests), then the aggregator, then analytics – same test-first cadence as M0/M1.
