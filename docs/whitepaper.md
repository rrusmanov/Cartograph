# Cartograph: Graph-Based Passive Attack-Surface Intelligence with Transparent Exposure Scoring

**Author:** kaiser · **Date:** 2026-07-05 · **Artifact:** <https://github.com/kaiser/cartograph>

## Abstract

Conventional attack-surface reconnaissance emits flat lists of hostnames, discarding the relationships
that make a surface interpretable and offering no principled way to prioritise. Cartograph models an
organisation's externally observable attack surface as a typed graph built entirely from passive,
public data sources, and layers a transparent, feature-based exposure score on top of it. We evaluate
the approach offline and deterministically on a public bug-bounty target (`shopify.com`, 314 hosts,
6,554 nodes). The graph exposes 7,485 typed relationships and 23 shared-infrastructure clusters that a
flat list cannot represent. The exposure ranking concentrates multi-signal hosts at the top with
precision@10 = 1.00 at a 4.8 % base rate (a 20.9× lift over random ordering). A per-source ablation
quantifies each collector's marginal contribution. We report a methodological finding – single passive
signals such as expired TLS are near-universal on targets with long Certificate Transparency
histories – and describe how the evaluation drove a correction to the prioritisation criterion.

## 1. Problem

Standard recon tooling (`amass`, `subfinder`, `httpx`, and similar) produces flat enumerations: an
analyst receives thousands of hostnames with no structure and no ordering. Three problems follow.
*Connectivity* – which assets share a certificate, IP, ASN or registrant, and where the bridges
between segments lie – is invisible. *Prioritisation* – the empirical reality that a small fraction of
assets carries most of the risk – is left to manual triage that does not scale. *Reproducibility* –
whether a run is stable and how much each source contributes – is essentially never measured.

Cartograph's thesis is that representing the surface as a **typed graph** and overlaying a
**documented, feature-based exposure score** recovers all three properties, and that the result can be
evaluated quantitatively and reproducibly.

## 2. Related work

Open-source recon tools focus on discovery breadth and emit flat lists; graph-oriented asset views
exist primarily in commercial attack-surface-management products, which are closed and unmeasured.
Cartograph's contribution is not a new data source but the combination of (a) a typed, provenance-aware
graph over standard passive sources, (b) an auditable scoring model, and (c) an open, reproducible
empirical evaluation of what that combination adds.

## 3. Method

**Sources (passive, key-less).** Certificate Transparency (crt.sh), RDAP registration data (rdap.org),
the Wayback Machine CDX index (web.archive.org), current-resolution DNS-over-HTTPS (Cloudflare), and
ASN/BGP data (RIPEstat). All are read from public databases; no packet is sent to the target. Every
response is cached on disk, so a re-run over a populated cache is deterministic and offline.

**Graph model.** Nodes are typed assets (`domain`, `subdomain`, `ip`, `asn`, `org`, `certificate`,
`endpoint`); edges are typed relationships (`resolves_to`, `part_of_asn`, `shares_cert`,
`registered_by`, `has_subdomain`, `has_endpoint`). Node identity is canonical, so the same asset
observed by two sources collapses into one node, and every node and edge records the set of sources
that asserted it (provenance), which is what makes source ablation possible without re-collection.

**Exposure score.** Each host receives a bounded score in [0, 100] equal to a weighted, normalised sum
of seven per-host features: newest-certificate TLS expiry, takeover-prone/dangling CNAME,
off-primary-ASN hosting, non-production naming, orphan/never-resolves, graph centrality, and wildcard
exposure. Every feature returns a value in [0, 1]; weights are documented with rationale in a single
module; and each score decomposes into per-feature contributions, so a ranking is auditable rather than
opaque. The model is deliberately transparent (not machine-learned) so that its behaviour is explainable
and every signal is ablatable.

**Analytics.** Degree/betweenness centrality (risk-concentration nodes and bridges), connected-component
clustering over shared certificates and IPs, a passive subdomain-takeover heuristic (curated provider
fingerprints; candidates only, never confirmed by touching the target), and snapshot diffing.

## 4. Experimental setup

**Target.** `shopify.com`, whose operator runs a public bug-bounty programme; only passive, public data
is used. **Determinism.** The experiment runs offline from a saved, scored graph; all randomness (the
layout aside) is seeded or absent. **Research questions.** RQ1 (connectivity): what structure does the
graph surface that a flat list cannot? RQ2 (prioritisation): does the exposure ranking concentrate
objectively risky hosts near the top? RQ3 (reproducibility): is scoring deterministic, and what does
each source contribute?

**Interesting-host label (RQ2).** A host is labelled *interesting* if it carries **two or more** distinct,
objective, passive risk signals among: no current valid TLS (newest certificate expired),
takeover-prone/dangling CNAME, non-production naming, and off-primary-ASN hosting. The multi-signal
threshold is motivated by a finding in §6.

**Metrics.** precision@k (fraction of the top-k exposure-ranked hosts that are interesting), base rate
(the fraction of all hosts that are interesting – the expectation under random ordering), and
lift@k = precision@k / base rate. Source ablation reports, per source, the hosts and edges that would
be lost if that source were removed, computed from provenance.

## 5. Results

### 5.1 RQ1 – Connectivity

The graph over `shopify.com` contains **314 hosts**, **6,554 total nodes**, and **7,485 typed edges**:

| Relationship | Count |
|---|---|
| `shares_cert` | 6,127 |
| `has_endpoint` | 982 |
| `has_subdomain` | 311 |
| `resolves_to` | 60 |
| `part_of_asn` | 4 |
| `registered_by` | 1 |

None of these relationships is expressible in a flat host list. The shared-certificate structure alone
yields **23 shared-infrastructure clusters** (groups of hosts provably tied together by a common
certificate or IP), and the passive takeover heuristic surfaces **2 candidate** hosts whose CNAMEs point
at takeover-prone providers. The graph therefore recovers exactly the connectivity that motivated it.

### 5.2 RQ2 – Prioritisation

With the multi-signal label, the base rate is **4.8 %** (15 of 314 hosts). The exposure ranking
concentrates these hosts sharply at the top:

| k | precision@k | lift over random |
|---|---|---|
| 5 | 1.00 | 20.9× |
| 10 | 1.00 | 20.9× |
| 20 | 0.75 | 15.7× |
| 50 | 0.30 | 6.3× |
| 100 | 0.15 | 3.1× |

Every one of the top-10 ranked hosts is interesting, and precision decays gracefully as k approaches the
total number of interesting hosts (15). An analyst reading the ranking top-down reaches the highest-value
targets an order of magnitude faster than with an unordered list.

### 5.3 RQ3 – Reproducibility and ablation

Scoring is **deterministic** (identical rankings across repeated runs on a fixed snapshot). The per-source
ablation quantifies marginal contribution:

| Source | Hosts lost if removed | Edges lost if removed |
|---|---|---|
| Certificate Transparency | 272 | 6,438 |
| Wayback | 0 | 982 |
| DoH resolver | 2 | 60 |
| ASN (RIPEstat) | 0 | 4 |
| RDAP | 0 | 1 |

Certificate Transparency dominates discovery (272 of 314 hosts and the bulk of edges are unique to it),
Wayback contributes the entire historical-endpoint layer, and DoH/ASN/RDAP add resolution, network, and
registration structure respectively. The ablation makes the value of each source explicit and would guide
where to invest in additional collectors.

## 6. A methodological finding

The initial *interesting* label used a single signal – an expired TLS certificate. On `shopify.com` this
labelled **99.4 %** of hosts (312/314), collapsing precision@k to a meaningless 1.0 at ~1.0× lift. Two
compounding causes: (i) a long Certificate Transparency history means most hosts have *some* expired
certificate on record, and (ii) passive recon surfaces many long-dead subdomains whose only certificate
is years old. We first corrected the TLS feature to judge the **newest** certificate rather than any
historical one; the base rate barely moved, confirming that the surface is genuinely dominated by hosts
with no current TLS. The real fix was conceptual: on a Certificate-Transparency-heavy target, no single
passive signal discriminates, and the value of the composite score lies in surfacing **coincidences** of
signals. Adopting a two-signal threshold produced the discriminating evaluation in §5.2. This is reported
not as an inconvenience but as a result: it characterises passive attack-surface data and justifies the
multi-signal design.

## 7. Threats to validity

**Circularity.** The interesting label is derived from the same passive signals the scorer aggregates, so
precision@k is a *behavioural* measure – "does the composite ranking concentrate multi-signal hosts?" –
not prediction of an independent ground truth. Requiring ≥2 signals reduces but does not eliminate this;
the score is a weighted sum, so multi-signal hosts are expected to rank highly. The honest claim is that
the aggregation behaves sensibly and concentrates coincident risk, not that it forecasts exploitability.
**Proxy signals.** Every feature is a passive proxy for interest, not a confirmation of vulnerability; the
takeover heuristic flags candidates that require authorised active verification. **Source bias.** Coverage
is uneven across targets (a CT-heavy target looks richer), and CT history biases the surface toward
historical/dead hosts. **Single target.** Results are reported for one target; generalisation requires a
broader study.

## 8. Limitations and future work

The current scoring is transparent by design; a natural extension is a machine-learned prioritiser using
these features as inputs, evaluated against held-out labels. Further work includes additional passive
sources (to reduce CT dominance shown in the ablation), calibration of weights against synthetic
ground-truth targets, and a multi-target measurement study. An opt-in, scope-guarded active-liveness
module could confirm takeover candidates under explicit authorisation.

## 9. Ethics

Cartograph is passive by default: it reads public databases and sends no traffic to the target. Active
operations are refused unless a target is covered by an explicit allowlist (scope-guard). The evaluation
target is covered by a public bug-bounty programme, and only passive data was used. Takeover findings are
candidates for authorised verification, never actions.

## 10. Reproducibility

```bash
pip install -e ".[dev,experiments]"
cartograph collect shopify.com --score -o out/shopify.json    # populates the on-disk cache
python experiments/shopify/run_experiment.py out/shopify.json # offline, deterministic
```

The experiment reads a saved scored graph and recomputes every metric; over a populated cache it touches
no network. Full method and code: the repository README and `docs/design_m2_scoring.md`.
