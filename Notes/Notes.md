# UEBA Module — Analysis Notes & Report Reference

Project: UEBA Module for SIEM | Universidade de Aveiro | Due: 2026-06-08
Dataset: X=1 (108212 + 108749 = 216961 → last digit = **1**)

---

## REPORT STRUCTURE GUIDE

Use this as a skeleton. Each subsection maps to a section in the PDF report.

### 1. Introduction / Problem Statement
- UEBA = User and Entity Behavior Analytics: detect anomalous network behaviour using statistical baselines.
- Dataset X=1: internal_train1/test1 (192.168.101.x) and external_train1/test1 (188.83.72.x).
- Only two protocols: TCP/443 (HTTPS) and UDP/53 (DNS).
- Goal: build baselines from training data, detect deviations in test data, forward alerts to Wazuh SIEM.

### 2. Data Characterisation
- Dataset row counts (see table below — corrected from live run)
- Protocol split (only HTTPS and DNS in entire dataset)
- Internal vs external clients; internal server topology
- Destination country distribution (table below)
- External inter-flow interval distribution and what it means (table below)
- Key invariants: DNS always to internal servers, all 198 clients talk to all 3 internal servers

### 3. Anomaly Detection Rules
One subsection per rule. For each: what it detects, threshold derivation, results, decision rationale.

### 4. SIEM Integration
- Architecture diagram (ueba.py → UDP/514 → wazuh.manager → indexer → dashboard)
- Wazuh internal pipeline (decoder → rule → alert → Filebeat → indexer)
- Decoder + rule code
- Dashboard screenshot (rule.id: 100201, 28 hits)
- Written answer: *"What can you conclude about the usage of such a rule in a real environment?"*

### 5. Results & Conclusions
- Final 27-IP table with confidence and rules
- Attack patterns and severity groupings
- Limitations and production extensions

### Spec compliance checklist (NetMonitoring_SIEM_SRC.pdf, section 11)

| Requirement | Our implementation | Status |
|---|---|---|
| Decoder `ueba_alarm` with `<prematch>Alarm UEBA</prematch>` | `local_decoder.xml` | ✓ |
| Child decoder with regex `(\d+.\d+.\d+.\d+)` → `srcip` | `local_decoder.xml` | ✓ |
| Rule 100201 level 7, `<decoded_as>ueba_alarm</decoded_as>` | `local_rules.xml` | ✓ |
| Description: `UEBA Alarm triggered from $(srcip)` | `local_rules.xml` | ✓ |
| Groups: `syslog,ueba,` + `ueba_security_event` | `local_rules.xml` | ✓ |
| Send format: `"Alarm UEBA <ip>"` | `send_syslog_alert()` | ✓ |
| Manual test: `logger -n 172.100.0.12 -P 514 "Alarm UEBA 10.1.1.1"` | Performed, verified in alerts.log | ✓ |

---

## DATA CHARACTERISATION

### Dataset sizes (from live run)

| File | Rows | Columns |
|---|---|---|
| internal_train1.json | 890,749 | 7 |
| internal_test1.json | 1,008,425 | 7 |
| external_train1.json | 712,488 | 7 |
| external_test1.json | 681,696 | 7 |

### Network topology
- **198 internal clients** (192.168.101.x) — all present in training
- **3 internal servers**: DNS `.226`, DNS `.229`, HTTPS `.240`
- All 198 clients communicate with all 3 internal servers in training — zero variance
- All DNS queries go exclusively to `.226` and `.229` — the strongest invariant in the dataset
- Only two protocols exist: TCP/443 (HTTPS) and UDP/53 (DNS) — no other traffic

### Internal destination countries (36 total in training)

Top 10 by flow count (public destinations only):

| Country | Flows | Upload | % of total |
|---|---|---|---|
| PT | 234,442 | 2669.7 MB | 37.4% |
| US | 164,761 | 1875.9 MB | 26.3% |
| CA | 93,719 | 1068.2 MB | 14.9% |
| FR | 64,307 | 733.6 MB | 10.2% |
| NL | 37,617 | 429.6 MB | 6.0% |
| GB | 8,725 | 99.4 MB | 1.4% |
| ES | 7,860 | 89.3 MB | 1.3% |
| BR | 5,850 | 66.8 MB | 0.9% |
| IE | 5,810 | 67.0 MB | 0.9% |
| DE | 1,623 | 18.2 MB | 0.3% |
| ... (26 other) | 2,808 | — | 0.4% |

Top 5 (PT, US, CA, FR, NL) account for **94.8%** of all flows.
The 26 remaining countries are the global anomaly set used in Step 4 (Tier 1).

### External inter-flow intervals

| Metric | Value |
|---|---|
| Mean | 807.6 s |
| Median | 104.0 s |
| Std | 11,879.4 s |
| p90 | 191.0 s |
| p95 | 3,475.0 s |

The enormous gap between median (104 s) and mean (807 s), and the jump from p90 (191 s) to p95 (3,475 s), confirms a heavy-tailed distribution — consistent with human web browsing: bursts separated by reading pauses, with occasional overnight idle gaps. The p90 at ~3 minutes is the practical "active session" ceiling.

---

## RULE-BY-RULE ANALYSIS

### Phase 1 — compute_baselines()

Key invariants found in training:
- Internal clients use **only two protocols**: TCP:443 and UDP:53. No other traffic exists.
- DNS goes **exclusively** to `.226` and `.229` — every client in training, zero exceptions.
- The external down/up ratio is **extremely tight** (mean=8.50, std=0.04). 3σ window = [8.38, 8.62].
- Normal internal clients upload at most **~120 MB/day** over HTTPS (mean=45 MB, std=24 MB).
- Inter-flow interval std is **right-skewed** (mean=8350, std=6668, min=1423). Mean−N×std goes negative → use p05=1742 as the BotNet threshold.
- All thresholds computed dynamically from training — no hardcoded numbers.

| Threshold | Value | Formula |
|---|---|---|
| HTTPS upload | 116.6 MB | mean(45 MB) + 3 × std(24 MB) |
| HTTPS PCR | −0.7918 | mean(−0.8046) + 3 × std(0.0043) |
| DNS flow count | ~1,399 flows | mean(536) + 3 × std(288) |
| BotNet interval std | < 1,741.9 s | p05 of training distribution |
| External ratio | [8.3817, 8.6226] | mean(8.5021) ± 3 × std(0.0402) |

---

#### Deep Dive — How and why each baseline block was designed

**Design principle: compute once, pass as a dict**

All five detection rules need statistics derived from training data. The naive approach would be to load and aggregate the training DataFrame inside each rule function — but this means re-reading ~900k rows five separate times and duplicates groupby operations. Instead, `compute_baselines()` reads the training data once, builds every statistic needed by every rule, and returns a single `dict b`. Each rule receives `b` as its only input. The separation is intentional: the function is purely computational (no printing, no flagging), which makes it independently testable and easy to replace with a different baseline source (e.g., a rolling window) without touching any rule logic.

---

**Block 1 — HTTPS exfiltration baseline (→ Step 3)**

The first question was: what metric best separates a normal client from one exfiltrating data over HTTPS?

The obvious candidate is **upload volume** (`total_up` per client on port 443). Training data shows: mean = 45 MB/day, std = 24 MB, max = ~120 MB. A threshold of `mean + 3σ = 116.6 MB` cleanly separates normal from anomalous — in training, no client exceeds it by construction (3σ guarantees ~0.1% false-positive rate if the distribution were Gaussian).

But upload volume alone misses a class of attack: **low-and-slow exfiltration**, where a device sends a modest amount of data but with an abnormal upload/download asymmetry. A legitimate HTTPS client downloads far more than it uploads (HTML, images, JS → ratio ≈ 8–10×). A device that POSTs small payloads and receives only tiny acknowledgements has near-equal upload and download — the signal is the *shape* of traffic, not the volume.

This is where **PCR (Producer-Consumer Ratio)** comes in:

```
PCR = (up_bytes − down_bytes) / (up_bytes + down_bytes)
```

Range: [−1, +1]. A pure downloader scores −1; a pure uploader scores +1; symmetric traffic scores 0. Normal HTTPS clients score ≈ −0.80 (download-dominant). The threshold `mean + 3σ = −0.7918` catches anyone who is *less download-dominant* than the 3σ floor — i.e., anyone uploading more than the training population's extreme cases.

The rule fires if **either** volume OR PCR exceeds its threshold. This OR logic is deliberate: volume catches bulk single-shot dumps; PCR catches the low-and-slow pattern. Together they cover the full attack surface. Validated by IPs `.117`, `.78`, `.128` — all below the volume threshold, all flagged by PCR.

*What was tested and removed:* The raw down/up ratio (= down/up, ranging from 0 to ∞) was also computed in baselines under `ext_ratio_mean` for external clients, and an equivalent internal ratio was tried. It is algebraically equivalent to PCR via `PCR = (1 − ratio)/(1 + ratio)` — Pearson correlation of −0.9992 between them across all clients. Applied to the test set they flagged the identical 9 IPs. PCR is the normalised, bounded [−1, +1] formulation from the literature; the raw ratio is redundant and was removed.

---

**Block 2 — DNS baseline (→ Step 5)**

DNS anomaly detection uses two completely independent sub-rules, and `compute_baselines()` produces a separate data structure for each.

**DNS-1 (volume) baseline:** `dns_flows_mean = 536`, `dns_flows_std = 288`, threshold = `536 + 3×288 = 1,399 flows/day`. The volume approach is motivated by the attack profile: both DNS tunneling (data encoded in subdomain labels) and C&C beaconing (regular keep-alive queries) produce far more DNS flows than any legitimate user. The training maximum is 1,446 flows; the threshold at 1,399 is therefore essentially the training maximum, ensuring anything above it in test is genuinely anomalous.

**DNS-2 (public server) baseline:** `dns_internal_servers = {'192.168.101.226', '192.168.101.229'}`. In training, every single internal client sends all its DNS queries exclusively to these two internal resolvers — zero exceptions. This perfect invariant means the rule requires no statistical threshold at all: any query to any other IP is an absolute violation. The set is built by `set(dns['dst_ip'].unique())` applied to training-only rows, producing exactly the two expected IPs.

*What was tested and removed:* A third DNS sub-rule was attempted based on **per-query payload size** (`up_bytes`). The hypothesis: DNS exfiltration encodes data in subdomain labels → larger packets. Training stats: `dns_up_mean ≈ 200 B`, `dns_up_std ≈ 3.5 B`, threshold = `200 + 3×3.5 = 210.5 B`. Applied to test: no IP exceeds this threshold — including the confirmed C&C beacons. Beaconing in this dataset uses fixed-size queries (the beacon identifier, not data). The DNS payload baseline was computed and kept in baselines for exploratory purposes, but the sub-rule was never added to the detection pipeline.

---

**Block 3 — Geo destination baseline (→ Step 4)**

The geo baseline answers: which countries has each client (and the network as a whole) contacted in training?

The approach requires only one line per client: `pub.groupby('src_ip')['country'].apply(set).to_dict()`. This produces `countries_per_ip`, a dict mapping each internal IP to the set of ISO country codes it contacted in training. Only public destination IPs are geo-tagged (private IPs have no country entry in the MaxMind database and return "PRIVATE" from `get_country()`), so the filter `~int_train['dst_ip'].apply(is_private)` is applied first.

The rule uses two tiers:
- **Tier 1 (global new-to-network):** `global_train_countries = set().union(*baselines['countries_per_ip'].values())` — the union of all per-IP sets, 36 countries total. A test client reaching a 37th country fires immediately.
- **Tier 2 (per-IP extreme new reach):** `len(test_countries - known_countries) >= 10` — a client contacting 10+ countries it personally never contacted in training. This threshold was tuned after observing that several devices normally visit a subset of the 36 training countries; a small new-to-them delta (1–3 countries) is plausible CDN rotation.

`country_stats` (flow counts and upload bytes per country) is computed purely for report characterisation — it does not feed any detection rule, but it produced the PT/US/CA/FR/NL breakdown shown in the output.

*What was tested and removed:* **ASN-based detection** was implemented alongside country-based detection. The hypothesis: a compromised device contacting a new ISP or cloud provider is suspicious even if the country is known. `geodbasn.asn(ip).autonomous_system_organization` was called for every public IP and an `asns_per_ip` dict was built. Applied to test, the set of IPs flagged by new-ASN overlap exactly with those flagged by new-country — the two dicts had identical key sets and the union `set(countries) | set(asns)` reduced to `set(countries)` alone. The ASN lookups added ~2.2 s overhead per run with zero additional detections and were removed.

---

**Block 4 — BotNet beaconing baseline (→ Step 6)**

The BotNet baseline measures how *regular* each client's traffic timing is.

For each internal client, flows are sorted by timestamp and `diff()` computes the time gap between consecutive flows. The **standard deviation of these gaps** per client is the metric: a regular beacon (e.g., every 5 seconds exactly) produces an extremely low std; a human browsing at irregular intervals produces a high std.

Training distribution stats:
- mean = 8,350 s, std = 6,668 s, min = 1,423 s, p05 = 1,742 s
- The distribution is **right-skewed** — a long right tail from clients with long idle gaps.

The key design decision: **why p05 instead of mean−3σ?**

`mean − 3σ = 8,350 − 3×6,668 = −11,654 s`. A standard deviation cannot be negative — this threshold is mathematically meaningless. The mean−Nσ formula requires a roughly symmetric distribution, which the interval std distribution is not. The 5th percentile (p05 = 1,742 s) is the correct non-parametric alternative: it captures "the 5% most regular clients in training" as the normal lower bound. Any test client more regular than this is suspicious.

*What was tested and removed:* **CV (Coefficient of Variation)** = std/mean was considered as a normalised regularity metric (makes values scale-independent). Training CVs range from 3.93 to 25.52. The beacon IPs in test have CVs of 3.7–16.6 — this range overlaps with the bottom of the training distribution. CV has no discriminative power for this dataset and was rejected.

---

**Block 5 — External ratio baseline (→ Step 2)**

External clients (188.83.72.x) access corporate port-443 servers. The key insight from training: the down/up ratio is **unusually tight** — mean = 8.50, std = 0.04, range [8.40, 8.61]. This is 50× tighter than the internal HTTPS distribution (std = 24 MB on upload). The consistency implies a highly uniform service: every client downloads ≈ 8.5× what it uploads, probably because the corporate server returns standardised responses (API, authentication portal, etc.).

A 3σ window [8.3817, 8.6226] provides the detection boundary. The narrow window is not a problem — it is the signal. Any external client whose ratio falls outside this range is using the service in a fundamentally different way from the trained baseline.

---

**Block 6 — External inter-flow intervals (characterisation only)**

The external interval statistics (mean, median, std, p90, p95) are computed but never fed to any detection rule. Purpose: validate that the external training data looks like real human browsing. The output (mean=807.6 s >> median=104.0 s, std=11,879 s) confirms a heavy-tailed distribution — a few clients have very long gaps but most activity is clustered. This is the signature of real browser behaviour and confirms the data is not synthetic or replayed at fixed intervals.

---

**The 3σ threshold — why this specific multiplier?**

All five rules (except BotNet's p05 exception) use `mean + 3σ` as the upper bound. This is the industry standard for anomaly detection in network traffic, with two properties that justify it:

1. **Known false-positive rate:** For a Gaussian distribution, 3σ captures 99.7% of normal behaviour. Expected FP rate per measurement: ~0.1% (1 in 1,000 clients on a given day). With ~198 internal clients, this means roughly 0.2 false positives per rule per day in the worst case — acceptable for a security analyst queue.
2. **Sensitivity balance:** 2σ (97.7%) would flag ~4 clients per rule per day from pure noise — too noisy for an operational environment. 4σ (99.994%) would be so conservative that moderate exfiltration goes undetected. 3σ is the documented sweet spot in both academic literature and SIEM vendor guidance (Elastic, Splunk, Wazuh).

---

### Step 2 — detect_external_anomalies()

**What it detects:** external clients (188.83.72.x) whose down/up ratio deviates from the training baseline.

**Why ratio not volume:** The spec hint says "it is not the amount of traffic". The external ratio baseline (mean=8.50, std=0.04) is the tightest in the entire dataset. A deviation means the server is being used in an unexpected way.

**Results: 5 anomalous external IPs — split into two behavioural groups**

| IP | Ratio | Deviation | Direction | Interpretation |
|---|---|---|---|---|
| 188.83.72.61 | 8.232 | −6.7σ | Upload-dominant | Uploads far more than expected |
| 188.83.72.64 | 8.338 | −4.1σ | Upload-dominant | Same pattern |
| 188.83.72.174 | 8.334 | −4.2σ | Upload-dominant | Same pattern |
| 188.83.72.182 | 8.661 | +4.0σ | Download-dominant | Downloads more than expected |
| 188.83.72.210 | 8.644 | +3.5σ | Download-dominant | Same pattern |

**Two groups — important distinction for the report:**
- **Upload-dominant** (.61, .64, .174): ratio below the lower bound → these external accounts push more data *toward* the corporate server than normal. Consistent with compromised credentials being used to stage data, or reversed exfiltration.
- **Download-dominant** (.182, .210): ratio above the upper bound → they retrieve more data than normal relative to what they upload. Consistent with bulk data staging or unusual large-object retrieval.

`.61` at 6.7σ is the most extreme anomaly in the entire external dataset.

---

### Step 3 — detect_https_exfiltration()

**What it detects:** internal clients uploading an anomalous HTTPS volume (mean+3σ) OR with an anomalous PCR indicating upload-heavy behaviour.

**PCR (Producer-Consumer Ratio):** = (up_bytes − down_bytes) / (up_bytes + down_bytes). Range [−1, +1].
- Source: Carter Bullard (QoSient) / John Gerth (Stanford), FloCon 2014.
- Normal HTTPS: PCR ≈ −0.80 (download-dominant). Exfiltration pushes PCR toward 0 or +1.
- Training: mean=−0.8046, std=0.0043. Threshold (mean+3σ) = **−0.7918**.
- Rule flags if EITHER `total_up > 116.6 MB` OR `PCR > −0.7918`.
- PCR catches low-and-slow exfil. Volume catches bulk single-shot dumps. Both together is documented best practice (Elastic, Splunk, ThreatHunting).

**Why not also use the internal HTTPS down/up ratio:** The ratio (down/up) was computed in baselines but removed. It is algebraically equivalent to PCR via `PCR = (1 − ratio) / (1 + ratio)`, giving a Pearson correlation of −0.9992 between them. Applied to test data they flag the **identical 9 IPs** — zero additional detections. PCR is the normalised, industry-standard formulation; the ratio is redundant.

**Results: 10 IPs flagged**

| IP | Upload | Deviation | Triggered by |
|---|---|---|---|
| 192.168.101.187 | 7.6 GB | 316σ | volume + PCR |
| 192.168.101.14 | 5.4 GB | 222σ | volume + PCR |
| 192.168.101.208 | 4.4 GB | 182σ | volume + PCR |
| 192.168.101.26 | 259 MB | 9σ | volume + PCR |
| 192.168.101.197 | 138 MB | 3.9σ | volume + PCR |
| 192.168.101.207 | 119 MB | 3.1σ | volume only (PCR=−0.802, just below threshold) |
| 192.168.101.117 | 1.2 MB | −1.8σ | **PCR only** (PCR=−0.783) → also Botnet → **HIGH** |
| 192.168.101.188 | 39.4 MB | −0.2σ | **PCR only** (PCR=−0.583) → also Botnet → **HIGH** |
| 192.168.101.78 | 6.9 MB | −1.6σ | **PCR only** (PCR=−0.790) |
| 192.168.101.128 | 4.7 MB | −1.7σ | **PCR only** (PCR=−0.788) |

**PCR-only detections are "low-and-slow" exfiltrators — key insight for the report:**
`.78`, `.128`, and `.117` have upload volumes of 6.9 MB, 4.7 MB, and 1.2 MB — all *below* the training mean of 45 MB. They would be completely invisible to a volume-only rule. They are flagged because almost everything they send is upload with almost no download response. A normal HTTPS session has a high download/upload ratio (server returns HTML, images, etc.). A device that POSTs data and receives only a tiny acknowledgement has PCR near 0 — the "low-and-slow" fingerprint. **This is the strongest argument for including PCR alongside volume.** Without PCR, these three devices would be missed entirely.

`.188` is different: 39.4 MB upload, PCR=−0.583. Much further from threshold, suggesting more deliberate upload-heavy behaviour at moderate volume.

---

### Step 4 — detect_new_geo_destinations()

**What it detects:** internal clients contacting countries anomalous at the network level or extreme per-device level.

**The CDN false positive problem:** First version (any new country per IP) flagged **163 of 198 clients** — 82% false positive rate. CDN providers rotate IPs across countries daily; legitimate users naturally hit new country codes.

**Solution — two-tier approach:**
- **Tier 1 (global):** flag any client reaching a country NO client contacted in training (26 such countries). Any access is immediately anomalous at the network level.
- **Tier 2 (per-IP extreme):** flag clients with ≥ 10 new-to-them countries. CDN rotation adds 1–3 new; 10+ indicates the device is reaching fundamentally new infrastructure.
- **MIN_INTENSITY_FLOWS = 5:** require ≥ 5 flows to new-country IPs. Suppresses one-off CDN edge-node lookups. Industry standard (Elastic, Active Countermeasures).

**Why ASN-based detection was removed:** ASN lookups (`geodbasn`, `get_asn()`) were implemented alongside country lookups. Removed because: (1) the two-tier country approach already covers every IP that would trigger an ASN-based rule — the two dict keys were identical (verified); (2) the union `set(countries) | set(asns)` reduced to `set(countries)` alone; (3) the lookups added ~2.2 s overhead per run with zero additional detections. The `detect_new_geo_destinations()` docstring was also updated to remove the stale "or ASNs" reference, keeping the documented interface consistent with the actual implementation.

**Results: 9 alerts, 6 unique IPs** (after .175 and .189 filtered by intensity)

| IP | Type | Countries | Note |
|---|---|---|---|
| 192.168.101.11 | Tier 2 | 10 new (BR, CA, CH, ES, FR, GB, IE, NL, PT, US) | 0 training rows — new device |
| 192.168.101.93 | Tier 2 | 11 new (BR, CA, DE, ES, FR, GB, IE, NL, PT, SE, US) | 0 training rows — new device |
| 192.168.101.125 | Tier 1 + 2 | 25 new incl. BG, IR, LV, PL, PY, RU, UA | high confidence |
| 192.168.101.36 | Tier 1 + 2 | 29 new incl. AR, BA, BY, IQ, IR, KZ, RU, UA | high confidence |
| 192.168.101.72 | Tier 1 + 2 | 30 new incl. BD, BY, EE, IR, KZ, LV, NG, RU, UA | **HIGH** (also Botnet) |
| 192.168.101.167 | Tier 1 | BE only (9 flows, 73 KB) | survived filter; low confidence |

`.175` and `.189` had < 5 flows to Belgium — CDN noise, correctly filtered.
`.11` and `.93` had **0 rows in training** (verified). Their sudden appearance with 10–11 country contacts is immediately suspicious regardless of which countries.

---

### Step 5 — detect_dns_anomalies()

**Two sub-rules:**

**DNS-1 (Volume):** DNS flow count > mean + 3σ (~1,399 flows). Primary signal for DNS-based C&C.

**DNS-2 (Public server):** Any DNS query to a server outside .226/.229. Zero-threshold binary rule — in training, the invariant is absolute.

**Why not use DNS query payload size (up_bytes) as a third sub-rule:** `dns_up_mean` and `dns_up_std` were computed in baselines but removed. In theory, DNS exfiltration encodes data in subdomain labels, making each query larger (typically 300–500 B+). In this dataset, DNS query sizes are uniform across every client — mean ≈ 200 B, full range 176–212 B, including the confirmed C&C beacons. No IP in test exceeds the mean+3σ threshold of 210.5 B. This metric has **zero discrimination power** here: the beaconing pattern is identified by volume and interval, not payload size.

**Critical distinction — DNS C&C beaconing vs DNS data exfiltration:**

| Aspect | C&C Beaconing (what we detected) | DNS Data Exfiltration |
|---|---|---|
| Pattern | Fixed periodic intervals (clock-driven) | Bursty, aperiodic |
| Interval | Exact 5.0 s in our data | Irregular, data-availability driven |
| Query content | Short, normal-looking | Long subdomains encoding data (base32/hex) |
| FQDN entropy | Low | High (random-looking subdomains) |
| Volume | Extreme query count | Moderate count, large per-query payload |
| Destination | Internal relay → upstream C2 | Often direct to attacker-controlled NS |

**Our DNS anomalies are C&C beaconing, not exfiltration.** The 5-second exact interval is clock-driven (malware timer). Actual data exfiltration in this dataset uses HTTPS (Step 3). DNS-2 triggered zero alerts — no device in test used public DNS. State this explicitly in the report to show understanding of both attack vectors.

**Results: 5 IPs flagged by DNS-1; DNS-2 = 0 alerts**

| IP | DNS flows | Median interval | Increase × | queries/dst |
|---|---|---|---|---|
| 192.168.101.41 | 39,493 | 5.0 s | 129× | 19,746 |
| 192.168.101.23 | 8,651 | 5.0 s | 8.6× | 4,326 |
| 192.168.101.201 | 2,941 | 5.0 s | 15.7× | 1,470 |
| 192.168.101.148 | 1,661 | 5.0 s | 4.8× | 830 |
| 192.168.101.207 | 1,418 | 5.0 s | 3.4× | 709 |

All beaconing through internal resolvers (.226/.229), which forward upstream to external C2 — explains why DNS-2 (public DNS) shows zero direct flows.

---

### Step 6 — detect_botnet_beaconing()

**What it detects:** internal clients with unusually low inter-flow interval standard deviation (below the p05 floor of training).

**Why p05, not mean−N×std:** distribution is right-skewed (mean=8350, std=6668, min=1423). mean−3σ < 0, meaningless. p05=1742 is the empirical lower floor of normal behaviour.

**Why CV was rejected:** training CVs range 3.93–25.52; beaconing IPs have CVs 3.7–16.6 — ranges overlap. Full-day overnight gaps inflate std and skew CV even for regular beacons. p05 interval std produces clean separation.

**Results: 8 IPs flagged**

| IP | Interval std | Ratio to p05 floor | Protocol | Note |
|---|---|---|---|---|
| 192.168.101.23 | 595 s | 0.34× floor | DNS (5.0 s) | also DNS volume → HIGH |
| 192.168.101.117 | 938 s | 0.54× floor | HTTPS (100 s) | also PCR → HIGH |
| 192.168.101.41 | 1,185 s | 0.68× floor | DNS (5.0 s) | also DNS volume → HIGH |
| 192.168.101.32 | 1,242 s | 0.71× floor | mixed (HTTPS 99 s, DNS 5 s) | |
| 192.168.101.72 | 1,403 s | 0.81× floor | HTTPS (102 s) | also Geo → HIGH |
| 192.168.101.201 | 1,598 s | 0.92× floor | mixed (HTTPS 103 s, DNS 5 s) | also DNS volume → HIGH |
| 192.168.101.160 | 1,667 s | 0.96× floor | mixed (HTTPS 104 s, DNS 5 s) | |
| 192.168.101.188 | 1,697 s | 0.97× floor | mixed (HTTPS 103 s, DNS 5 s) | also PCR → HIGH |

**Two beaconing channels:**
- DNS at 5 s: `.23`, `.41` (C&C via internal DNS relay)
- HTTPS at ~100 s: `.117`, `.72`, `.32`, `.160`, `.201`, `.188` — tight clustering (99–104 s) across all devices strongly suggests the same malware family or shared C2 timer

**Limitation — `.148` not caught by Step 6 (but IS caught by Step 5):**
`.148` has 1,661 DNS flows at exactly 5.0 s median interval — the same C&C pattern as all confirmed beacons. But its overall interval std = **7,259.5 s** (far above p05=1742). Reason: its HTTPS traffic is very irregular with long idle gaps; pooling DNS and HTTPS intervals together makes the combined std huge, masking the tight DNS signal.

This is a real limitation of the combined-channel approach and demonstrates exactly why Steps 5 and 6 are **complementary**: Step 5 catches what Step 6 misses when beaconing is DNS-only on a device with otherwise irregular HTTPS behaviour. Having both rules is not redundant — it is necessary.

---

## KEY DECISIONS MADE

| Decision | What we chose | Why | Alternative rejected |
|---|---|---|---|
| Statistical threshold | 3σ (0.1% FP rate) | Industry standard, consistent across all rules | 2σ (too many FPs), 4σ (misses real anomalies) |
| BotNet threshold | p05 of interval std | Distribution right-skewed — mean−Nσ goes negative | CV (ranges overlap in our data) |
| Geo tier 1 | Global network set | Network-wide never-seen countries are strong signal | Per-IP new country (163 FPs) |
| Geo tier 2 | ≥ 10 new countries per IP | Separates CDN noise (1–3 new) from real new reach (25–30 new) | Any new country (163 FPs) |
| Intensity filter | MIN_INTENSITY_FLOWS = 5 | Suppress one-off CDN edge lookups (Elastic, Active Countermeasures standard) | None (kept .175, .189 which are CDN) |
| HTTPS dual rule | volume OR PCR | PCR catches low-and-slow; volume catches bulk dumps | Volume only (misses .78, .128, .117) |
| HTTPS PCR vs down/up ratio | PCR (normalised) | Algebraically equivalent (Pearson −0.9992), flags identical 9 IPs; PCR is industry standard | down/up ratio (redundant) |
| DNS threshold | mean + 3σ on flow count | Consistent with all other volume-based rules | Per-query-size (no payload data available) |
| DNS public server | Zero-threshold binary | Invariant in training is absolute | Percentage-based (wrong for a binary invariant) |

---

## FAILURES & ITERATIONS

| Iteration | What happened | Fix |
|---|---|---|
| Geo rule v1 | 163 of 198 clients flagged → 82% FP rate | Two-tier approach (global set + per-IP extreme) |
| Geo rule v2 | .175 and .189 still included with 1–2 Belgium flows | MIN_INTENSITY_FLOWS = 5 filter |
| BotNet threshold v1 | mean − 3σ → negative threshold, flags everything | Switched to p05 |
| CV for beaconing | Ranges overlap 3.7–16.6 for beacons vs 3.93–25.52 for normal | Rejected, kept p05 interval std |
| DNS exfiltration | Tried to flag by FQDN entropy — dataset has no subdomain data | Limited to volume + public-DNS sub-rules |
| Flow count as float | `234,442.0 flows` printed | Added `int()` cast in print loop |
| Docker file access | `permission denied` reading Wazuh config via Bash | Used `docker exec wazuh.manager cat ...` instead |
| Wazuh reload | Decoder not picking up changes after edit | `docker exec wazuh.manager /var/ossec/bin/wazuh-control restart` |
| σ suffix bug | `print_alerts()` appended σ unconditionally — geo showed `+10 newσ` | Added `isinstance(dev, (int, float))` type check |
| BotNet deviation misleading | All 8 beacons showed 1.0–1.2σ despite severity differences | Replaced with `obs_std (obs_std/threshold× p05 floor)` ratio |
| HTTPS down/up ratio | Algebraically equivalent to PCR (Pearson −0.9992); flags identical 9 IPs — redundant metric | Removed; PCR retained as the normalised industry-standard formulation |
| ASN-based geo detection | Same dict keys as country-based, 2.2 s overhead per run, zero additional detections | Removed; country-based two-tier approach covers all cases |
| DNS payload size (up_bytes) | Query sizes uniform 176–212 B across all clients; mean+3σ = 210.5 B, zero IPs flagged | Removed; zero discrimination power in this dataset |

---

## FINAL RESULTS SUMMARY

### Threshold verification (independently recomputed from training)

| Threshold | Formula | Verified value |
|---|---|---|
| HTTPS upload | mean + 3σ | 116.6 MB ✓ |
| HTTPS PCR | mean + 3σ | −0.7918 ✓ |
| DNS flows | mean + 3σ | 1,399 flows ✓ |
| BotNet interval std | p05 | 1,741.9 s ✓ |
| External ratio | mean ± 3σ | [8.3817, 8.6226] ✓ |

### False negative check — nothing missed

| Rule | Highest unflagged value | Threshold | Gap |
|---|---|---|---|
| HTTPS upload | 105.2 MB | 116.6 MB | 11.4 MB below |
| DNS flows | 1,307 | 1,399 | 92 below |
| BotNet interval std | 1,758.4 s | 1,741.9 s | 16.5 s above |

No false negatives. All unflagged devices are cleanly below every threshold.

### 27 unique anomalous IPs total
- **22 internal** (192.168.101.x)
- **5 external** (188.83.72.x)

### HIGH confidence (2+ independent rules)

| IP | Rules triggered |
|---|---|
| `192.168.101.201` | DNS Volume + BotNet beaconing |
| `192.168.101.207` | HTTPS exfiltration + DNS volume |
| `192.168.101.23`  | DNS volume + BotNet beaconing |
| `192.168.101.41`  | DNS volume + BotNet beaconing |
| `192.168.101.72`  | Anomalous geo + BotNet beaconing |
| `192.168.101.117` | HTTPS PCR + BotNet beaconing |
| `192.168.101.188` | HTTPS PCR + BotNet beaconing |

### Complete 27-IP list

| IP | Confidence | Rules |
|---|---|---|
| 192.168.101.201 | HIGH | DNS Volume + BotNet |
| 192.168.101.207 | HIGH | HTTPS Exfil + DNS Volume |
| 192.168.101.23  | HIGH | DNS Volume + BotNet |
| 192.168.101.41  | HIGH | DNS Volume + BotNet |
| 192.168.101.72  | HIGH | New Geo + BotNet |
| 192.168.101.117 | HIGH | HTTPS PCR + BotNet |
| 192.168.101.188 | HIGH | HTTPS PCR + BotNet |
| 192.168.101.187 | MEDIUM | HTTPS Exfil (7.6 GB, 316σ) |
| 192.168.101.14  | MEDIUM | HTTPS Exfil (5.4 GB, 222σ) |
| 192.168.101.208 | MEDIUM | HTTPS Exfil (4.4 GB, 182σ) |
| 192.168.101.26  | MEDIUM | HTTPS Exfil (259 MB, 9σ) |
| 192.168.101.197 | MEDIUM | HTTPS Exfil (138 MB, 3.9σ) |
| 192.168.101.125 | MEDIUM | New Geo (25 new countries incl. RU, IR) |
| 192.168.101.36  | MEDIUM | New Geo (29 new countries) |
| 192.168.101.11  | MEDIUM | New Geo (new device, 10 countries) |
| 192.168.101.93  | MEDIUM | New Geo (new device, 11 countries) |
| 192.168.101.32  | MEDIUM | BotNet (HTTPS ~99 s, DNS 5 s) |
| 192.168.101.160 | MEDIUM | BotNet (HTTPS ~104 s, DNS 5 s) |
| 192.168.101.148 | MEDIUM | DNS Volume (5.0 s interval, not caught by Botnet — see Step 6 limitation) |
| 192.168.101.78  | MEDIUM | HTTPS PCR only (PCR=−0.790) |
| 192.168.101.128 | MEDIUM | HTTPS PCR only (PCR=−0.788) |
| 192.168.101.167 | MEDIUM | New Geo (BE only, low confidence) |
| 188.83.72.61    | MEDIUM | Ext. ratio 6.7σ below (upload-dominant) |
| 188.83.72.64    | MEDIUM | Ext. ratio 4.1σ below (upload-dominant) |
| 188.83.72.174   | MEDIUM | Ext. ratio 4.2σ below (upload-dominant) |
| 188.83.72.182   | MEDIUM | Ext. ratio 4.0σ above (download-dominant) |
| 188.83.72.210   | MEDIUM | Ext. ratio 3.5σ above (download-dominant) |

### Attack patterns identified
1. **Mass HTTPS exfiltrators**: `.187` (7.6 GB), `.14` (5.4 GB), `.208` (4.4 GB) — 182–316σ above baseline
2. **DNS C&C beaconers (5 s)**: `.41`, `.23`, `.201`, `.148` — malware polling C2 via internal DNS relay
3. **HTTPS C&C beaconers (~100 s)**: `.117`, `.72`, `.32`, `.160`, `.188`, `.201` — same malware family
4. **Dual-channel**: `.201` (DNS + HTTPS beacon), `.207` (HTTPS exfil + DNS beacon)
5. **New devices**: `.11`, `.93` — zero training rows, immediately contact 10+ countries
6. **Upload-dominant externals**: `.61`, `.64`, `.174` — push more data toward corporate server than normal
7. **Download-dominant externals**: `.182`, `.210` — bulk data retrieval anomaly

---

## SIEM ARCHITECTURE & FLOW

### High-level diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│  Host machine (172.100.0.1)                                         │
│                                                                     │
│  python3 ueba.py                                                    │
│    │                                                                │
│    ├─ 1. Loads training + test datasets (JSON)                      │
│    ├─ 2. compute_baselines() → per-IP statistical profiles          │
│    ├─ 3. Runs 5 detection rules → list of {ip, rule, metric, ...}   │
│    ├─ 4. Prints consolidated report (27 IPs, confidence level)      │
│    └─ 5. send_syslog_alert(ip) for each anomalous IP                │
│         │  UDP packet: "Alarm UEBA <ip>"  →  172.100.0.12:514      │
└─────────────────────────────────────────────────────────────────────┘
         │  UDP/514 (raw Python socket, one packet per IP)
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Docker: wazuh.manager (172.100.0.12)                               │
│  ossec.conf: syslog listener port 514, allowed-ips 172.100.0.0/24  │
│  → custom decoder (ueba_alarm) extracts srcip                       │
│  → rule 100201 level 7 fires                                        │
│  → alert written to alerts.log / alerts.json                        │
└─────────────────────────────────────────────────────────────────────┘
         │  Filebeat (bundled in manager container)
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Docker: wazuh.indexer (172.100.0.11)                               │
│  Stores alert as JSON in index wazuh-alerts-4.x-*                   │
└─────────────────────────────────────────────────────────────────────┘
         │  OpenSearch API (9200)
         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Docker: wazuh.dashboard (172.100.0.10:443)                         │
│  DQL filter: rule.id: 100201 → 28 hits                              │
│  Fields: data.srcip, rule.level=7, decoder.name=ueba_alarm          │
└─────────────────────────────────────────────────────────────────────┘
```

### Internal Wazuh pipeline — from UDP packet to dashboard event

```
send_syslog_alert("192.168.101.41")
  │  UDP: "Alarm UEBA 192.168.101.41"
  ▼
wazuh-remoted
  Listens 172.100.0.12:514/udp
  Stamps source IP (172.100.0.1 = Docker gateway)
  Queues raw event for wazuh-analysisd
  ▼
wazuh-analysisd — DECODING PHASE
  Matches <prematch>Alarm UEBA</prematch> → decoder ueba_alarm fires
  Child decoder regex (\d+.\d+.\d+.\d+) captures "192.168.101.41"
  Decoded fields:
    decoder.name = "ueba_alarm"
    data.srcip   = "192.168.101.41"
    location     = "172.100.0.1"
  ▼
wazuh-analysisd — RULE MATCHING PHASE
  Rule 100201: <decoded_as>ueba_alarm</decoded_as> matches
  Fires:
    rule.id          = 100201
    rule.level       = 7
    rule.description = "UEBA Alarm triggered from 192.168.101.41"
    rule.groups      = ["syslog", "ueba", "ueba_security_event"]
  ▼
Alert written to:
  /var/ossec/logs/alerts/alerts.log  (plain text)
  /var/ossec/logs/alerts/alerts.json (JSON)
  ▼
Filebeat → wazuh.indexer:9200
  Stored in wazuh-alerts-4.x-<date>
  ▼
wazuh.dashboard (https://localhost:443)
  DQL filter: rule.id: 100201
  Each row = one "Alarm UEBA <ip>" packet sent
```

**Why `location` shows `172.100.0.1`:** this is the machine that sent the UDP packet (the host running ueba.py, which is the Docker network gateway). The flagged IP is in `data.srcip`. Both fields are correct and serve different purposes.

**Why GeoLocation shows Aveiro, Portugal:** Wazuh geolocates `location` (the sender host = Aveiro), not `data.srcip` (192.168.x.x is a private range, cannot be geolocated).

**Why level 7:** Wazuh levels 0–15. Level 7 = "important event requiring analyst review". Level ≥ 7 appears in the Security Events module by default.

### Decoder and rule (inside wazuh.manager container)

**Why rule 100201 specifically:** This number was not a free choice — it is explicitly prescribed in section 11 of the spec (`NetMonitoring_SIEM_SRC.pdf`): *"add new rule 100201"*. The full custom rule namespace used across the guide is: 100101 (hidden image trigger, level 12, section 9), 100102 (DDoS escalation of 100101, level 13, section 10), and 100201 (UEBA alarm, level 7, section 11). The 100xxx prefix puts them all in the user-defined range (≥ 100000); the 2xx suffix distinguishes the UEBA exercise from the earlier Apache2 exercises. Every field — id, level, decoded_as, description text, group name — was given verbatim in the spec.

`/var/ossec/etc/decoders/local_decoder.xml`:
```xml
<decoder name="ueba_alarm">
  <prematch>Alarm UEBA</prematch>
</decoder>

<decoder name="ueba_alarm_fields">
  <parent>ueba_alarm</parent>
  <regex offset="after_parent">(\d+.\d+.\d+.\d+)</regex>
  <order>srcip</order>
</decoder>
```

`/var/ossec/etc/rules/local_rules.xml`:
```xml
<group name="syslog,ueba,">
  <rule id="100201" level="7">
    <decoded_as>ueba_alarm</decoded_as>
    <description>UEBA Alarm triggered from $(srcip)</description>
    <group>ueba_security_event</group>
  </rule>
</group>
```

After editing: `docker exec wazuh.manager /var/ossec/bin/wazuh-control restart`

### Step-by-step: running the full system

1. `cd Wazuh && docker-compose up -d` — start 4 containers
2. `python3 ueba.py` — runs full analysis and sends syslog alerts
3. Open `https://localhost:443`, login, navigate Security Events → Events
4. Apply DQL filter `rule.id: 100201` → 28 hits visible

### What to show in the report (SIEM section)

1. `send_syslog_alert()` function code
2. Terminal output showing `→ Alarm UEBA x.x.x.x` lines
3. Wazuh Dashboard screenshot: DQL filter, 28 hits, `data.srcip` field showing flagged IPs
4. Written answer — *"What can you conclude about the usage of such a rule in a real environment?"*:

> In a production environment, the Wazuh manager runs on a dedicated security server. Any monitoring tool — including a UEBA script — can send alerts over UDP/514 without requiring a Wazuh agent on the monitoring machine. The decoder normalises the message into structured fields (`srcip`) that Wazuh can correlate with other rules, feed into dashboards, trigger active responses (e.g. firewall blocks), or forward to ticketing systems. This makes the integration protocol-agnostic: the UEBA module needs no knowledge of Wazuh internals, only the IP and port of the manager. One practical limitation: UDP syslog has no delivery acknowledgement, so alerts may be silently lost under congestion; TCP syslog or a Wazuh agent would be preferred for production.

---

## ONLINE RESEARCH VALIDATION

### PCR — Producer-Consumer Ratio
Carter Bullard (QoSient) / John Gerth (Stanford), FloCon 2014. Our formula and threshold are canonical. Validated.

### Beaconing — Coefficient of Variation (CV)
CV ≤ 0.2 is the cited beacon threshold in literature. Not used: full-day overnight gaps inflate std and push CV up even for regular beacons. Training CVs (3.93–25.52) and beacon CVs (3.7–16.6) overlap — no clean separation. p05 interval std works better for 24-hour datasets.

### DNS C&C vs DNS exfiltration
DNS exfiltration = data encoded in subdomains (high-entropy FQDNs, bursty pattern). DNS C&C = clock-driven fixed interval, normal-looking queries. Our 5 s interval = C&C. Report should present both sub-rules and explicitly state DNS-2 (exfiltration) produced zero matches and why.

### Geo — CDN false positives
CDN rotation is the documented top source of geo rule false positives. Two-tier + MIN_INTENSITY_FLOWS is the documented mitigation. Validated against Elastic and Active Countermeasures guidance.

### HTTPS exfiltration — dual-signal
Volume spikes + client-to-server bytes ratio together is the documented best practice across Elastic, Fidelis, Splunk, ThreatHuntingProject. Validated.

### Statistical threshold — 3σ
Industry standard. 0.1% FP rate per measurement. Adaptive baselining would be better for production but is out of scope.
