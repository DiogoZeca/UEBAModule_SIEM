# UEBAModule_SIEM
Create a UEBA module for a SIEM. This module should implement data analysis rules to detect anomalous network behaviors and possibly compromised devices.

---

## Dataset

X = (108212 + 108749) % 10 = 216961 % 10 = 1  
=> **Dataset 1**

---

## Network Topology

| Role | Subnet / IP | Protocol | Port |
|---|---|---|---|
| Internal clients | `192.168.101.0/24` (198 devices) | TCP + UDP | 443, 53 |
| Internal DNS server (primary) | `192.168.101.226` | UDP | 53 |
| Internal DNS server (secondary) | `192.168.101.229` | UDP | 53 |
| Internal HTTPS server | `192.168.101.240` | TCP | 443 |
| External clients | `188.83.72.0/24` (196 devices) | TCP | 443 |
| Corporate public servers | `200.0.0.11`, `200.0.0.12` | TCP | 443 |

---

## Baselines (from training data)

### Internal Clients — `internal_train1.json`

| Metric | Mean | Std | Min | Max |
|---|---|---|---|---|
| HTTPS flows per client | 3962 | 2097 | 81 | 10597 |
| Total up_bytes per client (port 443) | 45 MB | 24 MB | 0.9 MB | 120 MB |
| Down/up ratio (port 443) | 9.24 | 0.23 | 8.56 | 10.15 |
| DNS flows per client | 536 | 288 | 15 | 1446 |
| Avg up_bytes per DNS query | 200 B | 3.5 B | 181 B | 211 B |
| Unique DNS destinations per client | 2 | 0 | 2 | 2 |
| Inter-flow interval std | 8350 | 6668 | 1423 | 35048 |

> All DNS traffic goes exclusively to the two internal DNS servers (`.226`, `.229`). Any client querying external DNS is immediately anomalous.

### External Clients — `external_train1.json`

| Metric | Mean | Std | Min | Max |
|---|---|---|---|---|
| HTTPS flows per client | 3635 | 1763 | 342 | 8966 |
| Down/up ratio | 8.50 | 0.04 | 8.40 | 8.61 |

> The external down/up ratio is extremely tight (std = 0.04). A 3-sigma threshold flags anything outside [8.38, 8.62].

---

## Implementation Plan — `ueba.py`

### Step 1 — `compute_baselines()`
Reads both training files (`internal_train1`, `external_train1`) and computes all baseline statistics as variables that the rule functions will reuse. Returns a dictionary with:
- Per internal client: HTTPS flow count, total up_bytes, down/up ratio, DNS flow count, avg DNS up_bytes, unique DNS destinations, inter-flow interval std
- Aggregate stats across all clients: mean and std of each metric above
- Per external client: down/up ratio
- Aggregate external stats: mean and std of ratio
- The set of DNS destination IPs seen per internal client (used by Step 5)
- The set of countries and ASNs contacted per internal client (used by Step 4)

Nothing is printed or flagged here — this function only computes and returns. All rule functions call this once at startup.

---

### Step 2 — `detect_external_anomalies()`
**Detects:** External clients accessing corporate servers in an anomalous way.  
**Data:** `external_train1` (baseline) → `external_test1` (detection).  
**Metric:** Down/up byte ratio per `src_ip`.  
**Logic:** Compute ratio per client in test. Flag any client where ratio deviates more than 3×std from the training mean (threshold: outside `[mean - 3σ, mean + 3σ]`).  
**Why this works:** The training ratio is extremely consistent (std=0.04). A client uploading more than usual (e.g. exfiltrating to the server) or downloading unusually little will break this tight distribution.

---

### Step 3 — `detect_https_exfiltration()`
**Detects:** Internal clients exfiltrating data over HTTPS.  
**Data:** `internal_train1` (baseline) → `internal_test1` (detection).  
**Metric:** Total `up_bytes` on port 443 per `src_ip`.  
**Logic:** Flag any internal client whose total upload in the test day exceeds `mean + 3×std` of the training distribution.  
**Why this works:** Normal clients upload at most ~120 MB/day. An exfiltrating device will send hundreds of MBs or GBs — orders of magnitude above the baseline.

---

### Step 4 — `detect_new_geo_destinations()`
**Detects:** Internal clients contacting countries anomalous at the network level or individually.  
**Data:** `internal_train1` (baseline) → `internal_test1` (detection).  
**Metric:** Set of destination countries (ISO codes) per `src_ip`, derived via geoip2 lookups on `dst_ip`.  
**Logic:** Two-tier approach (naive per-IP new-country produced 82% FP due to CDN rotation):
- **Tier 1 (global):** flag any client reaching a country that *no* client in the entire network contacted during training. New-to-network access is immediately anomalous regardless of which device triggered it.
- **Tier 2 (per-IP):** flag any client that contacts ≥10 countries new to it in the test period. CDN rotation adds 1–3 new countries naturally; ≥10 signals active reach to new infrastructure.
- Both tiers require `MIN_INTENSITY_FLOWS = 5` flows to new-country IPs before firing, suppressing one-off CDN edge lookups.

**Why this works:** A compromised device reaching new foreign infrastructure (C2 server, exfiltration endpoint) will contact countries the device — or the whole network — never reached during the training period. ASN detection was evaluated and removed: it flagged the identical set of IPs as country detection with 2.2 s of overhead and zero additional detections.

---

### Step 5 — `detect_dns_anomalies()`
**Detects:** DNS-based data exfiltration and C&C communication via DNS.  
**Data:** `internal_train1` (baseline) → `internal_test1` (detection).  
**Metrics (two sub-rules):**
- **DNS volume:** total DNS flow count per `src_ip`. Flag if count > `mean + 3×std` of training.
- **Public DNS:** flag any client sending DNS queries to a public IP (not `.226` or `.229`). In training, every client uses only the two internal DNS servers — any deviation is immediately anomalous.  

**Why this works:** DNS tunneling encodes data inside DNS queries, producing a high volume of queries to external resolvers. C&C over DNS uses the same pattern. Both break the "DNS only goes to internal servers" invariant that holds perfectly in training.

---

### Step 6 — `detect_botnet_beaconing()`
**Detects:** Internal devices with botnet-like beaconing behaviour.  
**Data:** `internal_train1` (baseline) → `internal_test1` (detection).  
**Metric:** Standard deviation of inter-flow time intervals per `src_ip` (sort flows by timestamp, compute `.diff()` per client group).  
**Logic:** Flag any client whose interval std in the test data is significantly lower than the training minimum (regular beaconing = low variance). Threshold: below the 5th percentile of the training distribution.  
**Why this works:** A botnet implant checks in with its C&C server at a fixed interval (e.g. every 5 seconds). This produces an unusually regular flow pattern — the std of intervals will be far lower than any legitimate user's traffic.

---

### Step 7 — `main()`
Calls `compute_baselines()` once, then runs all 5 detection functions in sequence. Collects all flagged IPs across all rules and prints:
- Per alert: rule name, flagged IP, observed metric value, training baseline (mean ± std), deviation magnitude
- Final consolidated list: every unique anomalous IP and which rule(s) triggered it