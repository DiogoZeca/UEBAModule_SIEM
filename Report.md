# UEBA Module for SIEM

Project: UEBA Module for SIEM | Universidade de Aveiro

- Diogo Silva       108212 
- Martim Carvalho   108749 
- Dataset: X=1 (108212 + 108749 = 216961 → last digit = **1**)

--- 

# Introduction 

### UEBA (User and Entity Behavior Analytics) 
UEBA is a security approach that builds statistical profiles of normal behaviour from historical data and uses them to flag deviations in new observations. Unlike signature-based detection, which looks for known attack patterns, UEBA detects anomalies - devices or users behaving in ways inconsistent with their own established baseline. This makes it effective against novel threats and insider attacks that leave no known signature.

### GOAL
The goal of this project is to implement a UEBA module. The module reads network flow data, computes per-IP statistical baselines from a training dataset, applies a set of anomaly detection rules to a test dataset, and forwards any flagged alerts to the Wazuh manager via syslog. The full pipeline runs as a single Python script — ueba.py — that produces a consolidated report of anomalous devices and their confidence levels.

### Dataset 
The assigned dataset is in the folder to explore. It contains two distinct populations: internal clients (192.168.101.x), representing corporate workstations on the internal network, and external clients (188.83.72.x), representing users accessing a corporate server from outside. Both populations include a training file, used to establish normal behaviour, and a test file, where anomalies are detected.


#### AI Prompt
> (All the context above was given to the AI exactly as is just to understand the goal of the project.)
---

# Data Reading & First Observations

## data Loading
The first step was loading the four JSON files and understanding the structure before writing any detection logic. Each file represents one full day of network flows, with 7 fields per record: src_ip, dst_ip, port, timestamp, up_bytes, down_bytes, and protocol.

Code used:
```python
int_train = pd.read_json(INTERNAL_TRAIN)
int_test  = pd.read_json(INTERNAL_TEST)
ext_train = pd.read_json(EXTERNAL_TRAIN)
ext_test  = pd.read_json(EXTERNAL_TEST)
```
Output received:
```
internal_train : (890749, 7)
internal_test  : (1008425, 7)
external_train : (712488, 7)
external_test  : (681696, 7)
```
Concluded that the test files are larger than the training files in both cases.


## Protocols and Ports
The first thing we explored after loading was what kind of traffic actually exists in the dataset. Grouping by port across the entire internal training file reveals something immediately striking — only two ports exist: TCP/443 (HTTPS) and UDP/53 (DNS). No other protocols, no other ports, anywhere in the dataset.

Code used:
```python
int_train['port'].value_counts()
# 443 (HTTPS)
# 53 (DNS)
```
Every anomaly we detect will be either in HTTPS behaviour or DNS behaviour — there is nothing else to look at. This simplifies the problem significantly and means our detection rules can be precisely targeted at each protocol.


## Internal Network Topology
Inspecting the data, grouping the internal data by destination IP, three internal servers emerge consistently accross all 198 clients:

| Role | IP | Port |
|----------|----------|----------|
| DNS Server (primary)| 192.168.101.226 | 53 |
| DNS Server (secondary)| 192.168.101.229 | 53 |
| HTTPS Server | 192.168.101.240 | 443 |

Every one of the 198 internal clients communicates with all three servers during training — zero exceptions. This uniformity is itself a baseline: the network behaves like a corporate environment where all machines follow the same configuration. Any device that deviates from this pattern in the test period stands out immediately


## DNS Invariant
The most important single observation in the entire dataset came from inspecting DNS destination IPs. During training, every DNS query from every internal client goes exclusively to .226 or .229 — without a single exception across all 198 clients and 890K rows.

Code Used:
```python
dns = int_train[int_train['port'] == 53]
internal_servers = set(dns['dst_ip'].unique())
# {'192.168.101.226', '192.168.101.229'}
```
Output received:
```
Internal DNS servers: {'192.168.101.229', '192.168.101.226'}
```
This shows an Invariation, not tendency. It directly motivates one of the DNS detection sub-rules: any internal client that sends a DNS query to an IP outside this set during the test period is immediately and unconditionally anomalous. No threshold needed, no baseline — just a violation of a rule that held perfectly across the entire training dataset


## External Clients
The external dataset contains clients from the 188.83.72.x subnet connecting to a corporate public server over HTTPS only — no DNS traffic exists in the external files. During training, these clients show an remarkably consistent down/up byte ratio across all 196 devices:

| Metric | Value | 
|----------|----------|
| Mean down/up ratio | 8.50 |
| Std | 0.04 |
| Min | 8.40 |
| Max | 8.61 |

A standard deviation of 0.04 on a ratio of 8.50 means the server returns almost exactly 8.5× what each client uploads, consistently, across every external user. This is the tightest baseline in the entire dataset. It tells us the corporate server behaves very predictably — which means any external client that breaks this pattern in the test period is doing something genuinely unusual, not just natural variation. A 3σ window of [8.38, 8.62] is enough to catch real anomalies with very few false positives.

The script also characterised the external inter-flow intervals during baseline computation:

| Metric | Value |
|----------|----------|
| Mean | 807.6 s |
| Median | 104.0 s |
| Std | 11879.4 s |
| p90 | 191.0 s |
| p95 | 3475.0 s |

The gap between median (104s) and mean (807s), and the jump from p90 (191s) to p95 (3,475s), confirms a heavy-tailed distribution — consistent with human web browsing: short active bursts separated by reading pauses, with occasional long overnight idle gaps.


### AI Prompt
> Explore the data given in the dataset1 folder having in mind all the context I gave you before, the script should read the training and then output usefull information that we could use in order to achieve our goal. The idea is to use a pythonScript, that you can have in base the example (sampleScript.py) provided. 

---

# Baseline Computation
Before any detection logic runs, compute_baselines() reads both training files and builds a dictionary of statistical profiles that every rule will consume. This function computes per-IP aggregates — total upload, DNS flow counts, inter-flow intervals, destination countries — and derives the thresholds that define "normal" for each detection rule. Nothing is flagged here. The goal is purely to characterise the training period so the test period can be compared against it.


## Threshold table
All thresholds are derived dynamically from the training data. The script prints them at startup:
```
HTTPS upload threshold:  116.6 MB   (mean+3σ)
HTTPS PCR threshold:     -0.7918    (mean=-0.8046  std=0.0043)
DNS flow threshold:      1399 flows (mean+3σ)
BotNet interval p05:     1741.9
External ration window:  [8.3817, 8.6226]
```
Each threshold targets a different dimension of behaviour. 
- The HTTPS upload threshold (116.6 MB) defines the maximum total data a normal internal client sends over HTTPS in a day — anything above this suggests bulk data exfiltration. 
- The HTTPS PCR threshold (−0.7918) measures the upload/download balance: PCR (Producer-Consumer Ratio) is defined as (up_bytes − down_bytes) / (up_bytes + down_bytes) and ranges from −1 (pure download) to +1 (pure upload). A normal HTTPS session is download-dominant — the server returns HTML, images, files — so the training mean sits at −0.8046. A device that uploads far more than it downloads pushes PCR toward 0 or positive, which is the fingerprint of data exfiltration even when the total volume is still low. 
- The DNS flow count threshold (1,399 flows) flags clients generating an abnormal number of DNS queries — the primary signal for DNS-based C&C beaconing. - The BotNet interval std (1,741.9 s) is a floor: any client whose inter-flow timestamps are more regular than the least regular normal client in training is beaconing at a fixed interval, consistent with malware checking in with a C&C server. 
- The external ratio window ([8.3817, 8.6226]) defines the expected down/up range for external clients — a symmetric band around the training mean of 8.50. Any external client outside this window is interacting with the corporate server in an anomalous way.


## The 3σ Rule
The choice of 3σ as the threshold is an industry standard in statistical anomaly detection. Under a normal distribution, 99.9% of observations fall within 3 standard deviations of the mean — meaning only 0.1% of legitimate traffic would be flagged as anomalous by chance. This gives a good balance between sensitivity (catching real anomalies) and specificity (avoiding false positives). Applied consistently across all volume-based rules, it means the thresholds adapt automatically to the dataset: a network with higher baseline DNS traffic will produce a higher DNS threshold, and a network with tighter HTTPS upload patterns will produce a lower upload threshold. No manual tuning required.


## Exception
The BotNet rule cannot use "mean − 3σ" because the inter-flow interval standard deviation distribution in training is heavily right-skewed — most clients have moderate regularity, but a few have very high interval variability, pulling the mean up.
The training values are: mean = 8,350 s, std = 6,668 s. Applying "mean − 3σ" gives 8,350 − 3 × 6,668 = −11,654 s — a negative threshold, which is mathematically meaningless for a standard deviation. 
Instead, we use the 5th percentile (p05 = 1,741.9 s) of the training distribution as the floor. This represents the lower boundary of normal behaviour empirically observed in training: any client in the test period with an interval std below this value is more regular than 95% of all normal clients — a strong signal of automated, clock-driven behaviour.


## Country Distribution
As part of the baseline computation, every internal client's HTTPS traffic was mapped to destination countries using a GeoIP database. Across all 198 clients and the full training period, the network contacted 36 unique countries. The top 5 alone account for 94.8% of all flows, showing a heavily concentrated geographic footprint — most traffic goes to Portugal, the US, Canada, France, and the Netherlands.
| Country | Flows | % of Total | 
|----------|----------| ---------|
| PT | 234442 | 37.4% |
| US | 164761 | 26.3% |
| CA | 93719 | 14.9% |
| FR | 64307 | 10.2% |
| NL | 37617 | 6.0% |
| (others) | 18676 | 5.2% |

These 36 countries define the known geographic footprint of this network — any country contacted in the test period that never appeared in training is an immediate network-level anomaly, regardless of which client triggered it.


### AI Prompt
> Explore online how the compute_baselines() function should be implemented. The idea is to compute the necessary statistics and thresholds that will be used by the detection rules. You can use the information you got from the data exploration phase and the list with all rules and justification for detection, to decide which statistics are relevant for each rule. The idea is to find the "normal" tresholds for each rule based on the training data, so that when we apply the rules to the test data, we can flag any deviations from these baselines as anomalies.

---

# Rule Implementation
With the baselines established, the next step was implementing the detection rules. 
Each rule targets a specific type of anomalous behaviour — exfiltration, beaconing, geographic anomalies — and operates independently, consuming the baseline dictionary computed in the previous step. 
The rules were designed to be complementary rather than redundant: some catch high-volume bulk attacks, others catch low-and-slow patterns that volume alone would miss entirely. 
For each rule, the process followed the same structure — define the metric, compute the threshold from training, apply it to the test data, and examine what gets flagged. In several cases the first approach produced too many false positives or broke down statistically, requiring iteration before arriving at a clean result.

## External Anomaly Detection
### What to look for
The external anomaly rule targets clients from the 188.83.72.x subnet accessing the corporate server in an unusual way. 
The key insight here is that the relevant signal is not the amount of traffic, but the ratio between downloaded and uploaded bytes. 
During training, every external client consistently downloads roughly 8.5× what it uploads — a tight, stable pattern with a standard deviation of just 0.04. This makes the ratio the most discriminating metric in the entire dataset: a client whose ratio breaks this pattern is interacting with the server in a fundamentally different way than normal, regardless of total volume. 
A 3σ window of [8.3817, 8.6226] is sufficient to flag real anomalies with minimal false positives.
### Code Implementation
Code used:
```python
low = mean - SIGMA * std  # 8.3817
high = mean + SIGMA * std # 8.6226

flagged = per_ip[(per_ip['ratio'] < low) | (per_ip['ratio'] > high)]
```
The logic is straightforward — compute the ratio for each external client in the test period and flag anyone outside the 3σ window. Below the lower bound means the client is uploading proportionally more than expected. Above the upper bound means it is downloading proportionally more than expected.
### Results
The rule flagged 5 external IPs, which naturally split into two distinct behavioural groups:
```
[ALERT] 188.83.72.61   ratio=8.232  deviation=6.7σ
[ALERT] 188.83.72.64   ratio=8.338  deviation=4.1σ
[ALERT] 188.83.72.174  ratio=8.334  deviation=4.2σ
[ALERT] 188.83.72.182  ratio=8.661  deviation=4.0σ
[ALERT] 188.83.72.210  ratio=8.644  deviation=3.5σ
```
The results showed us to groups: 
- The first group — .61, .64, .174 — sit below the lower bound. Their ratio is lower than normal, meaning they upload proportionally more than a legitimate client would. This is consistent with a compromised account being used to push data toward the corporate server, or with reversed exfiltration where data is staged on the server from outside. 
- The second group — .182, .210 — sit above the upper bound, downloading more than expected relative to what they upload, consistent with bulk data retrieval or unusual large-object access. These are two different threat models, but the same symmetric rule catches both because both break the tight ratio invariant in opposite directions.

The 188.83.72.61 at 6.7σ is the most extreme anomaly in the entire external dataset — its ratio of 8.232 is almost 7 standard deviations below the training mean, making it the clearest single signal of the five.


## Internal Anomaly Detection (HTTPS Exfiltration)
### What to look for
The HTTPS exfiltration rule targets internal clients sending an abnormal amount of data outbound over HTTPS. 
The first instinct is to flag by volume — any client uploading more than mean + 3σ (116.6 MB) in the test period is suspicious. However, volume alone has a blind spot: a device that exfiltrates data slowly and steadily, keeping its total upload below the threshold, would go completely undetected. To catch this pattern, we added a second signal — the PCR (Producer-Consumer Ratio), which measures the upload/download balance independently of total volume. 
The rule flags any client that triggers either condition, making it sensitive to both bulk single-shot dumps and low-and-slow exfiltration.
### Code Implementation
Explaining the PCR:
```python
PCR = (up_bytes - down_bytes) / (up_bytes + down_bytes)
```
The value ranges from −1 (pure download) to +1 (pure upload). 
A normal HTTPS session is download-dominant — the client sends a request and the server returns HTML, images, or files — so the training mean sits at −0.8046. 
A device that is exfiltrating data sends large uploads and receives only small acknowledgements in return, pushing PCR toward 0 or positive. 
The 3σ threshold is −0.7918 — any client above this value is uploading disproportionately relative to what it downloads, regardless of total volume.

```python
flagged_vol = per_ip['total_up'] > vol_threshold  # > 116.6 MB
flagged_pcr = per_ip['pcr']      > pcr_threshold        # > -0.7918
flagged     = per_ip[flagged_vol | flagged_pcr]
```
The OR logic is the key design decision — a client only needs to break one of the two conditions to be flagged. This ensures neither pattern escapes detection.
### Results
The rule flagged 10 internal IPs:
```
[ALERT] 192.168.101.187  upload=7586.3 MB  deviation=316.4σ  triggered_by=volume+PCR
[ALERT] 192.168.101.14   upload=5352.1 MB  deviation=222.6σ  triggered_by=volume+PCR
[ALERT] 192.168.101.208  upload=4402.0 MB  deviation=182.8σ  triggered_by=volume+PCR
[ALERT] 192.168.101.26   upload=259.2 MB   deviation=9.0σ    triggered_by=volume+PCR
[ALERT] 192.168.101.197  upload=138.3 MB   deviation=3.9σ    triggered_by=volume+PCR
[ALERT] 192.168.101.207  upload=119.0 MB   deviation=3.1σ    triggered_by=volume
[ALERT] 192.168.101.188  upload=39.4 MB    deviation=-0.2σ   triggered_by=PCR
[ALERT] 192.168.101.78   upload=6.9 MB     deviation=-1.6σ   triggered_by=PCR
[ALERT] 192.168.101.128  upload=4.7 MB     deviation=-1.7σ   triggered_by=PCR
[ALERT] 192.168.101.117  upload=1.2 MB     deviation=-1.8σ   triggered_by=PCR
```
The first five devices were caught by both signals — their uploads range from 138 MB to 7.6 GB, orders of magnitude above the 116.6 MB threshold. .207 was caught by volume only, sitting just above the threshold at 119 MB with a PCR still below the trigger point. 
The most interesting cases are the last four — flagged by PCR alone, with upload volumes below the training mean of 45 MB. A volume-only rule would have missed all of them entirely. .117 is the clearest example: it uploaded only 1.2MB that day, yet almost nothing came back in response — PCR = −0.783, well above the threshold of −0.7918. This is the low-and-slow fingerprint: a device quietly pushing data with no meaningful download activity, invisible to volume detection but fully exposed by the upload/download balance.


## GeoDestination Anomaly Detection
### What to look for
The geo destination rule targets internal clients contacting countries that are anomalous either at the network level or at the individual device level. The first approach was straightforward — flag any internal client that contacts a country in the test period that it never contacted during training. 
The result was immediate and catastrophic: 163 of 198 clients flagged, an 82% false positive rate. The reason is CDN rotation — large content delivery networks distribute their infrastructure globally and rotate IP addresses across countries regularly, meaning a legitimate user visiting the same website on two different days may hit servers in different countries each time. 
A naive per-IP new-country rule is completely blind to this and produces noise, not signal.
### Code Implementation
To solve the false positive problem, we replaced the naive approach with a two-tier detection strategy:
- Tier 1 (global): flag any client reaching a country that no client in the entire network contacted during training. There are 26 such countries. Any access to these is immediately anomalous at the network level — not just new to the individual device, but new to the whole organisation
- Tier 2 (per-IP): flag clients that contact 10 or more new-to-them countries in the test period. CDN rotation typically adds 1–3 new countries per day naturally. A device reaching 10+ new countries is not experiencing CDN noise — it is actively communicating with fundamentally new infrastructure.
```python
new_to_network = test_countries - global_train_countries  # Tier 1
new_to_ip      = test_countries - known_countries         # Tier 2

if new_to_network and flows_to_new >= MIN_INTENSITY_FLOWS:
      # fire Tier 1 alert
if len(new_to_ip) >= 10 and flows_to_new >= MIN_INTENSITY_FLOWS:
      # fire Tier 2 alert
```
The set difference operation is the core of both tiers — subtracting the known country sets from the observed ones leaves only the genuinely new destinations. The MIN_INTENSITY_FLOWS = 5 filter requires at least 5 flows to new-country IPs before an alert fires, suppressing one-off CDN edge-node lookups that would otherwise survive both tiers.
### Results
The two-tier approach with the intensity filter produced 6 unique flagged IPs across 9 alerts (some IPs triggered both tiers):
```
[ALERT] 192.168.101.11   +10 new countries  (0 known in training)
[ALERT] 192.168.101.93   +11 new countries  (0 known in training)
[ALERT] 192.168.101.125  +11 new to network, +25 new to IP  (incl. RU, IR, UA)
[ALERT] 192.168.101.36   +17 new to network, +29 new to IP  (incl. RU, IR, IQ, KZ)
[ALERT] 192.168.101.72   +15 new to network, +30 new to IP  (incl. RU, IR, UA)
[ALERT] 192.168.101.167  +1 new to network  (BE only, 9 flows)
```
The most striking results are .11 and .93 — both had zero rows in the training file. These devices did not exist on the network during the training period, and on the test day they immediately contacted 10 and 11 countries respectively. A brand new device appearing on the network and reaching out to multiple countries from day one is suspicious regardless of which countries are involved. .125, .36, and .72 are the highest confidence cases — they triggered both tiers, reaching countries the entire network had never contacted in training, including Russia, Iran, Ukraine, and Kazakhstan. .167 is the most borderline result: it triggered only Tier 1 with a single new country (Belgium), 9 flows, and 73 KB — low confidence, but it survived the intensity filter and was kept deliberately to avoid silently dropping a genuine signal.


## DNS Anomaly Detection
### What to look for
The DNS anomaly rule targets internal clients exhibiting abnormal DNS behaviour, using two independent sub-rules that catch different aspects of the same threat category. DNS-1 (Volume) flags any client whose total DNS flow count exceeds mean + 3σ (1,399 flows) — an extreme query rate is the primary signal for both DNS-based C&C beaconing and DNS tunneling. DNS-2 (Public server) flags any client that sends a DNS query to a server outside .226 and .229 — since this invariant held perfectly across all 198 clients during training, any violation is unconditionally anomalous and requires no statistical threshold. 
The two sub-rules are complementary: DNS-1 catches volume-based abuse through the internal resolvers, DNS-2 catches any attempt to bypass them entirely:
```python
# DNS-1: volume anomaly
  threshold      = mean + SIGMA * std          # 1,399 flows
  volume_flagged = dns_count[dns_count > threshold]
# DNS-2: public DNS server (binary invariant)
  public_dns = dns_test[~dns_test['dst_ip'].isin(internal_servers)]
```
### C&C Beaconing vs DNS Exfiltration
Before presenting the results, it is important to distinguish between two different DNS-based attack patterns, since they look different in the data and have different implications. DNS data exfiltration encodes stolen data inside DNS query subdomains — the queries are bursty, aperiodic, and contain long high-entropy subdomain labels. DNS C&C beaconing uses DNS queries as a heartbeat mechanism — a malware implant checks in with its C&C server at a fixed clock-driven interval, producing a very regular, high-volume query pattern with normal-looking short domain names.

| Aspect | C&C Beaconing | DNS Exfiltration |
|----------|----------|----------|
| Pattern | Fixes periodic intervals | Bursty, aperiodic |
| Query content | Short, normal-looking | Long high-entropy subdomains |
| Volume | Extreme query count | Moderate count, large payload |
| Interval | Exact, clock-driven | Irregular |

What we detected in this dataset is C&C beaconing, not exfiltration — the exact 5.0s median interval across all flagged devices is the unmistakable signature of a malware timer. Actual data exfiltration in this dataset happens over HTTPS, as seen in the previous rule.
We initially considered flagging DNS exfiltration by FQDN entropy — high-entropy subdomain labels are the signature of data encoded in DNS queries. However, the dataset does not include subdomain fields, only destination IPs — making entropy analysis impossible with the available data. Detection was therefore limited to volume and public-server sub-rules.
### Results
DNS-1 flagged 5 internal IPs. DNS-2 produced zero alerts — no client in the test period sent DNS queries to a public server:
```
[ALERT] 192.168.101.41   flows=39,493  median interval=5.0s  increase=129×
[ALERT] 192.168.101.23   flows=8,651   median interval=5.0s  increase=8.6×
[ALERT] 192.168.101.201  flows=2,941   median interval=5.0s  increase=15.7×
[ALERT] 192.168.101.148  flows=1,661   median interval=5.0s  increase=4.8×
[ALERT] 192.168.101.207  flows=1,418   median interval=5.0s  increase=3.4×
```
Every flagged device shows an exact 5.0s median interval between DNS queries — a clock-driven malware timer firing consistently throughout the day. .41 is the most extreme case at 39,493 flows, 129× its own training baseline, with queries concentrated almost entirely on the two internal resolvers. The zero result for DNS-2 is not a failure of the rule — it is explained by the beaconing pattern itself. The malware routes its C&C traffic through the internal DNS resolvers (.226/.229), which forward the queries upstream to the external C2 server. The infected devices never contact public DNS directly, which is why DNS-2 sees nothing. Both results together paint a consistent picture.

The 192.168.101.148 shows the same exact 5.0s interval and is correctly flagged here by DNS-1 — but it will not be caught by the BotNet beaconing rule in the next section, and that difference is worth examining closely.


## BotNet Beacon Detection
### What to look for
The BotNet beaconing rule targets internal clients whose network traffic follows an unusually regular timing pattern. A botnet implant checks in with its C&C server at a fixed interval — every 5 seconds, every 100 seconds — producing a very low standard deviation in inter-flow timestamps compared to legitimate users, whose traffic is naturally irregular. The detection metric is therefore the standard deviation of inter-flow intervals per client: a suspiciously low value means the device is firing traffic at a clockwork rate.
The first approach was to apply the standard mean − 3σ threshold, flagging any client below this floor. This immediately broke down — the inter-flow interval std distribution in training is heavily right-skewed, with a mean of 8,350s and a std of 6,668s. Applying mean − 3σ gives:
``` 8,350 − 3 × 6,668 = −11,654 s ```
A negative standard deviation is mathematically meaningless. No threshold can be set this way on a right-skewed distribution.
### Code Implementation
The solution was to use the 5th percentile (p05 = 1,741.9s) of the training distribution as the threshold floor. This represents the empirical lower boundary of normal behaviour — any client in the test period with an interval std below this value is more regular than 95% of all legitimate clients in training, a strong signal of automated clock-driven behaviour.
An alternative approach from the literature is the Coefficient of Variation (CV), defined as std/mean, with CV ≤ 0.2 cited as a beaconing threshold. We evaluated this but rejected it — when computed on the training data, the CV ranges for normal clients (3.93–25.52) and the confirmed beaconing devices (3.7–16.6) overlap almost completely. There is no clean separation point, making CV useless as a discriminator for this dataset. The p05 interval std produces a clear boundary with no overlap.
```python
threshold = baselines['interval_std_p05']    # 1,741.9s — p05 of training

overall_std = test_sorted.groupby('src_ip')['interval'].std()
flagged_ips = overall_std[overall_std < threshold]
```
### Results
The rule flagged 8 internal IPs, which split into two distinct beaconing channels:
```
[ALERT] 192.168.101.23   interval std=595s   (0.34× floor)  DNS  median=5.0s
[ALERT] 192.168.101.117  interval std=938s   (0.54× floor)  HTTPS median=100.0s
[ALERT] 192.168.101.41   interval std=1,185s (0.68× floor)  DNS  median=5.0s
[ALERT] 192.168.101.32   interval std=1,242s (0.71× floor)  mixed HTTPS=99s DNS=5s
[ALERT] 192.168.101.72   interval std=1,403s (0.81× floor)  HTTPS median=102.0s
[ALERT] 192.168.101.201  interval std=1,598s (0.92× floor)  mixed HTTPS=103s DNS=5s
[ALERT] 192.168.101.160  interval std=1,667s (0.96× floor)  mixed HTTPS=104s DNS=5s
[ALERT] 192.168.101.188  interval std=1,697s (0.97× floor)  mixed HTTPS=103s DNS=5s
```
The 8 devices fall into two beaconing channels. The first — .23 and .41 — beacon exclusively via DNS at a 5.0s interval, consistent with what DNS-1 already identified. The second and more striking group beacons via HTTPS at intervals clustering tightly between 99 and 104 seconds across six independent devices. This is not coincidence — six infected machines maintaining the same ~100s check-in interval is the fingerprint of a single malware family sharing the same hardcoded C2 timer.

The 192.168.101.148 was flagged by DNS-1 with 1,661 flows at an exact 5.0s median interval — the same C&C pattern as every confirmed beacon in this dataset. However, it is not flagged by this rule. The reason is that .148 also has highly irregular HTTPS traffic with long idle gaps throughout the day. When inter-flow intervals are computed across all its traffic combined — both DNS and HTTPS — the overall interval std is 7,259s, far above the p05 floor of 1,742s. The irregular HTTPS behaviour completely drowns out the tight DNS beaconing signal in the combined calculation.
This is a real limitation of the combined-channel approach, but it also demonstrates exactly why the two rules are complementary rather than redundant. Step 5 catches .148 through DNS volume. Step 6 catches the devices whose beaconing dominates their overall traffic pattern. Together they cover both cases — removing either rule would leave a gap.


---

# Final Results 

---

# SIEM Integration