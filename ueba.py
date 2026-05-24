import pandas as pd
import numpy as np
import ipaddress
import socket
import geoip2.database
from collections import defaultdict

# ── Paths ────────────────────────────────────────────────────────────────────
DATASET = 1
DATA_DIR = f"dataset{DATASET}/"
GEO_DIR  = "geo-database/"

INTERNAL_TRAIN = DATA_DIR + f"internal_train{DATASET}.json"
INTERNAL_TEST  = DATA_DIR + f"internal_test{DATASET}.json"
EXTERNAL_TRAIN = DATA_DIR + f"external_train{DATASET}.json"
EXTERNAL_TEST  = DATA_DIR + f"external_test{DATASET}.json"

GEODB_COUNTRY = GEO_DIR + "dbip-country-lite-2026-05.mmdb"

# ── Load data ─────────────────────────────────────────────────────────────────
print("[*] Loading datasets...")
int_train = pd.read_json(INTERNAL_TRAIN)
int_test  = pd.read_json(INTERNAL_TEST)
ext_train = pd.read_json(EXTERNAL_TRAIN)
ext_test  = pd.read_json(EXTERNAL_TEST)
print(f"    internal_train : {int_train.shape}")
print(f"    internal_test  : {int_test.shape}")
print(f"    external_train : {ext_train.shape}")
print(f"    external_test  : {ext_test.shape}")

# ── Geo-database handles ──────────────────────────────────────────────────────
geodb = geoip2.database.Reader(GEODB_COUNTRY)

def get_country(ip):
    try:
        return geodb.country(ip).country.iso_code or "XX"
    except Exception:
        return "PRIVATE"

# ── Private network helpers ───────────────────────────────────────────────────
PRIVATE_NETS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

def is_private(ip):
    addr = ipaddress.IPv4Address(ip)
    return any(addr in net for net in PRIVATE_NETS)

# ── Step 1: Baseline ─────────────────────────────────────────────────────────

def compute_baselines():
    """Compute all baseline statistics from training data.

    Reads internal_train and external_train once and returns a single dict
    that every rule function consumes. Nothing is printed or flagged here —
    this is the statistical foundation of the entire UEBA pipeline.

    Returned keys and their consumers:
      https_up_mean, https_up_std          → Step 3: volume threshold (mean + 3σ)
      pcr_mean, pcr_std                    → Step 3: PCR threshold (mean + 3σ)
      dns_flows_mean, dns_flows_std        → Step 5: DNS volume threshold (mean + 3σ)
      dns_dst_per_ip                       → Step 5: per-alert extra context
      dns_internal_servers                 → Step 5: zero-threshold public-DNS rule
      countries_per_ip                     → Step 4: per-IP known country set (Tier-2)
      country_stats, total_train_countries → Step 4 + report characterisation
      interval_std_mean, _std, _p05        → Step 6: beaconing threshold (p05)
      ext_ratio_mean, ext_ratio_std        → Step 2: external ratio window
      ext_interval_mean/median/std/p90/p95 → characterisation only (report)
    """

    b = {}

    # ── Step 3 baseline: HTTPS upload volume and PCR ──────────────────────────
    # Group all port-443 flows by source IP and aggregate upload/download totals.
    # PCR = (up - down) / (up + down), range [-1, +1].
    # Normal HTTPS is download-heavy: training PCR ≈ -0.80 (mean), std ≈ 0.004.
    # Exfiltration pushes more bytes out than in → PCR rises toward 0 or +1.
    # Alert fires if upload volume OR PCR individually exceeds mean + 3σ.
    https = int_train[int_train['port'] == 443]
    https_per_ip = https.groupby('src_ip').agg(
        https_flows  = ('up_bytes', 'count'),
        total_up     = ('up_bytes', 'sum'),
        total_down   = ('down_bytes', 'sum'),
    ).assign(ratio=lambda d: d['total_down'] / d['total_up'])

    b['https_up_mean'] = https_per_ip['total_up'].mean()
    b['https_up_std']  = https_per_ip['total_up'].std()

    pcr = (https_per_ip['total_up'] - https_per_ip['total_down']) / (https_per_ip['total_up'] + https_per_ip['total_down'])
    b['pcr_mean'] = pcr.mean()
    b['pcr_std']  = pcr.std()

    # ── Step 5 baseline: DNS flow volume and internal server set ──────────────
    # In training every client queries only the two internal DNS servers (.226,
    # .229) — no exceptions. This absolute invariant powers the zero-threshold
    # DNS-2 sub-rule: any query outside dns_internal_servers is immediately
    # anomalous without needing a statistical test.
    # DNS-1 sub-rule uses mean + 3σ on per-client flow count. Both DNS tunneling
    # and C&C beaconing generate far more queries than any legitimate client.
    dns = int_train[int_train['port'] == 53]
    dns_per_ip = dns.groupby('src_ip').agg(
        dns_flows  = ('up_bytes', 'count'),
        mean_up    = ('up_bytes', 'mean'),
        unique_dst = ('dst_ip', 'nunique'),
    )

    b['dns_flows_mean'] = dns_per_ip['dns_flows'].mean()
    b['dns_flows_std']  = dns_per_ip['dns_flows'].std()

    b['dns_dst_per_ip']       = dns.groupby('src_ip')['dst_ip'].apply(set).to_dict()
    b['dns_internal_servers'] = set(dns['dst_ip'].unique())

    # ── Step 4 baseline: geo destinations per client ──────────────────────────
    # Only public dst_ip addresses are geo-tagged (private IPs have no country).
    # Two structures are built:
    #   countries_per_ip  — per-client set, used in Tier-2 (per-IP extreme reach)
    #   global set        — union of all, recomputed inside the rule for Tier-1
    #     (new-to-entire-network country detection)
    # country_stats is a flow+byte breakdown used only for report characterisation.
    pub = int_train[~int_train['dst_ip'].apply(is_private)].copy()
    pub['country'] = pub['dst_ip'].apply(get_country)

    b['countries_per_ip'] = pub.groupby('src_ip')['country'].apply(set).to_dict()

    country_stats = pub.groupby('country').agg(
        flows = ('up_bytes', 'count'),
        up_mb = ('up_bytes', lambda x: round(x.sum() / 1e6, 1)),
    ).sort_values('flows', ascending=False)
    b['country_stats']         = country_stats
    b['total_train_countries'] = len(country_stats)

    # Tier-2 threshold: p95 of per-IP unique country count in training.
    # Any test client reaching more new-to-it countries than 95% of all training
    # clients ever contacted is flagged as having unusually broad new reach.
    # Mirrors the p05 approach used for BotNet — both use tails of the distribution.
    country_counts_per_ip      = pub.groupby('src_ip')['country'].nunique()
    b['geo_country_count_p95'] = int(country_counts_per_ip.quantile(0.95))

    # Intensity floor: p05 of per-(IP, country) flow counts in training.
    # Represents the minimum flows a real contact produces in training — any
    # new-country access below this floor in the test period is CDN noise.
    flows_per_ip_country         = pub.groupby(['src_ip', 'country']).size()
    b['geo_min_intensity_flows'] = max(int(flows_per_ip_country.quantile(0.05)), 2)

    # ── Step 6 baseline: inter-flow interval std (beaconing) ─────────────────
    # Flows are sorted per-client by timestamp; diff() gives the time gap between
    # consecutive flows. The std of these gaps measures how *regular* the traffic
    # pattern is. A botnet beacon fires at a fixed interval → very low std.
    # Training distribution is right-skewed (mean ≈ 8350s, long right tail from
    # idle clients). mean - 3σ ≈ -11,654s — meaningless for a std value.
    # Solution: use the 5th percentile as the lower-bound threshold instead.
    # Any test client below p05 of training is flagged as suspiciously regular.
    sorted_train = int_train.sort_values(['src_ip', 'timestamp']).copy()
    sorted_train['interval'] = sorted_train.groupby('src_ip')['timestamp'].diff()

    interval_std_per_ip = sorted_train.groupby('src_ip')['interval'].std().dropna()

    b['interval_std_mean'] = interval_std_per_ip.mean()
    b['interval_std_std']  = interval_std_per_ip.std()
    b['interval_std_p05']  = interval_std_per_ip.quantile(0.05)

    # ── Step 2 baseline: external client down/up ratio ────────────────────────
    # External clients (188.83.72.x) access corporate port-443 servers.
    # Training ratio is extremely tight: mean ≈ 8.50, std ≈ 0.04.
    # A 3σ window gives [8.38, 8.62]. The tight std (0.04) means even a small
    # deviation is statistically significant — at 3σ the expected false-positive
    # rate is 0.1% per client. A client uploading unusually much (exfiltration to
    # the server) or downloading unusually little will break this distribution.
    ext_per_ip = ext_train.groupby('src_ip').agg(
        total_up   = ('up_bytes', 'sum'),
        total_down = ('down_bytes', 'sum'),
    ).assign(ratio=lambda d: d['total_down'] / d['total_up'])

    b['ext_ratio_mean'] = ext_per_ip['ratio'].mean()
    b['ext_ratio_std']  = ext_per_ip['ratio'].std()

    # ── External: inter-flow intervals (characterisation only) ────────────────
    # Not used in any detection rule. Confirms the heavy-tailed distribution
    # (mean >> median) typical of real human browsing, validating that the
    # training data is not synthetic.
    ext_sorted = ext_train.sort_values(['src_ip', 'timestamp']).copy()
    ext_sorted['interval'] = ext_sorted.groupby('src_ip')['timestamp'].diff()
    ext_iv = ext_sorted['interval'].dropna()

    b['ext_interval_mean']   = ext_iv.mean()
    b['ext_interval_median'] = ext_iv.median()
    b['ext_interval_std']    = ext_iv.std()
    b['ext_interval_p90']    = ext_iv.quantile(0.90)
    b['ext_interval_p95']    = ext_iv.quantile(0.95)

    return b


# ── Step 2: Detect anomalous external users ───────────────────────────────────

SIGMA      = 3             # standard deviations used as threshold across all rules
WAZUH_IP   = "172.100.0.12"  # wazuh.manager Docker container
WAZUH_PORT = 514              # syslog UDP listener

def detect_external_anomalies(baselines: dict) -> list[dict]:
    """Flag external clients whose down/up ratio deviates from the training baseline.

    A legitimate external client consistently downloads ~8.5x what it uploads.
    Clients with an inverted or broken ratio are likely misusing the service.
    """
    mean   = baselines['ext_ratio_mean']
    std    = baselines['ext_ratio_std']
    low    = mean - SIGMA * std
    high   = mean + SIGMA * std

    per_ip = ext_test.groupby('src_ip').agg(
        total_up   = ('up_bytes',   'sum'),
        total_down = ('down_bytes', 'sum'),
    ).assign(ratio=lambda d: d['total_down'] / d['total_up'])

    flagged = per_ip[(per_ip['ratio'] < low) | (per_ip['ratio'] > high)].copy()

    alerts = []
    for ip, row in flagged.iterrows():
        alerts.append({
            'rule'      : 'Anomalous External User',
            'ip'        : ip,
            'metric'    : 'down/up ratio',
            'observed'  : round(row['ratio'], 4),
            'threshold' : f'[{low:.4f}, {high:.4f}]',
            'baseline'  : f'mean={mean:.4f} std={std:.4f}',
            'deviation' : round(abs(row['ratio'] - mean) / std, 1),
        })

    return alerts


# ── Step 3: Detect HTTPS data exfiltration ───────────────────────────────────

def detect_https_exfiltration(baselines: dict) -> list[dict]:
    """Flag internal clients whose total HTTPS upload far exceeds the training baseline.

    Normal clients upload at most ~120 MB/day. Exfiltrating devices send
    hundreds of MBs or GBs, breaking the mean + 3σ threshold.
    """
    mean          = baselines['https_up_mean']
    std           = baselines['https_up_std']
    vol_threshold = mean + SIGMA * std
    pcr_threshold = baselines['pcr_mean'] + SIGMA * baselines['pcr_std']

    https_test = int_test[int_test['port'] == 443]
    per_ip = https_test.groupby('src_ip').agg(
        total_up   = ('up_bytes',   'sum'),
        total_down = ('down_bytes', 'sum'),
    ).assign(
        ratio = lambda d: d['total_down'] / d['total_up'],
        pcr   = lambda d: (d['total_up'] - d['total_down']) / (d['total_up'] + d['total_down']),
    )

    flagged_vol = per_ip['total_up'] > vol_threshold
    flagged_pcr = per_ip['pcr'] > pcr_threshold
    flagged     = per_ip[flagged_vol | flagged_pcr].copy()

    alerts = []
    for ip, row in flagged.iterrows():
        triggers = []
        if row['total_up'] > vol_threshold:
            triggers.append('volume')
        if row['pcr'] > pcr_threshold:
            triggers.append('PCR')
        alerts.append({
            'rule'      : 'HTTPS Data Exfiltration',
            'ip'        : ip,
            'metric'    : 'total upload (port 443)',
            'observed'  : f"{row['total_up']/1e6:.1f} MB",
            'threshold' : f"{vol_threshold/1e6:.1f} MB",
            'baseline'  : f"mean={mean/1e6:.1f} MB  std={std/1e6:.1f} MB",
            'deviation' : round((row['total_up'] - mean) / std, 1),
            'extra'     : f"PCR={row['pcr']:.3f}  pcr_threshold={pcr_threshold:.3f}  triggered_by={'+'.join(triggers)}",
        })

    return sorted(alerts, key=lambda a: float(a['observed'].split()[0]), reverse=True)


# ── Step 4: Detect anomalous geo destinations ─────────────────────────────────

def detect_new_geo_destinations(baselines: dict) -> list[dict]:
    """Flag internal clients contacting countries anomalous at the network level.

    Two-tier approach to avoid CDN rotation false positives:
    1. Global: flag any client reaching a country that NO client contacted in training.
    2. Per-IP extreme: flag clients with an unusually high number of new-to-them
       countries (>= 10), indicating the device is reaching broad new infrastructure.
    """
    global_train_countries = set().union(*baselines['countries_per_ip'].values())

    pub_test = int_test[~int_test['dst_ip'].apply(is_private)].copy()
    pub_test['country'] = pub_test['dst_ip'].apply(get_country)

    test_countries_per_ip = pub_test.groupby('src_ip')['country'].apply(set).to_dict()

    NEW_COUNTRY_PER_IP_THRESHOLD = baselines['geo_country_count_p95']
    MIN_INTENSITY_FLOWS          = baselines['geo_min_intensity_flows']

    # Pre-group once — avoids O(n×m) re-scan of pub_test on every iteration
    ip_flows_map = {ip: df for ip, df in pub_test.groupby('src_ip')}

    alerts = []
    all_ips = set(test_countries_per_ip)

    for ip in sorted(all_ips):
        known_countries = baselines['countries_per_ip'].get(ip, set())
        test_countries  = test_countries_per_ip.get(ip, set())
        new_to_network  = test_countries - global_train_countries
        new_to_ip       = test_countries - known_countries

        ip_flows = ip_flows_map.get(ip, pd.DataFrame(columns=pub_test.columns))

        # Tier 1: client contacts a country the whole network never saw in training
        if new_to_network:
            new_net_rows = ip_flows[ip_flows['country'].isin(new_to_network)]
            flows_to_new = len(new_net_rows)
            bytes_to_new = new_net_rows['up_bytes'].sum()
            if flows_to_new >= MIN_INTENSITY_FLOWS:
                alerts.append({
                    'rule'      : 'Anomalous Geo Destination (New Country)',
                    'ip'        : ip,
                    'metric'    : 'countries new to entire network',
                    'observed'  : ', '.join(sorted(new_to_network)),
                    'threshold' : f'{len(global_train_countries)} countries seen in training',
                    'baseline'  : f"{len(known_countries)} countries known for this IP",
                    'deviation' : f"+{len(new_to_network)} new to network",
                    'extra'     : f"flows_to_new={flows_to_new}  bytes_to_new={bytes_to_new/1e3:.1f} KB",
                })

        # Tier 2: client contacts an extreme number of new-to-it countries
        if len(new_to_ip) >= NEW_COUNTRY_PER_IP_THRESHOLD:
            new_ip_rows  = ip_flows[ip_flows['country'].isin(new_to_ip)]
            flows_to_new = len(new_ip_rows)
            bytes_to_new = new_ip_rows['up_bytes'].sum()
            if flows_to_new >= MIN_INTENSITY_FLOWS:
                alerts.append({
                    'rule'      : 'Anomalous Geo Destination (Broad New Reach)',
                    'ip'        : ip,
                    'metric'    : 'new countries for this IP',
                    'observed'  : f"{len(new_to_ip)} new countries: {', '.join(sorted(new_to_ip))}",
                    'threshold' : f">= {NEW_COUNTRY_PER_IP_THRESHOLD} new countries",
                    'baseline'  : f"{len(known_countries)} countries known for this IP",
                    'deviation' : f"+{len(new_to_ip)} new",
                    'extra'     : f"flows_to_new={flows_to_new}  bytes_to_new={bytes_to_new/1e3:.1f} KB",
                })

    return alerts


# ── Step 5: Detect DNS anomalies (exfiltration + C&C) ─────────────────────────

def detect_dns_anomalies(baselines: dict) -> list[dict]:
    """Flag internal clients with abnormal DNS behaviour.

    Two sub-rules:
    1. Volume: DNS flow count far above the per-client training baseline
       (mean + 3σ). High query volume is the primary signal for both
       DNS tunneling and C&C beaconing over DNS.
    2. Public DNS: any DNS query sent to a server outside the known
       internal DNS servers is immediately flagged — in training every
       client uses only the two internal resolvers without exception.
    """
    mean               = baselines['dns_flows_mean']
    std                = baselines['dns_flows_std']
    threshold          = mean + SIGMA * std
    internal_servers   = baselines['dns_internal_servers']

    dns_test = int_test[int_test['port'] == 53]

    alerts = []

    # ── Sub-rule 1: DNS volume anomaly ────────────────────────────────────────
    dns_count = dns_test.groupby('src_ip').size()
    volume_flagged = dns_count[dns_count > threshold]

    for ip, count in volume_flagged.items():
        ip_dns       = dns_test[dns_test['src_ip'] == ip]
        intervals    = ip_dns.sort_values('timestamp')['timestamp'].diff().dropna()
        unique_dst   = ip_dns['dst_ip'].nunique()
        # queries/unique_dst: high value = queries concentrated on few servers = C2 relay pattern
        queries_per_dst = count / unique_dst
        train_count  = int_train[
            (int_train['src_ip'] == ip) & (int_train['port'] == 53)
        ].shape[0]

        alerts.append({
            'rule'      : 'DNS Volume Anomaly (C&C / Exfiltration)',
            'ip'        : ip,
            'metric'    : 'DNS flow count',
            'observed'  : int(count),
            'threshold' : f'{threshold:.0f} flows',
            'baseline'  : f'mean={mean:.0f}  std={std:.0f}  train={train_count}',
            'deviation' : round((count - mean) / std, 1),
            'extra'     : f'median interval={intervals.median():.1f}s  increase={count/max(train_count,1):.1f}x  queries/dst={queries_per_dst:.0f}',
        })

    # ── Sub-rule 2: DNS to public server (zero-threshold rule) ────────────────
    public_dns = dns_test[~dns_test['dst_ip'].isin(internal_servers)]
    for ip in sorted(public_dns['src_ip'].unique()):
        dst_ips = sorted(public_dns[public_dns['src_ip'] == ip]['dst_ip'].unique())
        alerts.append({
            'rule'      : 'DNS to Public Server (C&C / Tunneling)',
            'ip'        : ip,
            'metric'    : 'DNS destination',
            'observed'  : ', '.join(dst_ips),
            'threshold' : f'only {internal_servers}',
            'baseline'  : 'all DNS must go to internal servers',
            'deviation' : 'absolute violation',
            'extra'     : f'{len(public_dns[public_dns["src_ip"] == ip])} flows to public DNS',
        })

    return sorted(alerts, key=lambda a: (
        a['rule'],
        -a['deviation'] if isinstance(a['deviation'], float) else 0
    ))


# ── Step 6: Detect BotNet beaconing ──────────────────────────────────────────

def detect_botnet_beaconing(baselines: dict) -> list[dict]:
    """Flag internal clients with suspiciously regular traffic intervals.

    A botnet implant checks in with its C&C server at a fixed interval,
    producing a very low standard deviation in inter-flow timestamps.
    Threshold: below the 5th percentile of the training distribution,
    since the distribution is right-skewed and mean - N*std goes negative.

    Beaconing protocol is identified by computing interval std separately
    for HTTPS and DNS flows, exposing the channel being used.
    """
    threshold = baselines['interval_std_p05']

    test_sorted = int_test.sort_values(['src_ip', 'timestamp']).copy()
    test_sorted['interval'] = test_sorted.groupby('src_ip')['timestamp'].diff()

    overall_std = test_sorted.groupby('src_ip')['interval'].std().dropna()
    flagged_ips = overall_std[overall_std < threshold].sort_values()

    alerts = []
    for ip, obs_std in flagged_ips.items():
        # Identify beaconing protocol by comparing HTTPS vs DNS interval stds
        https_flows = int_test[(int_test['src_ip'] == ip) & (int_test['port'] == 443)]
        dns_flows   = int_test[(int_test['src_ip'] == ip) & (int_test['port'] == 53)]

        https_ts  = https_flows['timestamp'].sort_values()
        dns_ts    = dns_flows['timestamp'].sort_values()
        https_std = https_ts.diff().std()    if len(https_flows) > 1 else None
        dns_std   = dns_ts.diff().std()      if len(dns_flows) > 1  else None
        https_med = https_ts.diff().median() if len(https_flows) > 1 else None
        dns_med   = dns_ts.diff().median()   if len(dns_flows) > 1  else None

        if dns_std is not None and dns_std < threshold:
            protocol = f'DNS (median interval={dns_med:.1f}s)'
        elif https_std is not None and https_std < threshold:
            protocol = f'HTTPS (median interval={https_med:.1f}s)'
        else:
            https_m  = f"{https_med:.0f}s" if https_med is not None else "N/A"
            dns_m    = f"{dns_med:.0f}s"   if dns_med   is not None else "N/A"
            protocol = f'mixed (HTTPS median={https_m}, DNS median={dns_m})'

        train_std = baselines['interval_std_mean']

        alerts.append({
            'rule'      : 'BotNet Beaconing',
            'ip'        : ip,
            'metric'    : 'inter-flow interval std',
            'observed'  : round(obs_std, 1),
            'threshold' : f'< {threshold:.1f} (p05 of training)',
            'baseline'  : f'mean={train_std:.0f}  p05={threshold:.0f}',
            'deviation' : f"{obs_std:.0f} s  ({obs_std / threshold:.2f}× p05 floor)",
            'extra'     : f'beaconing via {protocol}  |  HTTPS={len(https_flows)} flows  DNS={len(dns_flows)} flows',
        })

    return alerts


def send_syslog_alert(ip: str) -> None:
    """Send 'Alarm UEBA <ip>' to the Wazuh manager via UDP syslog (port 514)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(f"Alarm UEBA {ip}".encode(), (WAZUH_IP, WAZUH_PORT))


def print_alerts(alerts: list[dict], step: str) -> None:
    """Print a formatted alert block for a given detection step."""
    print(f"\n{'═'*55}")
    print(f"  {step}")
    print(f"{'═'*55}")
    if not alerts:
        print("  No anomalies detected.")
        return
    for a in alerts:
        print(f"  [ALERT] {a['rule']}")
        print(f"          IP        : {a['ip']}")
        print(f"          Metric    : {a['metric']} = {a['observed']}")
        print(f"          Baseline  : {a['baseline']}")
        print(f"          Threshold : {a['threshold']}")
        dev = a['deviation']
        dev_str = f"{dev}σ" if isinstance(dev, (int, float)) else str(dev)
        print(f"          Deviation : {dev_str}")
        if 'extra' in a:
            print(f"          Note      : {a['extra']}")
        print()


# ── Step 7: Main — run all rules and print consolidated results ───────────────

def main() -> None:
    """Run the full UEBA pipeline: compute baselines, apply all detection rules,
    and print a consolidated report of every anomalous IP found."""

    # ── Baselines ─────────────────────────────────────────────────────────────
    print("\n[*] Computing baselines from training data...")
    b = compute_baselines()
    print(f"    HTTPS upload threshold  : {(b['https_up_mean'] + SIGMA*b['https_up_std'])/1e6:.1f} MB  (mean+{SIGMA}σ)")
    print(f"    HTTPS PCR threshold     : {b['pcr_mean'] + SIGMA*b['pcr_std']:.4f}  (mean={b['pcr_mean']:.4f}  std={b['pcr_std']:.4f})")
    print(f"    DNS flow threshold      : {b['dns_flows_mean'] + SIGMA*b['dns_flows_std']:.0f} flows  (mean+{SIGMA}σ)")
    print(f"    BotNet interval p05     : {b['interval_std_p05']:.1f}")
    print(f"    External ratio window   : [{b['ext_ratio_mean']-SIGMA*b['ext_ratio_std']:.4f}, {b['ext_ratio_mean']+SIGMA*b['ext_ratio_std']:.4f}]")
    print(f"    Internal DNS servers    : {b['dns_internal_servers']}")
    print(f"    Geo new-country threshold: {b['geo_country_count_p95']} countries  (p95 per-IP in training)")
    print(f"    Geo min intensity flows  : {b['geo_min_intensity_flows']} flows      (p05 per-IP-per-country)")

    print(f"\n[*] Network characterisation — internal destination countries ({b['total_train_countries']} total):")
    top10 = b['country_stats'].head(10)
    total_flows = b['country_stats']['flows'].sum()
    for country, row in top10.iterrows():
        pct = row['flows'] / total_flows * 100
        print(f"    {country:4s}  {int(row['flows']):>8,} flows  {row['up_mb']:>8.1f} MB  ({pct:.1f}%)")
    remaining = len(b['country_stats']) - 10
    if remaining > 0:
        other_flows = int(b['country_stats'].iloc[10:]['flows'].sum())
        print(f"    ...   {other_flows:>8,} flows  ({remaining} other countries)")

    print(f"\n[*] Network characterisation — external inter-flow intervals:")
    print(f"    mean={b['ext_interval_mean']:.1f}s  median={b['ext_interval_median']:.1f}s  "
          f"std={b['ext_interval_std']:.1f}s  p90={b['ext_interval_p90']:.1f}s  p95={b['ext_interval_p95']:.1f}s")

    # ── Detection rules ───────────────────────────────────────────────────────
    steps = [
        ("Step 2 — detect_external_anomalies()",   detect_external_anomalies(b)),
        ("Step 3 — detect_https_exfiltration()",   detect_https_exfiltration(b)),
        ("Step 4 — detect_new_geo_destinations()", detect_new_geo_destinations(b)),
        ("Step 5 — detect_dns_anomalies()",        detect_dns_anomalies(b)),
        ("Step 6 — detect_botnet_beaconing()",     detect_botnet_beaconing(b)),
    ]

    for label, alerts in steps:
        print_alerts(alerts, label)

    # ── Consolidated summary ──────────────────────────────────────────────────
    ip_rules: dict[str, list[str]] = defaultdict(list)
    for label, alerts in steps:
        for a in alerts:
            rule_short = label.split("—")[1].strip().replace("()", "")
            if rule_short not in ip_rules[a['ip']]:
                ip_rules[a['ip']].append(rule_short)

    print(f"\n{'═'*55}")
    print(f"  FINAL CONSOLIDATED REPORT")
    print(f"{'═'*55}")
    print(f"  Total unique anomalous IPs : {len(ip_rules)}")
    internal = [ip for ip in ip_rules if ip.startswith('192.168')]
    external = [ip for ip in ip_rules if not ip.startswith('192.168')]
    print(f"  Internal (192.168.101.x)   : {len(internal)}")
    print(f"  External (188.83.72.x)     : {len(external)}")
    print()

    sorted_ips = sorted(ip_rules.items(), key=lambda x: (-len(x[1]), ipaddress.IPv4Address(x[0])))
    for ip, rules in sorted_ips:
        confidence = "HIGH  " if len(rules) >= 2 else "MEDIUM"
        rules_str  = " | ".join(rules)
        print(f"  [{confidence}] {ip}  →  {rules_str}")

    print()

    # ── Syslog reporting to Wazuh SIEM ────────────────────────────────────────
    print(f"[*] Sending UEBA alerts to Wazuh ({WAZUH_IP}:{WAZUH_PORT})...")
    for ip in ip_rules:
        try:
            send_syslog_alert(ip)
            print(f"    → Alarm UEBA {ip}")
        except OSError as e:
            print(f"    [WARN] Could not reach Wazuh manager: {e}")
    print()

    geodb.close()


if __name__ == "__main__":
    main()
