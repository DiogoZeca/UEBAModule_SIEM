import pandas as pd
import numpy as np
import ipaddress
import geoip2.database

# ── Paths ────────────────────────────────────────────────────────────────────
DATASET = 1
DATA_DIR = f"dataset{DATASET}/"
GEO_DIR  = "geo-database/"

INTERNAL_TRAIN = DATA_DIR + f"internal_train{DATASET}.json"
INTERNAL_TEST  = DATA_DIR + f"internal_test{DATASET}.json"
EXTERNAL_TRAIN = DATA_DIR + f"external_train{DATASET}.json"
EXTERNAL_TEST  = DATA_DIR + f"external_test{DATASET}.json"

GEODB_COUNTRY = GEO_DIR + "dbip-country-lite-2026-05.mmdb"
GEODB_ASN     = GEO_DIR + "dbip-asn-lite-2026-05.mmdb"

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
geodb    = geoip2.database.Reader(GEODB_COUNTRY)
geodbasn = geoip2.database.Reader(GEODB_ASN)

def get_country(ip):
    try:
        return geodb.country(ip).country.iso_code or "XX"
    except Exception:
        return "PRIVATE"

def get_asn(ip):
    try:
        return geodbasn.asn(ip).autonomous_system_number
    except Exception:
        return -1

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
    Returns a dict consumed by every rule function."""

    b = {}

    # ── Internal: HTTPS (port 443) ────────────────────────────────────────────
    https = int_train[int_train['port'] == 443]
    https_per_ip = https.groupby('src_ip').agg(
        https_flows  = ('up_bytes', 'count'),
        total_up     = ('up_bytes', 'sum'),
        total_down   = ('down_bytes', 'sum'),
    ).assign(ratio=lambda d: d['total_down'] / d['total_up'])

    b['https_up_mean']    = https_per_ip['total_up'].mean()
    b['https_up_std']     = https_per_ip['total_up'].std()
    b['https_ratio_mean'] = https_per_ip['ratio'].mean()
    b['https_ratio_std']  = https_per_ip['ratio'].std()

    # ── Internal: DNS (port 53) ───────────────────────────────────────────────
    dns = int_train[int_train['port'] == 53]
    dns_per_ip = dns.groupby('src_ip').agg(
        dns_flows  = ('up_bytes', 'count'),
        mean_up    = ('up_bytes', 'mean'),
        unique_dst = ('dst_ip', 'nunique'),
    )

    b['dns_flows_mean']    = dns_per_ip['dns_flows'].mean()
    b['dns_flows_std']     = dns_per_ip['dns_flows'].std()
    b['dns_up_mean']       = dns_per_ip['mean_up'].mean()
    b['dns_up_std']        = dns_per_ip['mean_up'].std()

    # Set of DNS destination IPs per client (used by rule_dns to detect public DNS)
    b['dns_dst_per_ip'] = dns.groupby('src_ip')['dst_ip'].apply(set).to_dict()

    # All DNS destinations seen in training (should only be internal servers)
    b['dns_internal_servers'] = set(dns['dst_ip'].unique())

    # ── Internal: geo destinations per client ─────────────────────────────────
    # Only tag public dst_ip (private IPs have no country/ASN)
    pub = int_train[~int_train['dst_ip'].apply(is_private)].copy()
    pub['country'] = pub['dst_ip'].apply(get_country)
    pub['asn']     = pub['dst_ip'].apply(get_asn)

    b['countries_per_ip'] = pub.groupby('src_ip')['country'].apply(set).to_dict()
    b['asns_per_ip']      = pub.groupby('src_ip')['asn'].apply(set).to_dict()

    # ── Internal: inter-flow interval std (BotNet baseline) ───────────────────
    sorted_train = int_train.sort_values(['src_ip', 'timestamp'])
    sorted_train = sorted_train.copy()
    sorted_train['interval'] = sorted_train.groupby('src_ip')['timestamp'].diff()

    interval_std_per_ip = sorted_train.groupby('src_ip')['interval'].std().dropna()

    b['interval_std_mean'] = interval_std_per_ip.mean()
    b['interval_std_std']  = interval_std_per_ip.std()
    b['interval_std_p05']  = interval_std_per_ip.quantile(0.05)

    # ── External: down/up ratio ───────────────────────────────────────────────
    ext_per_ip = ext_train.groupby('src_ip').agg(
        total_up   = ('up_bytes', 'sum'),
        total_down = ('down_bytes', 'sum'),
    ).assign(ratio=lambda d: d['total_down'] / d['total_up'])

    b['ext_ratio_mean'] = ext_per_ip['ratio'].mean()
    b['ext_ratio_std']  = ext_per_ip['ratio'].std()

    return b


# ── Step 2: Detect anomalous external users ───────────────────────────────────

SIGMA = 3  # number of standard deviations used as threshold across all rules

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
    mean      = baselines['https_up_mean']
    std       = baselines['https_up_std']
    threshold = mean + SIGMA * std

    https_test = int_test[int_test['port'] == 443]
    per_ip = https_test.groupby('src_ip').agg(
        total_up   = ('up_bytes',   'sum'),
        total_down = ('down_bytes', 'sum'),
    ).assign(ratio=lambda d: d['total_down'] / d['total_up'])

    flagged = per_ip[per_ip['total_up'] > threshold].copy()

    alerts = []
    for ip, row in flagged.iterrows():
        alerts.append({
            'rule'      : 'HTTPS Data Exfiltration',
            'ip'        : ip,
            'metric'    : 'total upload (port 443)',
            'observed'  : f"{row['total_up']/1e6:.1f} MB",
            'threshold' : f"{threshold/1e6:.1f} MB",
            'baseline'  : f"mean={mean/1e6:.1f} MB  std={std/1e6:.1f} MB",
            'deviation' : round((row['total_up'] - mean) / std, 1),
        })

    return sorted(alerts, key=lambda a: float(a['observed'].split()[0]), reverse=True)


# ── Step 4: Detect anomalous geo destinations ─────────────────────────────────

def detect_new_geo_destinations(baselines: dict) -> list[dict]:
    """Flag internal clients contacting countries or ASNs anomalous at the network level.

    Two-tier approach to avoid CDN rotation false positives:
    1. Global: flag any client reaching a country that NO client contacted in training.
    2. Per-IP extreme: flag clients with an unusually high number of new-to-them
       countries (>= 10), indicating the device is reaching broad new infrastructure.
    """
    global_train_countries = set().union(*baselines['countries_per_ip'].values())

    pub_test = int_test[~int_test['dst_ip'].apply(is_private)].copy()
    pub_test['country'] = pub_test['dst_ip'].apply(get_country)
    pub_test['asn']     = pub_test['dst_ip'].apply(get_asn)

    test_countries_per_ip = pub_test.groupby('src_ip')['country'].apply(set).to_dict()
    test_asns_per_ip      = pub_test.groupby('src_ip')['asn'].apply(set).to_dict()

    # Countries/ASNs that no client ever contacted in training
    NEW_COUNTRY_PER_IP_THRESHOLD = 10

    alerts = []
    all_ips = set(test_countries_per_ip) | set(test_asns_per_ip)

    for ip in sorted(all_ips):
        known_countries = baselines['countries_per_ip'].get(ip, set())
        test_countries  = test_countries_per_ip.get(ip, set())
        new_to_network  = test_countries - global_train_countries
        new_to_ip       = test_countries - known_countries

        # Tier 1: client contacts a country the whole network never saw in training
        if new_to_network:
            alerts.append({
                'rule'      : 'Anomalous Geo Destination (New Country)',
                'ip'        : ip,
                'metric'    : 'countries new to entire network',
                'observed'  : ', '.join(sorted(new_to_network)),
                'threshold' : f'{len(global_train_countries)} countries seen in training',
                'baseline'  : f"{len(known_countries)} countries known for this IP",
                'deviation' : f"+{len(new_to_network)} new to network",
            })

        # Tier 2: client contacts an extreme number of new-to-it countries
        if len(new_to_ip) >= NEW_COUNTRY_PER_IP_THRESHOLD:
            alerts.append({
                'rule'      : 'Anomalous Geo Destination (Broad New Reach)',
                'ip'        : ip,
                'metric'    : 'new countries for this IP',
                'observed'  : f"{len(new_to_ip)} new countries: {', '.join(sorted(new_to_ip))}",
                'threshold' : f">= {NEW_COUNTRY_PER_IP_THRESHOLD} new countries",
                'baseline'  : f"{len(known_countries)} countries known for this IP",
                'deviation' : f"+{len(new_to_ip)} new",
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
        # Compute median inter-query interval to expose beaconing pattern
        intervals = (
            dns_test[dns_test['src_ip'] == ip]
            .sort_values('timestamp')['timestamp']
            .diff().dropna()
        )
        train_count = int_train[
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
            'extra'     : f'median interval={intervals.median():.1f}s  increase={count/max(train_count,1):.1f}x',
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

        https_std = https_flows['timestamp'].diff().std() if len(https_flows) > 1 else None
        dns_std   = dns_flows['timestamp'].diff().std()   if len(dns_flows) > 1  else None
        https_med = https_flows['timestamp'].diff().median() if len(https_flows) > 1 else None
        dns_med   = dns_flows['timestamp'].diff().median()   if len(dns_flows) > 1  else None

        if dns_std is not None and dns_std < threshold:
            protocol = f'DNS (median interval={dns_med:.1f}s)'
        elif https_std is not None and https_std < threshold:
            protocol = f'HTTPS (median interval={https_med:.1f}s)'
        else:
            protocol = f'mixed (HTTPS median={https_med:.0f}s, DNS median={dns_med:.0f}s)'

        train_std = baselines['interval_std_mean']

        alerts.append({
            'rule'      : 'BotNet Beaconing',
            'ip'        : ip,
            'metric'    : 'inter-flow interval std',
            'observed'  : round(obs_std, 1),
            'threshold' : f'< {threshold:.1f} (p05 of training)',
            'baseline'  : f'mean={train_std:.0f}  p05={threshold:.0f}',
            'deviation' : round((train_std - obs_std) / baselines['interval_std_std'], 1),
            'extra'     : f'beaconing via {protocol}  |  HTTPS={len(https_flows)} flows  DNS={len(dns_flows)} flows',
        })

    return alerts


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
        print(f"          Deviation : {a['deviation']}σ")
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
    print(f"    DNS flow threshold      : {b['dns_flows_mean'] + SIGMA*b['dns_flows_std']:.0f} flows  (mean+{SIGMA}σ)")
    print(f"    BotNet interval p05     : {b['interval_std_p05']:.1f}")
    print(f"    External ratio window   : [{b['ext_ratio_mean']-SIGMA*b['ext_ratio_std']:.4f}, {b['ext_ratio_mean']+SIGMA*b['ext_ratio_std']:.4f}]")
    print(f"    Internal DNS servers    : {b['dns_internal_servers']}")

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
    from collections import defaultdict
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

    sorted_ips = sorted(ip_rules.items(), key=lambda x: (-len(x[1]), x[0]))
    for ip, rules in sorted_ips:
        confidence = "HIGH  " if len(rules) >= 2 else "MEDIUM"
        rules_str  = " | ".join(rules)
        print(f"  [{confidence}] {ip}  →  {rules_str}")

    print()


if __name__ == "__main__":
    main()
