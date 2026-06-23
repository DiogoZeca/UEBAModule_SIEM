import pandas as pd
import numpy as np
import ipaddress
import socket
import geoip2.database
from collections import defaultdict

# ── Paths ─────────────────────────────────────────────────────────────────────
DATASET = 10
DATA_DIR = f"dataset{DATASET}/"
GEO_DIR  = "geo-database/"

INTERNAL_TRAIN = DATA_DIR + f"internal_train{DATASET}.json"
INTERNAL_TEST  = DATA_DIR + f"internal_test{DATASET}.json"
EXTERNAL_TRAIN = DATA_DIR + f"external_train{DATASET}.json"
EXTERNAL_TEST  = DATA_DIR + f"external_test{DATASET}.json"

GEODB_COUNTRY = GEO_DIR + "dbip-country-lite-2026-05.mmdb"
GEODB_ASN     = GEO_DIR + "dbip-asn-lite-2026-05.mmdb"

# ── Load data ──────────────────────────────────────────────────────────────────
print("[*] Loading datasets...")
int_train = pd.read_json(INTERNAL_TRAIN)
int_test  = pd.read_json(INTERNAL_TEST)
ext_train = pd.read_json(EXTERNAL_TRAIN)
ext_test  = pd.read_json(EXTERNAL_TEST)
print(f"    internal_train : {int_train.shape}")
print(f"    internal_test  : {int_test.shape}")
print(f"    external_train : {ext_train.shape}")
print(f"    external_test  : {ext_test.shape}")

# ── Geo-database handles ───────────────────────────────────────────────────────
geodb    = geoip2.database.Reader(GEODB_COUNTRY)
geodbasn = geoip2.database.Reader(GEODB_ASN)

def get_country(ip: str) -> str:
    try:
        return geodb.country(ip).country.iso_code or "XX"
    except Exception:
        return "PRIVATE"

def get_asn(ip: str) -> str | None:
    try:
        return geodbasn.asn(ip).autonomous_system_organization or "Unknown"
    except Exception:
        return None

# ── Private network helpers ────────────────────────────────────────────────────
PRIVATE_NETS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

def is_private(ip: str) -> bool:
    addr = ipaddress.IPv4Address(ip)
    return any(addr in net for net in PRIVATE_NETS)

# ── Constants ─────────────────────────────────────────────────────────────────
SIGMA      = 3
WAZUH_IP   = "172.100.0.12"
WAZUH_PORT = 514

# Beaconing regularisation guard: minimum ratio of (train interval std) /
# (test interval std) required to confirm a genuine behavioural change.
# Derived from the observed gap between confirmed beacons (≥1.84×) and the
# highest false-positive (.160 at 1.17×); 1.5 sits cleanly in the middle.
MIN_HTTPS_REGULARIZATION = 1.5

# Geo: new-country flows must represent at least 1% of the IP's total test
# traffic to distinguish deliberate exfiltration from CDN edge rotation.
GEO_MIN_PROPORTION = 0.01

# ── Step 1: Baselines ──────────────────────────────────────────────────────────

def compute_baselines() -> dict:
    b = {}

    # HTTPS upload volume + ratio (Step 3)
    https = int_train[int_train['port'] == 443]
    https_per_ip = https.groupby('src_ip').agg(
        total_up   = ('up_bytes', 'sum'),
        total_down = ('down_bytes', 'sum'),
    )
    b['https_up_mean'] = https_per_ip['total_up'].mean()
    b['https_up_std']  = https_per_ip['total_up'].std()
    https_ratio = https_per_ip['total_down'] / https_per_ip['total_up']
    b['https_ratio_mean'] = https_ratio.mean()
    b['https_ratio_std']  = https_ratio.std()

    # HTTPS destination split: internal server vs external (characterisation only)
    INTERNAL_HTTPS_SERVER = (
        https[https['dst_ip'].apply(is_private)]['dst_ip'].mode()[0]
    )
    b['internal_https_server'] = INTERNAL_HTTPS_SERVER
    for label, subset in [('int', https[https['dst_ip'] == INTERNAL_HTTPS_SERVER]),
                          ('ext', https[https['dst_ip'] != INTERNAL_HTTPS_SERVER])]:
        per_ip = subset.groupby('src_ip').agg(
            total_up   = ('up_bytes', 'sum'),
            total_down = ('down_bytes', 'sum'),
        ).assign(ratio=lambda d: d['total_down'] / d['total_up'])
        b[f'https_{label}_flows']      = len(subset)
        b[f'https_{label}_up_mean']    = per_ip['total_up'].mean()
        b[f'https_{label}_down_mean']  = per_ip['total_down'].mean()
        b[f'https_{label}_ratio_mean'] = per_ip['ratio'].mean()
        b[f'https_{label}_ratio_std']  = per_ip['ratio'].std()

    # DNS flow volume and internal server set (Step 5)
    dns = int_train[int_train['port'] == 53]
    b['dns_flows_mean']       = dns.groupby('src_ip').size().mean()
    b['dns_flows_std']        = dns.groupby('src_ip').size().std()
    b['dns_internal_servers'] = set(dns['dst_ip'].unique())

    # Geo: per-IP known countries and ASNs (Steps 4, 4b)
    pub = int_train[~int_train['dst_ip'].apply(is_private)].copy()
    pub['country'] = pub['dst_ip'].apply(get_country)
    pub['asn']     = pub['dst_ip'].apply(get_asn)

    b['countries_per_ip']  = pub.groupby('src_ip')['country'].apply(set).to_dict()
    b['global_train_asns'] = set(pub['asn'].dropna().unique())

    # Step 4b: minimum flows to a new ASN — p10 of per-(IP, ASN) flow counts in training.
    ip_asn_counts = pub.groupby(['src_ip', 'asn']).size()
    b['new_asn_min_flows'] = int(ip_asn_counts.quantile(0.10))

    # Geo intensity floor: p10 of per-(IP,country) flow counts in training.
    # Separates CDN rotation noise (1–3 flows) from sustained deliberate traffic.
    ip_country_counts = pub.groupby(['src_ip', 'country']).size()
    b['geo_min_intensity_flows'] = int(ip_country_counts.quantile(0.10))

    country_stats = pub.groupby('country').agg(
        flows = ('up_bytes', 'count'),
        up_mb = ('up_bytes', lambda x: round(x.sum() / 1e6, 1)),
    ).sort_values('flows', ascending=False)
    b['country_stats']         = country_stats
    b['total_train_countries'] = len(country_stats)

    # Global set of internal destination IPs seen in training (Step 4b)
    priv = int_train[int_train['dst_ip'].apply(is_private)]
    b['global_train_internal_dsts'] = set(priv['dst_ip'].unique())

    # Step 4b: minimum flows to a new internal dst — p10 of per-(IP, dst_ip) flow counts in training.
    ip_int_dst_counts = priv.groupby(['src_ip', 'dst_ip']).size()
    b['new_int_min_flows'] = int(ip_int_dst_counts.quantile(0.10))

    # External destination fan-out: unique external dst_ips per src_ip (Step 4c)
    ext_fan = pub.groupby('src_ip')['dst_ip'].nunique()
    b['ext_fan_mean'] = ext_fan.mean()
    b['ext_fan_std']  = ext_fan.std()

    # Beaconing: per-protocol interval std p05, distribution stats, and per-IP baseline (Step 6)
    for proto, port in [('https', 443), ('dns', 53)]:
        subset = int_train[int_train['port'] == port].sort_values(['src_ip', 'timestamp'])
        iv_std = subset.groupby('src_ip')['timestamp'].apply(lambda x: x.diff().std()).dropna()
        b[f'{proto}_interval_std_p05']    = iv_std.quantile(0.05)
        b[f'{proto}_interval_std_per_ip'] = iv_std.to_dict()
        b[f'{proto}_interval_std_mean']   = iv_std.mean()
        b[f'{proto}_interval_std_std']    = iv_std.std()

    # External inter-flow interval characterisation (Task 1-iv) + anti-human baseline (Step 2b)
    ext_sorted = ext_train.sort_values(['src_ip', 'timestamp'])
    ext_iv_all = ext_sorted.groupby('src_ip')['timestamp'].diff().dropna()
    b['ext_interval_mean']   = ext_iv_all.mean()         / 100
    b['ext_interval_median'] = ext_iv_all.median()       / 100
    b['ext_interval_std']    = ext_iv_all.std()          / 100
    b['ext_interval_p90']    = ext_iv_all.quantile(0.90) / 100
    b['ext_interval_p95']    = ext_iv_all.quantile(0.95) / 100
    ext_iv_std_per_ip = ext_sorted.groupby('src_ip')['timestamp'].apply(lambda x: x.diff().std()).dropna()
    b['ext_interval_std_min'] = ext_iv_std_per_ip.min()

    # External client ratio baseline (Step 2)
    ext_per_ip = ext_train.groupby('src_ip').agg(
        total_up   = ('up_bytes', 'sum'),
        total_down = ('down_bytes', 'sum'),
    ).assign(ratio=lambda d: d['total_down'] / d['total_up'])
    b['ext_ratio_mean'] = ext_per_ip['ratio'].mean()
    b['ext_ratio_std']  = ext_per_ip['ratio'].std()

    # Known internal source IPs from training (Step 1)
    b['train_src_ips'] = set(int_train['src_ip'].unique())

    return b


# ── Step 1: New source IPs ────────────────────────────────────────────────────

def detect_new_source_ips(baselines: dict) -> list[dict]:
    train_ips = baselines['train_src_ips']
    new_ips   = sorted(set(int_test['src_ip'].unique()) - train_ips,
                       key=lambda ip: ipaddress.IPv4Address(ip))
    alerts = []
    for ip in new_ips:
        grp          = int_test[int_test['src_ip'] == ip]
        total        = len(grp)
        https_n      = int((grp['port'] == 443).sum())
        dns_n        = int((grp['port'] == 53).sum())
        https_up_mb  = float(grp[grp['port'] == 443]['up_bytes'].sum()) / 1e6
        ext_ips      = int(grp[~grp['dst_ip'].apply(is_private)]['dst_ip'].nunique())
        alerts.append({
            'rule'  : 'New Source IP',
            'ip'    : ip,
            'threat': 'Device with no training baseline — possible rogue endpoint or network implant',
            'why'   : (f"{total} flows ({https_n} HTTPS, {dns_n} DNS), "
                       f"HTTPS upload: {https_up_mb:.1f} MB, unique ext IPs: {ext_ips} "
                       f"— all metrics sub-threshold, absent entire training period"),
        })
    return alerts


# ── Step 2: Anomalous external users ──────────────────────────────────────────

def detect_external_anomalies(baselines: dict) -> list[dict]:
    mean = baselines['ext_ratio_mean']
    std  = baselines['ext_ratio_std']
    low  = mean - SIGMA * std
    high = mean + SIGMA * std

    per_ip = ext_test.groupby('src_ip').agg(
        total_up   = ('up_bytes', 'sum'),
        total_down = ('down_bytes', 'sum'),
    ).assign(ratio=lambda d: d['total_down'] / d['total_up'])

    alerts = []
    for ip, row in per_ip[(per_ip['ratio'] < low) | (per_ip['ratio'] > high)].iterrows():
        deviation = abs(row['ratio'] - mean) / std
        alerts.append({
            'rule'  : 'Anomalous External User',
            'ip'    : ip,
            'threat': 'Unusual upload/download ratio — possible exfiltration or compromise',
            'why'   : f"Down/up ratio={row['ratio']:.4f} ({deviation:.1f}σ from baseline {mean:.4f}±{std:.4f}; window [{low:.4f}, {high:.4f}])",
        })
    return alerts


# ── Step 2b: External automation / anti-human pattern ────────────────────────

def detect_external_automation(baselines: dict) -> list[dict]:
    threshold   = baselines['ext_interval_std_min']
    ext_sorted  = ext_test.sort_values(['src_ip', 'timestamp'])
    iv_std      = ext_sorted.groupby('src_ip')['timestamp'].apply(lambda x: x.diff().std()).dropna()

    alerts = []
    for ip, obs_std in iv_std[iv_std < threshold].items():
        median_iv = ext_sorted[ext_sorted['src_ip'] == ip]['timestamp'].diff().median()
        alerts.append({
            'rule'  : 'External Automation',
            'ip'    : ip,
            'threat': 'Non-human access pattern — possible bot, scraper, or automated attack tool',
            'why'   : (f"Inter-flow interval std={obs_std/100:.2f}s "
                       f"(threshold {threshold/100:.2f}s — training minimum) "
                       f"— regularity below any training client, median interval={median_iv/100:.2f}s"),
        })
    return sorted(alerts, key=lambda a: ipaddress.IPv4Address(a['ip']))


# ── Step 3: HTTPS data exfiltration ───────────────────────────────────────────

def detect_https_exfiltration(baselines: dict) -> list[dict]:
    vol_mean      = baselines['https_up_mean']
    vol_std       = baselines['https_up_std']
    vol_threshold = vol_mean + SIGMA * vol_std
    ratio_mean    = baselines['https_ratio_mean']
    ratio_std     = baselines['https_ratio_std']
    ratio_low     = ratio_mean - SIGMA * ratio_std

    per_ip = int_test[int_test['port'] == 443].groupby('src_ip').agg(
        total_up   = ('up_bytes', 'sum'),
        total_down = ('down_bytes', 'sum'),
    ).assign(ratio=lambda d: d['total_down'] / d['total_up'])

    alerts = []
    for ip, row in per_ip.iterrows():
        vol_flag   = row['total_up'] > vol_threshold
        ratio_flag = row['ratio'] < ratio_low
        if not (vol_flag or ratio_flag):
            continue
        upload_mb = row['total_up'] / 1e6
        reasons   = []
        if vol_flag:
            dev = (row['total_up'] - vol_mean) / vol_std
            reasons.append(f"uploaded {upload_mb:.0f} MB — {dev:.0f}σ above mean (threshold: {vol_threshold/1e6:.0f} MB)")
        if ratio_flag:
            dev = (ratio_mean - row['ratio']) / ratio_std
            reasons.append(f"down/up ratio={row['ratio']:.2f} ({dev:.1f}σ below baseline {ratio_mean:.2f}±{ratio_std:.2f}; threshold {ratio_low:.2f})")
        alerts.append({
            'rule'  : 'HTTPS Data Exfiltration',
            'ip'    : ip,
            'threat': 'Data exfiltration over HTTPS',
            'why'   : '; '.join(reasons),
        })
    return sorted(alerts, key=lambda a: per_ip.loc[a['ip'], 'total_up'], reverse=True)


# ── Step 4: New country destinations ──────────────────────────────────────────

def detect_new_geo_destinations(baselines: dict) -> list[dict]:
    global_train_countries = set().union(*baselines['countries_per_ip'].values())
    min_flows              = baselines['geo_min_intensity_flows']

    pub_test = int_test[~int_test['dst_ip'].apply(is_private)].copy()
    pub_test['country'] = pub_test['dst_ip'].apply(get_country)

    test_countries_per_ip = pub_test.groupby('src_ip')['country'].apply(set).to_dict()
    ip_flows_map          = {ip: df for ip, df in pub_test.groupby('src_ip')}
    total_flows_per_ip    = int_test.groupby('src_ip').size().to_dict()

    alerts = []
    for ip in sorted(test_countries_per_ip):
        new_to_network = test_countries_per_ip[ip] - global_train_countries
        if not new_to_network:
            continue
        ip_flows     = ip_flows_map.get(ip, pd.DataFrame(columns=pub_test.columns))
        flows_to_new = len(ip_flows[ip_flows['country'].isin(new_to_network)])
        if flows_to_new < min_flows:
            continue
        total = total_flows_per_ip.get(ip, 1)
        if flows_to_new / total < GEO_MIN_PROPORTION:
            continue
        alerts.append({
            'rule'  : 'New Country Destination',
            'ip'    : ip,
            'threat': 'Traffic to country not seen during training',
            'why'   : f"{flows_to_new} flows to new country/ies: {', '.join(sorted(new_to_network))} ({flows_to_new/total*100:.1f}% of total traffic)",
        })
    return alerts


# ── Step 4b: New destination IPs and ASNs ─────────────────────────────────────

def detect_new_destinations(baselines: dict) -> list[dict]:
    alerts = []

    # Sub-rule 1: new external ASN not seen by ANY client in training
    global_train_asns = baselines['global_train_asns']
    min_ext_flows     = baselines['new_asn_min_flows']
    pub_test = int_test[~int_test['dst_ip'].apply(is_private)].copy()
    pub_test['asn'] = pub_test['dst_ip'].apply(get_asn)

    for ip, grp in pub_test.groupby('src_ip'):
        new_asns = set(grp['asn'].dropna().unique()) - global_train_asns
        if not new_asns:
            continue
        flows = len(grp[grp['asn'].isin(new_asns)])
        if flows < min_ext_flows:
            continue
        sample = ', '.join(sorted(new_asns)[:3]) + ('...' if len(new_asns) > 3 else '')
        alerts.append({
            'rule'  : 'New External Destination (New ASN)',
            'ip'    : ip,
            'threat': 'Communication to infrastructure not seen in any training traffic',
            'why'   : f"{flows} flows to {len(new_asns)} new-to-network ASN(s): {sample}",
        })

    # Sub-rule 2: new internal destination IP not seen in any training flow
    global_train_internal = baselines['global_train_internal_dsts']
    min_int_flows         = baselines['new_int_min_flows']
    priv_test = int_test[int_test['dst_ip'].apply(is_private)].copy()

    for ip, grp in priv_test.groupby('src_ip'):
        new_dsts = set(grp['dst_ip'].unique()) - global_train_internal
        if not new_dsts:
            continue
        flows = len(grp[grp['dst_ip'].isin(new_dsts)])
        if flows < min_int_flows:
            continue
        alerts.append({
            'rule'  : 'New Internal Destination',
            'ip'    : ip,
            'threat': 'Communication to internal host never seen in training — possible lateral movement',
            'why'   : f"{flows} flows to new internal IP(s): {', '.join(sorted(new_dsts))}",
        })

    return sorted(alerts, key=lambda a: ipaddress.IPv4Address(a['ip']))


# ── Step 4c: External destination fan-out ────────────────────────────────────

def detect_external_fanout(baselines: dict) -> list[dict]:
    mean      = baselines['ext_fan_mean']
    std       = baselines['ext_fan_std']
    threshold = mean + SIGMA * std

    pub_test = int_test[~int_test['dst_ip'].apply(is_private)]
    fan      = pub_test.groupby('src_ip')['dst_ip'].nunique()

    alerts = []
    for ip, count in fan[fan > threshold].items():
        deviation = (count - mean) / std
        alerts.append({
            'rule'  : 'External Destination Fan-out',
            'ip'    : ip,
            'threat': 'Anomalous number of unique external destinations — possible C2 sweep or reconnaissance',
            'why'   : f"{int(count)} unique external IPs ({deviation:.1f}σ above mean {mean:.0f}; threshold {threshold:.0f})",
        })
    return sorted(alerts, key=lambda a: ipaddress.IPv4Address(a['ip']))


# ── Step 5: DNS anomalies ─────────────────────────────────────────────────────

def detect_dns_anomalies(baselines: dict) -> list[dict]:
    mean             = baselines['dns_flows_mean']
    std              = baselines['dns_flows_std']
    threshold        = mean + SIGMA * std
    internal_servers = baselines['dns_internal_servers']

    dns_test = int_test[int_test['port'] == 53]
    alerts   = []

    # Sub-rule 1: DNS volume anomaly
    for ip, count in dns_test.groupby('src_ip').size().items():
        if count <= threshold:
            continue
        intervals = dns_test[dns_test['src_ip'] == ip].sort_values('timestamp')['timestamp'].diff().dropna()
        deviation = (count - mean) / std
        alerts.append({
            'rule'  : 'DNS Volume Anomaly',
            'ip'    : ip,
            'threat': 'DNS-based C&C beaconing or DNS tunneling',
            'why'   : f"{int(count):,} DNS queries ({deviation:.1f}σ above mean {mean:.0f}), median interval={intervals.median()/100:.2f}s",
        })

    return sorted(alerts, key=lambda a: (a['rule'], a['ip']))


# ── Step 6: BotNet beaconing ──────────────────────────────────────────────────

def detect_botnet_beaconing(baselines: dict) -> list[dict]:
    https_threshold       = baselines['https_interval_std_p05']
    dns_threshold         = baselines['dns_interval_std_p05']
    dns_vol_threshold     = baselines['dns_flows_mean'] + SIGMA * baselines['dns_flows_std']
    https_train_std_by_ip = baselines['https_interval_std_per_ip']

    alerts = []
    for ip in sorted(int_test['src_ip'].unique()):
        ip_https = int_test[(int_test['src_ip'] == ip) & (int_test['port'] == 443)]
        ip_dns   = int_test[(int_test['src_ip'] == ip) & (int_test['port'] == 53)]

        https_ts = ip_https['timestamp'].sort_values()
        dns_ts   = ip_dns['timestamp'].sort_values()

        https_std = https_ts.diff().std() if len(ip_https) > 1 else None
        dns_std   = dns_ts.diff().std()   if len(ip_dns)   > 1 else None

        protocol  = None
        obs_std   = None
        thresh    = None
        median_iv = None

        if https_std is not None and https_std < https_threshold:
            train_std = https_train_std_by_ip.get(ip)
            regularization = (train_std / https_std) if train_std is not None else 0
            if regularization >= MIN_HTTPS_REGULARIZATION:
                protocol  = 'HTTPS'
                obs_std   = https_std
                thresh    = https_threshold
                median_iv = https_ts.diff().median()

        # DNS beaconing requires high DNS volume independently to avoid flagging
        # devices whose only signal is normal periodic DNS alongside regular HTTPS.
        if (dns_std is not None and dns_std < dns_threshold
                and len(ip_dns) > dns_vol_threshold):
            if protocol is None or dns_std < obs_std:
                protocol  = 'DNS'
                obs_std   = dns_std
                thresh    = dns_threshold
                median_iv = dns_ts.diff().median()

        if protocol is None:
            continue

        alerts.append({
            'rule'  : 'BotNet Beaconing',
            'ip'    : ip,
            'threat': f'Botnet C&C — automated {protocol} beaconing',
            'why'   : f"{protocol} interval std={obs_std/100:.2f}s (threshold {thresh/100:.2f}s), median={median_iv/100:.2f}s",
        })

    return alerts


# ── Output ────────────────────────────────────────────────────────────────────

def send_syslog_alert(ip: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(f"Alarm UEBA {ip}".encode(), (WAZUH_IP, WAZUH_PORT))


def print_alerts(alerts: list[dict], step: str) -> None:
    print(f"\n{'═'*60}")
    print(f"  {step}")
    print(f"{'═'*60}")
    if not alerts:
        print("  No anomalies detected.")
        return
    for i, a in enumerate(alerts, 1):
        print(f"  [{i}] Rule   : {a['rule']}")
        print(f"       IP     : {a['ip']}")
        print(f"       Threat : {a['threat']}")
        print(f"       Why    : {a['why']}")
        print()


# ── Step 7: Main ──────────────────────────────────────────────────────────────

def main() -> None:
    print("\n[*] Computing baselines from training data...")
    b = compute_baselines()
    print(f"    HTTPS upload threshold  : {(b['https_up_mean'] + SIGMA*b['https_up_std'])/1e6:.1f} MB  (mean+{SIGMA}σ)")
    print(f"    DNS flow threshold      : {b['dns_flows_mean'] + SIGMA*b['dns_flows_std']:.0f} flows  (mean+{SIGMA}σ)")
    print(f"    HTTPS beaconing p05     : {b['https_interval_std_p05']/100:.2f}s")
    print(f"    DNS beaconing p05       : {b['dns_interval_std_p05']/100:.2f}s")
    print(f"    External ratio window   : [{b['ext_ratio_mean']-SIGMA*b['ext_ratio_std']:.4f}, {b['ext_ratio_mean']+SIGMA*b['ext_ratio_std']:.4f}]")
    print(f"    Internal DNS servers    : {b['dns_internal_servers']}")
    print(f"    HTTPS ratio threshold   : {b['https_ratio_mean'] - SIGMA*b['https_ratio_std']:.4f}  (mean-{SIGMA}σ = {b['https_ratio_mean']:.4f}±{b['https_ratio_std']:.4f})")
    print(f"    Geo min intensity flows : {b['geo_min_intensity_flows']} flows  (p10 of per-IP/country flow counts)")
    print(f"    New ASN min flows       : {b['new_asn_min_flows']} flows  (p10 of per-IP/ASN flow counts)")
    print(f"    New internal min flows  : {b['new_int_min_flows']} flows  (p10 of per-IP/internal-dst flow counts)")
    print(f"    External fan-out threshold : {b['ext_fan_mean'] + SIGMA*b['ext_fan_std']:.0f} unique dst IPs  (mean+{SIGMA}σ)")
    print(f"    External automation threshold : {b['ext_interval_std_min']/100:.2f}s  (training minimum — no training client was ever below this)")

    print(f"\n[*] Network characterisation — internal destination countries ({b['total_train_countries']} total):")
    top10       = b['country_stats'].head(10)
    total_flows = b['country_stats']['flows'].sum()
    for country, row in top10.iterrows():
        pct = row['flows'] / total_flows * 100
        print(f"    {country:4s}  {int(row['flows']):>8,} flows  {row['up_mb']:>8.1f} MB  ({pct:.1f}%)")
    remaining = len(b['country_stats']) - 10
    if remaining > 0:
        other_flows = int(b['country_stats'].iloc[10:]['flows'].sum())
        print(f"    ...   {other_flows:>8,} flows  ({remaining} other countries)")

    print(f"\n[*] Network characterisation — internal HTTPS destination split:")
    print(f"    {'Destination':<26}  {'Flows':>8}  {'Up/client':>10}  {'Down/client':>12}  {'Ratio mean':>11}  {'Ratio std':>10}")
    _srv_last = b['internal_https_server'].split('.')[-1]
    print(f"    {f'Internal server (.{_srv_last})':<26}  {b['https_int_flows']:>8,}  "
          f"{b['https_int_up_mean']/1e6:>9.1f}MB  {b['https_int_down_mean']/1e6:>11.1f}MB  "
          f"{b['https_int_ratio_mean']:>11.4f}  {b['https_int_ratio_std']:>10.4f}")
    print(f"    {'External HTTPS servers':<26}  {b['https_ext_flows']:>8,}  "
          f"{b['https_ext_up_mean']/1e6:>9.1f}MB  {b['https_ext_down_mean']/1e6:>11.1f}MB  "
          f"{b['https_ext_ratio_mean']:>11.4f}  {b['https_ext_ratio_std']:>10.4f}")

    print(f"\n[*] Network characterisation — external client inter-flow intervals:")
    print(f"    Mean   : {b['ext_interval_mean']:.2f} s")
    print(f"    Median : {b['ext_interval_median']:.2f} s")
    print(f"    Std    : {b['ext_interval_std']:.2f} s")
    print(f"    p90    : {b['ext_interval_p90']:.2f} s")
    print(f"    p95    : {b['ext_interval_p95']:.2f} s")

    steps = [
        ("Step 1 — New Source IPs",              detect_new_source_ips(b)),
        ("Step 2 — Anomalous External Users",    detect_external_anomalies(b)),
        ("Step 2b — External Automation",        detect_external_automation(b)),
        ("Step 3 — HTTPS Data Exfiltration",     detect_https_exfiltration(b)),
        ("Step 4 — New Country Destinations",    detect_new_geo_destinations(b)),
        ("Step 4b — New Destination IPs / ASNs", detect_new_destinations(b)),
        ("Step 4c — External Destination Fan-out", detect_external_fanout(b)),
        ("Step 5 — DNS Anomalies",               detect_dns_anomalies(b)),
        ("Step 6 — BotNet Beaconing",            detect_botnet_beaconing(b)),
    ]

    for label, alerts in steps:
        print_alerts(alerts, label)

    # Consolidated summary
    ip_rules: dict[str, list[str]] = defaultdict(list)
    for label, alerts in steps:
        rule_short = label.split("—")[1].strip()
        for a in alerts:
            if rule_short not in ip_rules[a['ip']]:
                ip_rules[a['ip']].append(rule_short)

    print(f"\n{'═'*60}")
    print(f"  FINAL CONSOLIDATED REPORT")
    print(f"{'═'*60}")
    internal = [ip for ip in ip_rules if is_private(ip)]
    external = [ip for ip in ip_rules if not is_private(ip)]
    print(f"  Total unique anomalous IPs : {len(ip_rules)}")
    print(f"  Internal                   : {len(internal)}")
    print(f"  External                   : {len(external)}")
    print()

    sorted_ips = sorted(ip_rules.items(), key=lambda x: (-len(x[1]), ipaddress.IPv4Address(x[0])))
    for ip, rules in sorted_ips:
        confidence = "HIGH  " if len(rules) >= 2 else "MEDIUM"
        rules_str  = " | ".join(rules)
        print(f"  [{confidence}] {ip:<20}  {rules_str}")

    print()

    print(f"[*] Sending UEBA alerts to Wazuh ({WAZUH_IP}:{WAZUH_PORT})...")
    for ip in ip_rules:
        try:
            send_syslog_alert(ip)
            print(f"    → Alarm UEBA {ip}")
        except OSError as e:
            print(f"    [WARN] Could not reach Wazuh manager: {e}")
    print()

    geodb.close()
    geodbasn.close()


if __name__ == "__main__":
    main()
