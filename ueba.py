import pandas as pd
import numpy as np
import ipaddress
import socket
import geoip2.database
from collections import defaultdict

# ── Paths ─────────────────────────────────────────────────────────────────────
DATASET = 1
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

# ── Step 1: Baselines ──────────────────────────────────────────────────────────

def compute_baselines() -> dict:
    b = {}

    # HTTPS upload volume (Step 3)
    https = int_train[int_train['port'] == 443]
    https_per_ip = https.groupby('src_ip').agg(
        total_up   = ('up_bytes', 'sum'),
        total_down = ('down_bytes', 'sum'),
    )
    b['https_up_mean'] = https_per_ip['total_up'].mean()
    b['https_up_std']  = https_per_ip['total_up'].std()

    # HTTPS destination split: internal server vs external (characterisation only)
    INTERNAL_HTTPS_SERVER = '192.168.101.240'
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

    b['countries_per_ip']        = pub.groupby('src_ip')['country'].apply(set).to_dict()
    b['global_train_asns']       = set(pub['asn'].dropna().unique())
    b['geo_min_intensity_flows'] = 10

    country_stats = pub.groupby('country').agg(
        flows = ('up_bytes', 'count'),
        up_mb = ('up_bytes', lambda x: round(x.sum() / 1e6, 1)),
    ).sort_values('flows', ascending=False)
    b['country_stats']         = country_stats
    b['total_train_countries'] = len(country_stats)

    # Global set of internal destination IPs seen in training (Step 4b)
    priv = int_train[int_train['dst_ip'].apply(is_private)]
    b['global_train_internal_dsts'] = set(priv['dst_ip'].unique())

    # External destination fan-out: unique external dst_ips per src_ip (Step 4c)
    ext_fan = pub.groupby('src_ip')['dst_ip'].nunique()
    b['ext_fan_mean'] = ext_fan.mean()
    b['ext_fan_std']  = ext_fan.std()

    # Beaconing: per-protocol interval std p05 and per-IP baseline (Step 6)
    for proto, port in [('https', 443), ('dns', 53)]:
        subset = int_train[int_train['port'] == port].sort_values(['src_ip', 'timestamp'])
        iv_std = subset.groupby('src_ip')['timestamp'].apply(lambda x: x.diff().std()).dropna()
        b[f'{proto}_interval_std_p05']    = iv_std.quantile(0.05)
        b[f'{proto}_interval_std_per_ip'] = iv_std.to_dict()

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
        grp      = int_test[int_test['src_ip'] == ip]
        total    = len(grp)
        https_n  = int((grp['port'] == 443).sum())
        dns_n    = int((grp['port'] == 53).sum())
        alerts.append({
            'rule'  : 'New Source IP',
            'ip'    : ip,
            'threat': 'Device with no training baseline — possible rogue endpoint or network implant',
            'why'   : f"{total} flows ({https_n} HTTPS, {dns_n} DNS) from IP absent in entire training period",
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


# ── Step 3: HTTPS data exfiltration ───────────────────────────────────────────

def detect_https_exfiltration(baselines: dict) -> list[dict]:
    mean      = baselines['https_up_mean']
    std       = baselines['https_up_std']
    threshold = mean + SIGMA * std

    per_ip = int_test[int_test['port'] == 443].groupby('src_ip').agg(
        total_up = ('up_bytes', 'sum'),
    )

    alerts = []
    for ip, row in per_ip[per_ip['total_up'] > threshold].iterrows():
        upload_mb = row['total_up'] / 1e6
        deviation = (row['total_up'] - mean) / std
        alerts.append({
            'rule'  : 'HTTPS Data Exfiltration',
            'ip'    : ip,
            'threat': 'Data exfiltration over HTTPS',
            'why'   : f"Uploaded {upload_mb:.0f} MB — {deviation:.0f}σ above mean (threshold: {threshold/1e6:.0f} MB)",
        })
    return sorted(alerts, key=lambda a: float(a['why'].split()[1]), reverse=True)


# ── Step 4: New country destinations ──────────────────────────────────────────

def detect_new_geo_destinations(baselines: dict) -> list[dict]:
    global_train_countries = set().union(*baselines['countries_per_ip'].values())
    min_flows              = baselines['geo_min_intensity_flows']

    pub_test = int_test[~int_test['dst_ip'].apply(is_private)].copy()
    pub_test['country'] = pub_test['dst_ip'].apply(get_country)

    test_countries_per_ip = pub_test.groupby('src_ip')['country'].apply(set).to_dict()
    ip_flows_map          = {ip: df for ip, df in pub_test.groupby('src_ip')}

    alerts = []
    for ip in sorted(test_countries_per_ip):
        new_to_network = test_countries_per_ip[ip] - global_train_countries
        if not new_to_network:
            continue
        ip_flows     = ip_flows_map.get(ip, pd.DataFrame(columns=pub_test.columns))
        flows_to_new = len(ip_flows[ip_flows['country'].isin(new_to_network)])
        if flows_to_new < min_flows:
            continue
        alerts.append({
            'rule'  : 'New Country Destination',
            'ip'    : ip,
            'threat': 'Traffic to country not seen during training',
            'why'   : f"{flows_to_new} flows to new country/ies: {', '.join(sorted(new_to_network))}",
        })
    return alerts


# ── Step 4b: New destination IPs and ASNs ─────────────────────────────────────

MIN_NEW_EXTERNAL_FLOWS = 10
MIN_NEW_INTERNAL_FLOWS = 5

def detect_new_destinations(baselines: dict) -> list[dict]:
    alerts = []

    # Sub-rule 1: new external ASN not seen by ANY client in training
    global_train_asns = baselines['global_train_asns']
    pub_test = int_test[~int_test['dst_ip'].apply(is_private)].copy()
    pub_test['asn'] = pub_test['dst_ip'].apply(get_asn)

    for ip, grp in pub_test.groupby('src_ip'):
        new_asns = set(grp['asn'].dropna().unique()) - global_train_asns
        if not new_asns:
            continue
        flows = len(grp[grp['asn'].isin(new_asns)])
        if flows < MIN_NEW_EXTERNAL_FLOWS:
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
    priv_test = int_test[int_test['dst_ip'].apply(is_private)].copy()

    for ip, grp in priv_test.groupby('src_ip'):
        new_dsts = set(grp['dst_ip'].unique()) - global_train_internal
        if not new_dsts:
            continue
        flows = len(grp[grp['dst_ip'].isin(new_dsts)])
        if flows < MIN_NEW_INTERNAL_FLOWS:
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
            'why'   : f"{int(count):,} DNS queries ({deviation:.1f}σ above mean {mean:.0f}), median interval={intervals.median():.1f}s",
        })

    # Sub-rule 2: DNS to public server (zero-threshold)
    public_dns = dns_test[~dns_test['dst_ip'].isin(internal_servers)]
    for ip in sorted(public_dns['src_ip'].unique()):
        dst_ips = sorted(public_dns[public_dns['src_ip'] == ip]['dst_ip'].unique())
        count   = len(public_dns[public_dns['src_ip'] == ip])
        alerts.append({
            'rule'  : 'DNS to Public Server',
            'ip'    : ip,
            'threat': 'DNS tunneling or C&C — bypassing internal resolvers',
            'why'   : f"{count} queries sent to external DNS: {', '.join(dst_ips)}",
        })

    return sorted(alerts, key=lambda a: (a['rule'], a['ip']))


# ── Step 6: BotNet beaconing ──────────────────────────────────────────────────

# Minimum ratio of (training interval std) / (test interval std) to confirm
# that the device became genuinely more regular in the test period, not just
# that it naturally has tight intervals. Derived from analysis: confirmed
# beacons show ≥1.84×; false-positive .160 shows only 1.17×.
MIN_HTTPS_REGULARIZATION = 1.5

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
            regularization = (train_std / https_std) if train_std else 0
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
            'why'   : f"{protocol} interval std={obs_std:.0f}s (threshold {thresh:.0f}s), median={median_iv:.1f}s",
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
    print(f"    HTTPS beaconing p05     : {b['https_interval_std_p05']:.1f}s")
    print(f"    DNS beaconing p05       : {b['dns_interval_std_p05']:.1f}s")
    print(f"    External ratio window   : [{b['ext_ratio_mean']-SIGMA*b['ext_ratio_std']:.4f}, {b['ext_ratio_mean']+SIGMA*b['ext_ratio_std']:.4f}]")
    print(f"    Internal DNS servers    : {b['dns_internal_servers']}")
    print(f"    Geo min intensity flows : {b['geo_min_intensity_flows']}")
    print(f"    External fan-out threshold : {b['ext_fan_mean'] + SIGMA*b['ext_fan_std']:.0f} unique dst IPs  (mean+{SIGMA}σ)")

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
    print(f"    {'Internal server (.240)':<26}  {b['https_int_flows']:>8,}  "
          f"{b['https_int_up_mean']/1e6:>9.1f}MB  {b['https_int_down_mean']/1e6:>11.1f}MB  "
          f"{b['https_int_ratio_mean']:>11.4f}  {b['https_int_ratio_std']:>10.4f}")
    print(f"    {'External HTTPS servers':<26}  {b['https_ext_flows']:>8,}  "
          f"{b['https_ext_up_mean']/1e6:>9.1f}MB  {b['https_ext_down_mean']/1e6:>11.1f}MB  "
          f"{b['https_ext_ratio_mean']:>11.4f}  {b['https_ext_ratio_std']:>10.4f}")

    steps = [
        ("Step 1 — New Source IPs",              detect_new_source_ips(b)),
        ("Step 2 — Anomalous External Users",    detect_external_anomalies(b)),
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
    internal = [ip for ip in ip_rules if ip.startswith('192.168')]
    external = [ip for ip in ip_rules if not ip.startswith('192.168')]
    print(f"  Total unique anomalous IPs : {len(ip_rules)}")
    print(f"  Internal (192.168.101.x)   : {len(internal)}")
    print(f"  External (188.83.72.x)     : {len(external)}")
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
