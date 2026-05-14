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

if __name__ == "__main__":
    print("\n[OK] ueba.py loaded — all paths and helpers verified.")
    print(f"     Dataset X = {DATASET}  (nmec: 108212 + 108749 = 216961 % 10 = 1)")
