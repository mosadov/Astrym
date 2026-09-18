#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Web 9.4.0 — permutation, HTTP probe, favicon, analytics

import warnings
warnings.filterwarnings('ignore')
WEB_VERSION = "9.4.0"

import re
import socket
import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from astrym_core import HAS_REQUESTS, HAS_DNS


# ============================================================
# PERMUTATION
# ============================================================

_PERM_SUFFIXES = [
    "dev", "dev1", "dev2", "test", "test1", "staging", "stg", "stage",
    "prod", "prod1", "production", "beta", "alpha", "rc", "preprod",
    "uat", "qa", "sit", "sandbox", "demo", "preview", "internal",
    "private", "public", "ext", "external", "old", "old1", "new", "new1",
    "v1", "v2", "v3", "v4", "backup", "bak", "us", "eu", "asia", "uk",
    "de", "fr", "ap", "cn", "api", "app", "web", "mobile", "static",
    "cdn", "assets", "admin", "portal", "auth", "sso", "account",
]

_PERM_PREFIXES = [
    "dev", "test", "stg", "prod", "beta", "alpha", "uat", "qa", "old",
    "new", "v1", "v2", "v3", "internal", "ext", "api", "app", "admin",
    "pre", "post", "us", "eu", "asia",
]

_PERM_NUMBERS = ["1", "2", "3", "01", "02"]


def permute_subs(known_subs, domain, limit=500):
    """Генерирует варианты из известных поддоменов.

    api.example.com → api-dev.example.com, dev-api.example.com,
                     api2.example.com, api1.example.com, ...
    """
    variants = set()
    for sub in known_subs:
        if not sub.endswith("." + domain):
            continue
        label = sub[:-len(domain) - 1].lower()
        if not label or "." in label:
            continue

        for s in _PERM_SUFFIXES:
            variants.add(label + "-" + s + "." + domain)
            variants.add(label + s + "." + domain)

        for p in _PERM_PREFIXES:
            variants.add(p + "-" + label + "." + domain)
            variants.add(p + label + "." + domain)

        for n in _PERM_NUMBERS:
            variants.add(label + n + "." + domain)
            variants.add(label + "-" + n + "." + domain)

        for s in _PERM_SUFFIXES:
            if label.endswith("-" + s):
                base = label[:-len(s) - 1]
                if base:
                    variants.add(base + "." + domain)
            if label.endswith(s) and len(label) > len(s) + 1:
                variants.add(label[:-len(s)] + "." + domain)

        if len(variants) >= limit:
            break

    known_lower = set(s.lower() for s in known_subs)
    return sorted(v for v in variants if v not in known_lower)[:limit]


def resolve_permutations(variants, workers=40, timeout=2.0):
    """Резолвит варианты через DNS."""
    if not HAS_DNS:
        return []
    import dns.resolver as _dns
    found = []

    def ck(h):
        try:
            ans = _dns.resolve(h, "A", lifetime=timeout)
            return (h, [a.to_text() for a in ans])
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(ck, variants):
            if r:
                found.append(r)
    return found


# ============================================================
# HTTP PROBE (замена httpx)
# ============================================================

_PROBE_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/120.0 Safari/537.36"),
}


def http_probe(host, timeout=5):
    """Проверяет HTTP и HTTPS, возвращает статус, title, сервер."""
    if not HAS_REQUESTS:
        return None
    import requests
    out = {"host": host, "http": None, "https": None,
           "title": None, "server": None, "status": None, "url": None}

    for scheme in ("https", "http"):
        url = scheme + "://" + host
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True,
                             headers=_PROBE_HEADERS, verify=False)
            out[scheme] = r.status_code
            out["url"] = r.url
            out["status"] = r.status_code
            out["server"] = r.headers.get("Server")
            tm = re.search(r"<title[^>]*>(.*?)</title>",
                           r.text[:5000], re.I | re.S)
            if tm:
                out["title"] = tm.group(1).strip()[:120]
            break
        except Exception:
            continue
    return out if (out["http"] or out["https"]) else None


def probe_many(hosts, workers=30):
    """Параллельный HTTP probe."""
    if not HAS_REQUESTS or not hosts:
        return []
    results = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fu = {ex.submit(http_probe, h): h for h in hosts}
        for f in as_completed(fu):
            try:
                r = f.result()
                if r:
                    results.append(r)
            except Exception:
                pass
    return results


# ============================================================
# FAVICON HASH (MurmurHash3)
# ============================================================

def _murmur3_32(data, seed=0):
    """Pure Python MurmurHash3 x86 32-bit."""
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    rounded_end = length & 0xfffffffc

    for i in range(0, rounded_end, 4):
        k1 = ((data[i] & 0xff) |
              ((data[i+1] & 0xff) << 8) |
              ((data[i+2] & 0xff) << 16) |
              (data[i+3] << 24)) & 0xffffffff
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff

    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (data[rounded_end + 2] & 0xff) << 16
    if val in (2, 3):
        k1 |= (data[rounded_end + 1] & 0xff) << 8
    if val in (1, 2, 3):
        k1 |= data[rounded_end] & 0xff
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    return h1


def favicon_hash(url):
    """Возвращает MurmurHash3 от base64(favicon.ico).

    Совпадает с Shodan → можно сравнивать сайты через Shodan.
    """
    if not HAS_REQUESTS:
        return None
    import requests
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = requests.get(url.rstrip("/") + "/favicon.ico",
                         timeout=10, headers=_PROBE_HEADERS,
                         allow_redirects=True, verify=False)
        if r.status_code != 200 or not r.content:
            return None
        b64 = base64.encodebytes(r.content)
        h = _murmur3_32(b64)
        if h > 0x7fffffff:
            h -= 0x100000000
        return h
    except Exception:
        return None


# ============================================================
# SHARED ANALYTICS
# ============================================================

_ANALYTICS_PATTERNS = [
    ("google_analytics", r"UA-\d{4,10}-\d{1,4}"),
    ("google_analytics_v4", r"G-[A-Z0-9]{8,12}"),
    ("google_tag_manager", r"GTM-[A-Z0-9]{4,10}"),
    ("google_adsense", r"ca-pub-\d{10,20}"),
    ("facebook_pixel", r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]"),
    ("yandex_metrica", r"ym\(\s*(\d{5,10})"),
    ("hotjar", r"hjid['\"]?\s*[:=]\s*(\d{5,10})"),
    ("intercom", r"intercomSettings\s*=\s*\{[^}]*app_id['\"]?\s*[:=]\s*['\"]?([a-z0-9]{6,10})"),
    ("mixpanel", r"mixpanel\.init\(\s*['\"]([a-f0-9]{20,40})"),
    ("segment", r"analytics\.load\(\s*['\"]([a-zA-Z0-9]{6,30})"),
    ("clarity", r"clarity\.ms.*?projectId['\"]?\s*[:=]\s*['\"]?([a-z0-9]{6,15})"),
]


def extract_analytics(html):
    """Ищет tracking IDs в HTML."""
    out = {}
    if not html:
        return out
    text = html[:200000]
    for name, pat in _ANALYTICS_PATTERNS:
        try:
            matches = re.findall(pat, text, re.I)
            if matches:
                flat = []
                for m in matches:
                    if isinstance(m, tuple):
                        flat.extend(m)
                    else:
                        flat.append(m)
                cleaned = sorted(set(str(x) for x in flat if x))
                if cleaned:
                    out[name] = cleaned[:10]
        except Exception:
            continue
    return out


def fetch_and_extract_analytics(url, timeout=10):
    """Загружает URL и извлекает analytics IDs."""
    if not HAS_REQUESTS:
        return {}
    import requests
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        r = requests.get(url, timeout=timeout, headers=_PROBE_HEADERS,
                         allow_redirects=True, verify=False)
        if r.status_code == 200:
            return extract_analytics(r.text)
    except Exception:
        pass
    return {}


# ============================================================
# CLI-ТЕСТ
# ============================================================

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage:")
        print("  astrym_web.py probe <host>")
        print("  astrym_web.py favicon <host>")
        print("  astrym_web.py analytics <host>")
        print("  astrym_web.py permute <domain> sub1 sub2 ...")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "probe" and len(sys.argv) >= 3:
        r = http_probe(sys.argv[2])
        print(r)
    elif cmd == "favicon" and len(sys.argv) >= 3:
        h = favicon_hash(sys.argv[2])
        print("favicon mmh3: " + str(h))
    elif cmd == "analytics" and len(sys.argv) >= 3:
        a = fetch_and_extract_analytics(sys.argv[2])
        for k, v in a.items():
            print(k + ": " + ", ".join(v))
    elif cmd == "permute" and len(sys.argv) >= 3:
        domain = sys.argv[2]
        known = sys.argv[3:] or ["api." + domain, "dev." + domain, "admin." + domain]
        perms = permute_subs(known, domain, limit=30)
        for p in perms:
            print(p)
