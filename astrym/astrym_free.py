#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Free 9.3.0 — бесплатные источники без API-ключей

FREE_VERSION = "9.3.0"

import time
from astrym_core import HAS_REQUESTS, _rl_sleep


def _req():
    import requests
    return requests


HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/120.0 Safari/537.36")
}


# ============================================================
# 1. XposedOrNot — замена HIBP (без ключа)
# ============================================================

def xposedornot_check(email):
    """Проверка утечек email через XposedOrNot (без ключа)."""
    if not HAS_REQUESTS:
        return None
    _rl_sleep()
    try:
        from urllib.parse import quote as _q
        encoded = _q(email, safe="")
        url = "https://api.xposedornot.com/v1/check-email/" + encoded
        r = _req().get(url, timeout=15, headers=HEADERS)
        if r.status_code == 200:
            d = r.json()
            breaches = d.get("breaches", [])
            if breaches and isinstance(breaches[0], list):
                breaches = breaches[0]
            return {
                "source": "xposedornot",
                "found": len(breaches) > 0,
                "breach_count": len(breaches),
                "breaches": [{"name": b} for b in breaches[:50]],
            }
        if r.status_code == 404:
            return {"source": "xposedornot", "found": False,
                    "breach_count": 0, "breaches": []}
        return {"source": "xposedornot", "error": "HTTP " + str(r.status_code)}
    except Exception as e:
        return {"source": "xposedornot", "error": str(e)[:100]}

def threatcrowd_domain(domain):
    """ThreatCrowd — альтернатива SecurityTrails для поддоменов."""
    if not HAS_REQUESTS:
        return None
    _rl_sleep()
    try:
        r = _req().get(
            "https://www.threatcrowd.org/searchApi/v2/domain/report/",
            params={"domain": domain}, timeout=15,
            headers=HEADERS)
        if r.status_code == 200:
            d = r.json()
            return {
                "source": "threatcrowd",
                "subdomains": d.get("subdomains", []) or [],
                "resolutions": d.get("resolutions", []) or [],
                "emails": d.get("emails", []) or [],
            }
    except Exception:
        pass
    return None


# ============================================================
# 3. ThreatMiner — passive DNS
# ============================================================

def threatminer_domain(domain):
    """ThreatMiner — passive DNS + subdomains."""
    if not HAS_REQUESTS:
        return None
    _rl_sleep()
    try:
        r = _req().get(
            "https://api.threatminer.org/v2/domain.php",
            params={"q": domain, "rt": "5"}, timeout=15,
            headers=HEADERS)
        if r.status_code == 200:
            d = r.json()
            if d.get("status_code") == "200":
                return {
                    "source": "threatminer",
                    "subdomains": d.get("results", []) or [],
                }
    except Exception:
        pass
    return None


# ============================================================
# 4. Wayback CDX — исторические URL домена
# ============================================================

def wayback_urls(domain, limit=300):
    """Wayback Machine CDX API — исторические URL.

    Ловит удалённые админки, старые API, забытые .env.
    """
    if not HAS_REQUESTS:
        return None
    _rl_sleep()
    try:
        r = _req().get(
            "http://web.archive.org/cdx/search/cdx",
            params={"url": domain + "/*", "output": "json",
                    "limit": str(limit), "collapse": "urlkey",
                    "fl": "original,statuscode,mimetype,timestamp"},
            timeout=25, headers=HEADERS)
        if r.status_code == 200:
            d = r.json()
            if not isinstance(d, list) or len(d) < 2:
                return {"source": "wayback", "count": 0, "urls": []}
            rows = d[1:]
            urls = []
            interesting = []
            for row in rows:
                if len(row) < 4:
                    continue
                u = row[0]
                urls.append(u)
                # фильтр интересных
                low = u.lower()
                if any(k in low for k in (
                        "admin", "login", "config", ".env", ".git",
                        "backup", "api/", "test", "dev", "staging",
                        "phpinfo", "wp-config", "internal", "private")):
                    interesting.append(u)
            return {
                "source": "wayback",
                "count": len(urls),
                "urls": urls[:200],
                "interesting": interesting[:50],
            }
    except Exception:
        pass
    return None


# ============================================================
# Хелпер: собрать всё для домена
# ============================================================

def collect_free_for_domain(domain):
    """Все бесплатные источники для домена — параллельно."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    tasks = {
        "threatcrowd": lambda: threatcrowd_domain(domain),
        "threatminer": lambda: threatminer_domain(domain),
        "wayback":     lambda: wayback_urls(domain, limit=200),
    }
    out = {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        fu = {ex.submit(fn): name for name, fn in tasks.items()}
        for f in as_completed(fu):
            name = fu[f]
            try:
                r = f.result()
                if r:
                    out[name] = r
            except Exception:
                pass
    return out


def collect_free_for_email(email):
    """Все бесплатные источники для email."""
    out = {}
    r = xposedornot_check(email)
    if r:
        out["xposedornot"] = r
    return out
