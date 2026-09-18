#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM ASN 9.5.0 — ASN discovery + CNAME chain
# Все источники без ключей

ASN_VERSION = "9.5.0"

import re
import socket
import warnings
warnings.filterwarnings("ignore")

from astrym_core import (
    HAS_REQUESTS, HAS_DNS, now_iso, hist_record,
    c_ok, c_warn, c_err, c_info, c_muted, section,
)

try:
    import requests
except ImportError:
    requests = None

try:
    import dns.resolver
except ImportError:
    dns = None


HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
}


# ============================================================
# ASN DISCOVERY (без ключей)
# ============================================================

def _norm_asn(asn):
    s = str(asn).strip().upper()
    if not s.startswith("AS"):
        s = "AS" + s
    return s


def asn_peers_bgpview(asn, timeout=20):
    """Peers ASN (upstream + downstream) через RIPE Stat asn-neighbours.

    Сохранены имя функции и форма ответа BGPView:
      {"upstreams": [...], "downstreams": [...]}
    """
    asn_num = _asn_normalize(asn) if "_asn_normalize" in globals() else None
    if asn_num is None:
        s = str(asn).strip().upper().lstrip("AS")
        asn_num = int(s) if s.isdigit() else None
    if asn_num is None:
        return {"upstreams": [], "downstreams": []}

    out = {"upstreams": [], "downstreams": []}
    try:
        data = _ripe_get(
            "asn-neighbours/data.json",
            {"resource": f"AS{asn_num}"},
            timeout=timeout,
        )
    except Exception as e:
        print(f"[astrym_asn] RIPE Stat asn-neighbours fail for AS{asn_num}: {e}")
        return out

    # RIPE отдаёт neighbours: [{"asn": N, "type": "left"|"right",
    #                          "power": int, "v4_peers":..., "v6_peers":...}]
    # left  = upstream (тот, кто анонсит нам)
    # right = downstream (кому анонсим мы)
    for nb in data.get("neighbours", []) or []:
        entry = {
            "asn": "AS" + str(nb.get("asn")),
            "name": nb.get("name") or "",
            "description": nb.get("description") or nb.get("name") or "",
        }
        t = (nb.get("type") or "").lower()
        if t == "left":
            out["upstreams"].append(entry)
        elif t == "right":
            out["downstreams"].append(entry)

    # RIPE может не заполнять "type" — тогда кладём всех в upstreams
    if not out["upstreams"] and not out["downstreams"]:
        for nb in data.get("neighbours", []) or []:
            out["upstreams"].append({
                "asn": "AS" + str(nb.get("asn")),
                "name": nb.get("name") or "",
                "description": nb.get("name") or "",
            })

    out["upstreams"] = out["upstreams"][:20]
    out["downstreams"] = out["downstreams"][:20]
    out["source"] = "ripe-stat"
    return out


def asn_reverse_ripe(asn):
    """Reverse DNS для префиксов через RIPE Stat."""
    if not HAS_REQUESTS:
        return []
    asn = _norm_asn(asn)
    num = asn[2:]
    try:
        r = requests.get(
            "https://stat.ripe.net/data/announced-prefixes/data.json",
            params={"resource": "AS" + num}, timeout=20, headers=HEADERS)
        if r.status_code == 200:
            d = r.json()
            prefixes = d.get("data", {}).get("prefixes", [])
            return [p.get("prefix") for p in prefixes]
    except Exception:
        pass
    return []


def collect_asn(asn):
    """Полный ASN-анализ."""
    asn = _norm_asn(asn)
    out = {
        "meta": {"type": "asn", "target": asn,
                 "generated_at": now_iso(),
                 "tool": "ASTRYM " + ASN_VERSION},
        "info": asn_info_bgpview(asn) or {},
        "prefixes": asn_prefixes_bgpview(asn),
        "peers": asn_peers_bgpview(asn),
        "ripe_prefixes": asn_reverse_ripe(asn),
    }
    return out


def run_asn(target, extras=False):
    d = collect_asn(target)
    if not d.get("info") and not d.get("prefixes"):
        c_err("ASN не найден или источник недоступен")
        return None
    hist_record("asn", target,
                {"prefixes": len(d.get("prefixes", [])),
                 "name": d.get("info", {}).get("name")})
    return d


# ============================================================
# CNAME CHAIN TRACING
# ============================================================

def _resolve_cname(host, timeout=3.0):
    """Один шаг CNAME."""
    if not HAS_DNS:
        return None
    try:
        ans = dns.resolver.resolve(host, "CNAME", lifetime=timeout)
        if ans:
            return str(ans[0]).rstrip(".").lower()
    except Exception:
        pass
    return None


def _resolve_a(host, timeout=3.0):
    if not HAS_DNS:
        return []
    try:
        ans = dns.resolver.resolve(host, "A", lifetime=timeout)
        return [str(a) for a in ans] if ans else []
    except Exception:
        return []


def trace_cname_chain(host, max_hops=15, timeout=3.0):
    """Полный путь CNAME: хост → cdn → origin.

    Returns:
        {
            "start": host,
            "chain": [{"host": ..., "cname": ..., "ips": [...]}],
            "final_host": ...,
            "final_ips": [...],
            "hops": int,
        }
    """
    chain = []
    visited = set()
    current = host.lower().rstrip(".")

    for _ in range(max_hops):
        if current in visited:
            break
        visited.add(current)

        cname = _resolve_cname(current, timeout)
        ips = _resolve_a(current, timeout)

        step = {"host": current, "cname": cname, "ips": ips}
        chain.append(step)

        if not cname:
            break
        current = cname

    return {
        "start": host,
        "chain": chain,
        "final_host": chain[-1]["host"] if chain else host,
        "final_ips": chain[-1]["ips"] if chain else [],
        "hops": len(chain),
    }


def collect_cname_chain(domain):
    """CNAME chain + список поддоменов с разными CNAME."""
    out = {
        "meta": {"type": "cname-chain", "target": domain,
                 "generated_at": now_iso(),
                 "tool": "ASTRYM " + ASN_VERSION},
        "chain": trace_cname_chain(domain),
        "records": [],
    }
    try:
        if HAS_DNS:
            ans = dns.resolver.resolve(domain, "CNAME", lifetime=3)
            for r in ans:
                target = str(r).rstrip(".").lower()
                sub_chain = trace_cname_chain(target)
                out["records"].append({
                    "target": target,
                    "final_host": sub_chain["final_host"],
                    "final_ips": sub_chain["final_ips"],
                    "chain_len": sub_chain["hops"],
                })
    except Exception:
        pass
    return out


def run_cname(target, extras=False):
    d = collect_cname_chain(target)
    hist_record("cname", target,
                {"hops": d.get("chain", {}).get("hops", 0)})
    return d


# ============================================================
# RENDER
# ============================================================

def render_asn(d):
    from astrym_core import header, kv
    header("ASN Discovery", d["meta"]["target"])
    info = d.get("info", {})

    if info:
        section("ASN Info")
        kv([
            ("ASN", info.get("asn")),
            ("Name", info.get("name")),
            ("Description", info.get("description")),
            ("Country", info.get("country")),
            ("Website", info.get("website")),
            ("RIR allocation", info.get("rir_allocation")),
        ])

    prefixes = d.get("prefixes", [])
    if prefixes:
        section("Announced Prefixes (" + str(len(prefixes)) + ")")
        for p in prefixes[:80]:
            c_muted("  " + str(p.get("prefix","?")).ljust(22) +
                    str(p.get("name","") or p.get("description",""))[:50])
        if len(prefixes) > 80:
            c_muted("  ... +" + str(len(prefixes) - 80))

    peers = d.get("peers", {})
    if peers.get("upstreams"):
        section("Upstream ASNs (" + str(len(peers["upstreams"])) + ")")
        for p in peers["upstreams"][:15]:
            c_muted("  " + p["asn"].ljust(12) + str(p.get("name",""))[:50])
    if peers.get("downstreams"):
        section("Downstream ASNs (" + str(len(peers["downstreams"])) + ")")
        for p in peers["downstreams"][:15]:
            c_muted("  " + p["asn"].ljust(12) + str(p.get("name",""))[:50])


def render_cname(d):
    from astrym_core import header, kv
    header("CNAME Chain", d["meta"]["target"])
    chain = d.get("chain", {})
    steps = chain.get("chain", [])
    section("Chain (" + str(chain.get("hops", 0)) + " hops)")
    for i, step in enumerate(steps, 1):
        c_muted("  " + str(i) + ". " + step["host"])
        if step.get("cname"):
            c_muted("      CNAME -> " + step["cname"])
        if step.get("ips"):
            c_muted("      IPs: " + ", ".join(step["ips"][:3]))
    section("Final")
    kv([
        ("Final host", chain.get("final_host")),
        ("Final IPs", ", ".join(chain.get("final_ips", []))),
    ])


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage:")
        print("  astrym_asn.py asn <AS15169>")
        print("  astrym_asn.py cname <domain>")
        sys.exit(0)
    cmd, target = sys.argv[1], sys.argv[2]
    if cmd == "asn":
        d = run_asn(target)
        if d: render_asn(d)
    elif cmd == "cname":
        d = run_cname(target)
        if d: render_cname(d)


# === BEGIN RIPE Stat replacement (patch) ===
import requests as _requests

_RIPESTAT_BASE = "https://stat.ripe.net/data"


def _asn_normalize(asn):
    """'AS15169' | '15169' | 15169 -> 15169 ; иначе None."""
    if asn is None:
        return None
    if isinstance(asn, int):
        return asn
    s = str(asn).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    return int(s) if s.isdigit() else None


def _ripe_get(path, params, timeout=20):
    url = f"{_RIPESTAT_BASE}/{path}"
    r = _requests.get(
        url,
        params=params,
        timeout=timeout,
        headers={"User-Agent": "astrym-asn/1.0 (+ripe-stat)"},
    )
    r.raise_for_status()
    js = r.json()
    if js.get("status") != "ok":
        raise RuntimeError(
            f"RIPE Stat error: {js.get('message', js.get('status'))}"
        )
    return js.get("data", {})


def asn_info_bgpview(asn, timeout=15):
    """
    Совместимая замена BGPView -> RIPE Stat as-overview.
    Возвращает словарь формы BGPView: {"status": "ok", "data": {...}}
    или None при ошибке.
    """
    asn_num = _asn_normalize(asn)
    if asn_num is None:
        return None
    try:
        data = _ripe_get(
            "as-overview/data.json",
            {"resource": f"AS{asn_num}"},
            timeout=timeout,
        )
    except Exception as e:
        print(f"[astrym_asn] RIPE Stat as-overview fail for AS{asn_num}: {e}")
        return None

    return {
        "status": "ok",
        "data": {
            "asn": asn_num,
            "name": data.get("holder", "") or "",
            "description_short": data.get("holder", "") or "",
            "country_code": data.get("country", "") or "",
            "announced": data.get("announced", False),
            "source": "ripe-stat",
        },
    }


def asn_prefixes_bgpview(asn, timeout=20):
    """
    Совместимая замена BGPView -> RIPE Stat announced-prefixes.
    Возвращает список строк вида ["8.8.8.0/24", "2001:4860::/32", ...].
    """
    asn_num = _asn_normalize(asn)
    if asn_num is None:
        return []
    try:
        data = _ripe_get(
            "announced-prefixes/data.json",
            {"resource": f"AS{asn_num}"},
            timeout=timeout,
        )
    except Exception as e:
        print(f"[astrym_asn] RIPE Stat announced-prefixes fail for AS{asn_num}: {e}")
        return []

    out = []
    for item in data.get("prefixes", []) or []:
        p = item.get("prefix")
        if p:
            out.append(p)
    return out


# Алиасы на случай, если проект вызывает функции под другими именами
asn_info = asn_info_bgpview
asn_prefixes = asn_prefixes_bgpview
# === END RIPE Stat replacement ===


# ============================================================
# ASTRYM RIPE cache (appended override)
# Переопределяет _ripe_get после его первого определения.
# Кэш: ~/.astrym/cache/ripe/<sha1>.json
# TTL: 3600 сек. Env override: ASTRYM_RIPE_TTL=0 отключает кэш.
# ============================================================

import os as _rc_os
import json as _rc_json
import time as _rc_time
import hashlib as _rc_hash
from pathlib import Path as _RCPath

try:
    from astrym_core import CACHE_DIR as _RC_CACHE_DIR
except Exception:
    _RC_CACHE_DIR = _RCPath.home() / ".astrym" / "cache"

_RC_RIPE_DIR = _RC_CACHE_DIR / "ripe"
try:
    _RC_RIPE_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

_RC_TTL_DEFAULT = 3600


def _rc_ttl():
    try:
        v = int(_rc_os.environ.get("ASTRYM_RIPE_TTL", str(_RC_TTL_DEFAULT)))
    except Exception:
        v = _RC_TTL_DEFAULT
    return max(0, v)


def _rc_key(path, params):
    raw = path + "|" + "&".join(
        f"{k}={params[k]}" for k in sorted(params)
    )
    return _rc_hash.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _rc_load(path, params):
    if _rc_ttl() <= 0:
        return None
    fp = _RC_RIPE_DIR / (_rc_key(path, params) + ".json")
    if not fp.exists():
        return None
    try:
        d = _rc_json.loads(fp.read_text(encoding="utf-8"))
    except Exception:
        return None
    ts = d.get("ts", 0)
    if _rc_time.time() - ts > _rc_ttl():
        return None
    return d.get("data")


def _rc_save(path, params, data):
    if _rc_ttl() <= 0:
        return
    fp = _RC_RIPE_DIR / (_rc_key(path, params) + ".json")
    try:
        fp.write_text(
            _rc_json.dumps({
                "ts": _rc_time.time(),
                "path": path,
                "params": params,
                "data": data,
            }, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass


def _ripe_get(path, params, timeout=20):  # noqa: F811
    """RIPE Stat get с дисковым кэшем."""
    cached = _rc_load(path, params)
    if cached is not None:
        return cached

    url = f"{_RIPESTAT_BASE}/{path}"
    r = _requests.get(
        url,
        params=params,
        timeout=timeout,
        headers={"User-Agent": "astrym-asn/1.0 (+ripe-stat)"},
    )
    r.raise_for_status()
    js = r.json()
    if js.get("status") != "ok":
        raise RuntimeError(
            f"RIPE Stat error: {js.get('message', js.get('status'))}"
        )
    data = js.get("data", {})
    _rc_save(path, params, data)
    return data


def cache_stats():
    """Инфо о кэше — для selfcheck."""
    try:
        files = list(_RC_RIPE_DIR.glob("*.json"))
    except Exception:
        files = []
    total = sum(f.stat().st_size for f in files if f.exists())
    return {
        "dir": str(_RC_RIPE_DIR),
        "files": len(files),
        "size_kb": round(total / 1024, 1),
        "ttl": _rc_ttl(),
    }


def cache_clear():
    """Очистка кэша."""
    n = 0
    try:
        for f in _RC_RIPE_DIR.glob("*.json"):
            f.unlink()
            n += 1
    except Exception:
        pass
    return n
# end ASTRYM RIPE cache


# ============================================================
# ASTRYM asn-render fix (appended override)
# Совместим с обоими форматами prefixes:
#   - list[str]  (RIPE Stat)   -> ["8.8.8.0/24", ...]
#   - list[dict] (BGPView old) -> [{"prefix":..., "name":...}, ...]
# Также учитывает поля RIPE Stat (description_short, country_code).
# ============================================================


def render_asn(d):
    from astrym_core import header, kv, section, c_muted, c_ok

    meta = d.get("meta") or {}
    header("ASN Discovery", meta.get("target", "?"))

    # --- Info ---
    info = d.get("info") or {}
    if isinstance(info, dict):
        data = info.get("data") if "data" in info else info
    else:
        data = {}
    if not isinstance(data, dict):
        data = {}

    if data:
        section("ASN Info")
        kv([
            ("ASN", data.get("asn")),
            ("Name", data.get("name") or data.get("holder")),
            ("Description",
             data.get("description") or data.get("description_short")),
            ("Country",
             data.get("country") or data.get("country_code")),
            ("Announced", data.get("announced")),
            ("Source", data.get("source")),
        ])

    # --- Prefixes ---
    prefixes = d.get("prefixes") or []
    if prefixes:
        section("Announced Prefixes (" + str(len(prefixes)) + ")")
        shown = 0
        for p in prefixes[:80]:
            if isinstance(p, dict):
                pfx = p.get("prefix") or p.get("value") or "?"
                name = (p.get("name") or p.get("description") or "")
                line = "  " + str(pfx)[:40].ljust(40) + " " + str(name)[:50]
            else:
                line = "  " + str(p)[:90]
            c_muted(line)
            shown += 1
        if len(prefixes) > shown:
            c_muted("  ... +" + str(len(prefixes) - shown))

    # --- Peers ---
    peers = d.get("peers") or {}
    if isinstance(peers, dict):
        ups = peers.get("upstreams") or []
        dns = peers.get("downstreams") or []
        if ups:
            section("Upstream ASNs (" + str(len(ups)) + ")")
            for p in ups[:15]:
                if isinstance(p, dict):
                    c_muted("  " + str(p.get("asn", "?")).ljust(12) +
                            str(p.get("name") or p.get("description") or "")[:50])
                else:
                    c_muted("  " + str(p)[:70])
            if len(ups) > 15:
                c_muted("  ... +" + str(len(ups) - 15))
        if dns:
            section("Downstream ASNs (" + str(len(dns)) + ")")
            for p in dns[:15]:
                if isinstance(p, dict):
                    c_muted("  " + str(p.get("asn", "?")).ljust(12) +
                            str(p.get("name") or p.get("description") or "")[:50])
                else:
                    c_muted("  " + str(p)[:70])
            if len(dns) > 15:
                c_muted("  ... +" + str(len(dns) - 15))
# end ASTRYM asn-render fix
