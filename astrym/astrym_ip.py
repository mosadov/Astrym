#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM IP 8.1.0 — IP + WHOIS + GeoIP + DNSBL + extended sources

import time, json, socket, ipaddress
from astrym_core import (
    now_iso, is_ip, ip_geo, reverse_dns, check_dnsbl,
    whois_ip, parse_whois, resolve, HAS_REQUESTS, HAS_DNS,
    load_cfg, hist_record, c_ok, c_warn, c_err, c_info, c_muted,
    _rl_sleep,
)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION = "8.1.0"

# ============================================================
# MAIN COLLECTOR
# ============================================================

def collect_ip(ip):
    obj = ipaddress.ip_address(ip)
    ptr = reverse_dns(ip)
    geo = ip_geo(ip)
    bl = check_dnsbl(ip)
    raw = whois_ip(ip)
    kvw = parse_whois(raw) if raw and not raw.startswith("__error__") else {}
    imp = ["netrange", "cidr", "netname", "orgname", "organization",
           "country", "inetnum", "descr", "org-name", "address",
           "abuse-mailbox", "regdate", "updated", "created"]
    clean = {k: v for k, v in kvw.items() if any(k.startswith(p) for p in imp)}
    return {
        "meta": {"type": "ip", "target": ip,
                 "generated_at": now_iso(), "tool": "ASTRYM " + VERSION},
        "overview": {"address": ip, "version": "IPv" + str(obj.version),
                     "ptr": ptr, "private": obj.is_private},
        "geo": geo, "dnsbl": bl, "whois": clean,
    }

# ============================================================
# EXTENDED SOURCES (-x)
# ============================================================

def _x_ip(ip):
    out = {}
    if not HAS_REQUESTS:
        return out
    # ipwho.is
    try:
        r = requests.get("https://ipwho.is/" + ip, timeout=8)
        if r.status_code == 200:
            d = r.json()
            if d.get("success"):
                out["ipwho"] = {
                    "country": d.get("country"), "city": d.get("city"),
                    "region": d.get("region"),
                    "isp": d.get("connection", {}).get("isp"),
                    "org": d.get("connection", {}).get("org"),
                    "asn": d.get("connection", {}).get("asn"),
                }
    except Exception: pass
    # ipapi.co
    try:
        r = requests.get("https://ipapi.co/" + ip + "/json/", timeout=8)
        if r.status_code == 200:
            d = r.json()
            if not d.get("error"):
                out["ipapi"] = {"country": d.get("country_name"),
                                "city": d.get("city"),
                                "org": d.get("org"), "asn": d.get("asn")}
    except Exception: pass
    # ipinfo.io
    try:
        r = requests.get("https://ipinfo.io/" + ip + "/json", timeout=8)
        if r.status_code == 200:
            d = r.json()
            if not d.get("error"):
                out["ipinfo"] = {"hostname": d.get("hostname"),
                                 "city": d.get("city"),
                                 "org": d.get("org"),
                                 "timezone": d.get("timezone")}
    except Exception: pass
    # RIPE Stat (заменяет BGPView, который мёртв с 26.11.2025)
    try:
        r = requests.get(
            "https://stat.ripe.net/data/network-info/data.json",
            params={"resource": ip}, timeout=8)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "ok":
                nd = d.get("data", {})
                prefix = nd.get("prefix")
                asns = nd.get("asns") or []
                asn0 = asns[0] if asns else None
                entry = {
                    "asn": asn0,
                    "prefix": prefix,
                    "source": "ripe-stat",
                }
                # подтянем имя ASN отдельным запросом
                if asn0:
                    try:
                        r2 = requests.get(
                            "https://stat.ripe.net/data/as-overview/data.json",
                            params={"resource": "AS" + str(asn0)},
                            timeout=8)
                        if r2.status_code == 200:
                            d2 = r2.json()
                            if d2.get("status") == "ok":
                                holder = d2.get("data", {}).get("holder", "")
                                entry["asn_name"] = holder
                                entry["asn_description"] = holder
                    except Exception:
                        pass
                out["bgpview"] = entry  # имя ключа сохранено для совместимости
    except Exception:
        pass
    # Team Cymru ASN via DNS
    if HAS_DNS:
        try:
            from astrym_core import dns
            rev = ".".join(reversed(ip.split(".")))
            ans = dns.resolver.resolve(rev + ".origin.asn.cymru.com",
                                       "TXT", lifetime=3)
            if ans:
                parts = str(ans[0]).strip('"').split("|")
                if len(parts) >= 3:
                    out["team_cymru"] = {
                        "asn": parts[0].strip(),
                        "prefix": parts[1].strip(),
                        "country": parts[2].strip(),
                    }
        except Exception: pass
    # Shodan InternetDB
    idb = shodan_internetdb(ip)
    if idb and idb.get("found"):
        out["shodan_internetdb"] = idb
    return out

def shodan_internetdb(ip):
    if not HAS_REQUESTS: return None
    try:
        r = requests.get("https://internetdb.shodan.io/" + ip, timeout=8)
        if r.status_code == 200:
            d = r.json()
            if d.get("detail") == "No information available":
                return {"found": False}
            return {"found": True, "ports": d.get("ports", []),
                    "hostnames": d.get("hostnames", []),
                    "vulns": d.get("vulns", []),
                    "cpes": d.get("cpes", []),
                    "tags": d.get("tags", [])}
    except Exception: pass
    return None

# ============================================================
# EXTERNAL LINKS
# ============================================================

def extras_links_ip(ip):
    return [
        ("IPVoid", "https://www.ipvoid.com/ip-blacklist-check/"),
        ("Scamalytics", "https://scamalytics.com/ip/" + ip),
        ("IPQualityScore", "https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/" + ip),
        ("Project Honey Pot", "https://www.projecthoneypot.org/ip_" + ip),
        ("BrightCloud", "https://www.brightcloud.com/tools/url-ip-lookup.php"),
        ("Talos", "https://talosintelligence.com/reputation_center/lookup?search=" + ip),
        ("SenderBase", "https://www.senderbase.org/lookup/?search_string=" + ip),
        ("FortiGuard", "https://www.fortiguard.com/webfilter?q=" + ip),
        ("AlienVault OTX", "https://otx.alienvault.com/indicator/ip/" + ip),
        ("ThreatCrowd", "https://www.threatcrowd.org/ip.php?ip=" + ip),
        ("Censys", "https://search.censys.io/hosts/" + ip),
        ("GreyNoise Viz", "https://viz.greynoise.io/ip/" + ip),
        ("Shodan", "https://www.shodan.io/host/" + ip),
        ("InternetDB", "https://internetdb.shodan.io/" + ip),
        ("BGP Toolkit", "https://bgp.he.net/ip/" + ip),
        ("RIPE Stat", "https://stat.ripe.net/" + ip),
        ("AbuseIPDB", "https://www.abuseipdb.com/check/" + ip),
        ("URLhaus", "https://urlhaus.abuse.ch/browse.php?search=" + ip),
        ("Hybrid Analysis", "https://www.hybrid-analysis.com/search?query=" + ip),
        ("Kaspersky OpenTIP", "https://opentip.kaspersky.com/" + ip),
    ]

# ============================================================
# ENTRY POINT (для main dispatcher)
# ============================================================

def run_ip(target, extras=False):
    if not is_ip(target):
        c_err("not a valid IP: " + target)
        return None
    d = collect_ip(target)
    if extras:
        d["extended"] = _x_ip(target)
        d["extended_links"] = extras_links_ip(target)
    # # ASTRYM consensus patch
    try:
        from astrym_consensus import aggregate as _agg
        d["consensus"] = _agg(d)
    except Exception as _e:
        pass
    hist_record("ip", target, {"country": d["geo"].get("country"),
                                "isp": d["geo"].get("isp")})
    return d