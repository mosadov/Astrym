#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Check 8.1.0 — threat intelligence + extended sources

import time, json, base64
from astrym_core import (
    now_iso, classify, is_ip, is_domain, is_email,
    HAS_REQUESTS, load_cfg, hist_record,
    c_ok, c_warn, c_err, c_info, c_muted, _rl_sleep,
)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

VERSION = "8.1.0"

# ============================================================
# BASE THREAT INTEL
# ============================================================

def _http_with_retry(method, url, timeout=30, retries=2,
                     headers=None, params=None, data=None, json_payload=None):
    """HTTP запрос с retry при timeout."""
    if not HAS_REQUESTS:
        return None
    import requests
    last = None
    for attempt in range(retries + 1):
        try:
            if method == "GET":
                return requests.get(url, headers=headers, params=params,
                                     timeout=timeout)
            elif method == "POST":
                if json_payload is not None:
                    return requests.post(url, headers=headers, params=params,
                                         json=json_payload, timeout=timeout)
                else:
                    return requests.post(url, headers=headers, params=params,
                                         data=data, timeout=timeout)
        except requests.exceptions.Timeout as e:
            last = e
            time.sleep(1 + attempt * 2)
        except requests.exceptions.ConnectionError as e:
            last = e
            time.sleep(1 + attempt * 2)
        except Exception as e:
            last = e
            break
    return None


def vt_lookup(cfg, kind, target):
    if not HAS_REQUESTS:
        return {"error": "no requests"}
    key = cfg.get("virustotal")
    if not key:
        return {"error": "no API key"}
    _rl_sleep()
    try:
        if kind == "url":
            uid = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            ep = "https://www.virustotal.com/api/v3/urls/" + uid
        elif kind == "ip":
            ep = "https://www.virustotal.com/api/v3/ip_addresses/" + target
        elif kind == "domain":
            ep = "https://www.virustotal.com/api/v3/domains/" + target
        else:
            return {"error": "unknown kind"}
        r = requests.get(ep, headers={"x-apikey": key},
                              timeout=20)
        if r.status_code == 404:
            return {"found": False}
        if r.status_code == 401:
            return {"error": "invalid key"}
        if r.status_code == 429:
            return {"error": "rate limit"}
        a = r.json().get("data", {}).get("attributes", {})
        s = a.get("last_analysis_stats", {})
        return {
            "found": True,
            "malicious": s.get("malicious", 0),
            "suspicious": s.get("suspicious", 0),
            "harmless": s.get("harmless", 0),
            "total_engines": sum(s.values()) if s else 0,
            "reputation": a.get("reputation"),
        }
    except Exception as e:
        return {"error": str(e)}

def greynoise_lookup(ip):
    if not HAS_REQUESTS:
        return {"error": "no requests"}
    _rl_sleep()
    try:
        r = requests.get(
            "https://api.greynoise.io/v3/community/" + ip, timeout=15)
        if r.status_code == 404:
            return {"found": False}
        if r.status_code == 429:
            return {"error": "rate limit"}
        d = r.json()
        return {"found": True, "classification": d.get("classification"),
                "name": d.get("name"), "last_seen": d.get("last_seen")}
    except Exception as e:
        return {"error": str(e)}

def urlhaus_lookup(kind, target):
    if not HAS_REQUESTS:
        return {"error": "no requests"}
    _rl_sleep()
    try:
        url = ("https://urlhaus-api.abuse.ch/v1/host/" if kind == "host"
               else "https://urlhaus-api.abuse.ch/v1/url/")
        data = {"host": target} if kind == "host" else {"url": target}
        r = requests.post(url, data=data, timeout=15)
        d = r.json()
        if d.get("query_status") == "no_results":
            return {"found": False, "status": "clean"}
        return {"found": True, "status": d.get("query_status"),
                "threat": d.get("threat"),
                "tags": d.get("tags", []),
                "url_count": len(d.get("urls", []))}
    except Exception as e:
        return {"error": str(e)}

def threatfox_lookup(target):
    if not HAS_REQUESTS:
        return {"error": "no requests"}
    _rl_sleep()
    try:
        r = requests.post("https://threatfox-api.abuse.ch/api/v1",
                          json={"query": "search_ioc", "search_term": target},
                          timeout=15)
        d = r.json()
        if d.get("query_status") == "no_result":
            return {"found": False, "status": "clean"}
        return {"found": True, "ioc_count": len(d.get("data") or [])}
    except Exception as e:
        return {"error": str(e)}

def shodan_internetdb(ip):
    if not HAS_REQUESTS:
        return None
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
    except Exception:
        pass
    return None

# ============================================================
# EXTENDED THREAT INTEL
# ============================================================

def _x_check(target):
    out = {}
    if not HAS_REQUESTS:
        return out
    kind = classify(target)

    # AlienVault OTX
    if kind == "ip":
        otx_url = "https://otx.alienvault.com/api/v1/indicators/IPv4/" + target + "/general"
    elif kind == "domain":
        otx_url = "https://otx.alienvault.com/api/v1/indicators/domain/" + target + "/general"
    else:
        otx_url = None
    if otx_url:
        try:
            r = requests.get(otx_url, timeout=10)
            if r.status_code == 200:
                d = r.json()
                out["otx"] = {
                    "pulse_count": d.get("pulse_info", {}).get("count", 0),
                    "reputation": d.get("reputation", 0),
                    "tags": (d.get("tags") or [])[:10],
                }
        except Exception:
            pass

    # MalwareBazaar (domain)
    if kind == "domain":
        try:
            r = requests.post("https://mb-api.abuse.ch/api/v1/",
                              json={"query": "get_taginfo",
                                    "tag": target, "limit": 10},
                              timeout=15)
            if r.status_code == 200:
                d = r.json()
                if d.get("query_status") == "ok":
                    out["malwarebazaar"] = {"count": len(d.get("data") or [])}
        except Exception:
            pass

    # Feodo Tracker (IP)
    if kind == "ip":
        try:
            r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                             timeout=15)
            if r.status_code == 200:
                d = r.json()
                if isinstance(d, list):
                    for e in d:
                        if e.get("ip_address") == target:
                            out["feodo"] = {"malware": e.get("malware"),
                                             "status": e.get("status"),
                                             "first_seen": e.get("first_seen")}
                            break
        except Exception:
            pass

    # IPsum
    if kind == "ip":
        try:
            r = requests.get(
                "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
                timeout=15)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    if line.startswith("#"):
                        continue
                    parts = line.split()
                    if parts and parts[0] == target:
                        out["ipsum"] = {"sources_count": int(parts[1])
                                        if len(parts) > 1 else 0}
                        break
        except Exception:
            pass

    # Blocklist.de
    if kind == "ip":
        try:
            r = requests.get("https://lists.blocklist.de/lists/all.txt",
                             timeout=15)
            if r.status_code == 200:
                if target in r.text.split("\n"):
                    out["blocklist_de"] = {"listed": True}
        except Exception:
            pass

    # Spamhaus DROP
    if kind == "ip":
        try:
            r = requests.get("https://www.spamhaus.org/drop/drop.txt",
                             timeout=15)
            if r.status_code == 200:
                import ipaddress
                try:
                    net = ipaddress.ip_network(target + "/32", strict=False)
                    for line in r.text.splitlines():
                        line = line.split(";")[0].strip()
                        if "/" in line:
                            try:
                                if net.subnet_of(ipaddress.ip_network(line,
                                                                      strict=False)):
                                    out["spamhaus_drop"] = {"listed": True,
                                                             "range": line}
                                    break
                            except Exception:
                                continue
                except Exception:
                    pass
        except Exception:
            pass

    return out

# ============================================================
# RISK SCORING
# ============================================================

def compute_risk(results):
    """Risk score 0-100.

    Правила:
      - баллы начисляются только за РЕАЛЬНЫЕ угрозы (count > 0)
      - ошибки API / таймауты / пустые ответы = 0 баллов
    """
    score = 0
    reasons = []
    src = results.get("results", {})

    # --- VirusTotal ---
    vt = src.get("virustotal", {})
    if vt.get("found") is True and not vt.get("error"):
        m = int(vt.get("malicious", 0) or 0)
        s = int(vt.get("suspicious", 0) or 0)
        if m > 0:
            p = min(60, 10 + m * 3)
            score += p
            reasons.append("VirusTotal: " + str(m) + " malicious (+" + str(p) + ")")
        if s > 0:
            p2 = min(15, s * 2)
            score += p2
            reasons.append("VirusTotal: " + str(s) + " suspicious (+" + str(p2) + ")")

    # --- GreyNoise ---
    gn = src.get("greynoise", {})
    if (gn.get("found") is True
            and not gn.get("error")
            and gn.get("classification") == "malicious"):
        score += 20
        reasons.append("GreyNoise: malicious (+20)")

    # --- URLhaus ---
    uh = src.get("urlhaus", {})
    if uh.get("found") is True and not uh.get("error"):
        uc = int(uh.get("url_count", 0) or 0)
        if uc > 0:
            score += 25
            reasons.append("URLhaus: " + str(uh.get("threat") or "listed") +
                           " (" + str(uc) + " urls, +25)")
        else:
            reasons.append("URLhaus: found entry with 0 urls (no penalty)")

    # --- ThreatFox ---
    tf = src.get("threatfox", {})
    if tf.get("found") is True and not tf.get("error"):
        ic = int(tf.get("ioc_count", 0) or 0)
        if ic > 0:
            score += 20
            reasons.append("ThreatFox: " + str(ic) + " IOC (+20)")
        else:
            reasons.append("ThreatFox: 0 IOC (no penalty)")

    # --- Shodan InternetDB ---
    idb = src.get("shodan_internetdb", {})
    if idb and idb.get("vulns"):
        vc = len(idb["vulns"])
        if vc > 0:
            p = min(15, vc * 3)
            score += p
            reasons.append("InternetDB: " + str(vc) + " CVE (+" + str(p) + ")")

    # --- OTX ---
    otx = src.get("otx", {})
    if otx and not otx.get("error"):
        pc = int(otx.get("pulse_count", 0) or 0)
        if pc > 0:
            p = min(20, pc * 2)
            score += p
            reasons.append("OTX: " + str(pc) + " pulses (+" + str(p) + ")")

    # --- Feodo ---
    feodo = src.get("feodo", {})
    if feodo and not feodo.get("error"):
        if feodo.get("malware") or feodo.get("status"):
            score += 25
            reasons.append("Feodo: " + str(feodo.get("malware") or "listed") + " (+25)")

    # --- IPsum ---
    ipsum = src.get("ipsum", {})
    if ipsum and not ipsum.get("error"):
        sc = int(ipsum.get("sources_count", 0) or 0)
        if sc > 0:
            p = min(15, sc)
            score += p
            reasons.append("IPsum: " + str(sc) + " sources (+" + str(p) + ")")

    # --- Blocklist.de ---
    bd = src.get("blocklist_de", {})
    if bd and bd.get("listed") is True:
        score += 15
        reasons.append("Blocklist.de: listed (+15)")

    # --- Spamhaus DROP ---
    sd = src.get("spamhaus_drop", {})
    if sd and sd.get("listed") is True:
        score += 20
        reasons.append("Spamhaus DROP: listed (+20)")

    # --- кламп ---
    score = min(100, score)

    # --- ошибки API: показать, но НЕ штрафовать ---
    api_errors = []
    for name in ("virustotal", "greynoise", "urlhaus", "threatfox"):
        r = src.get(name, {})
        if r and r.get("error"):
            err_text = str(r["error"])
            if len(err_text) > 250:
                err_text = err_text[:247] + "..."
            api_errors.append(name + ": " + err_text)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "CLEAN"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "api_errors": api_errors,
    }



def sec_check_ip(cfg, ip):
    r = {}
    r["virustotal"] = vt_lookup(cfg, "ip", ip)
    r["greynoise"] = greynoise_lookup(ip)
    r["threatfox"] = threatfox_lookup(ip)
    idb = shodan_internetdb(ip)
    if idb and idb.get("found"):
        r["shodan_internetdb"] = idb
    return {"target": ip, "kind": "ip", "results": r}

def sec_check_domain(cfg, domain):
    r = {}
    r["virustotal"] = vt_lookup(cfg, "domain", domain)
    r["urlhaus"] = urlhaus_lookup("host", domain)
    r["threatfox"] = threatfox_lookup(domain)
    return {"target": domain, "kind": "domain", "results": r}

def sec_check_url(cfg, url):
    r = {}
    r["virustotal"] = vt_lookup(cfg, "url", url)
    r["urlhaus"] = urlhaus_lookup("url", url)
    return {"target": url, "kind": "url", "results": r}

# ============================================================
# COLLECTOR
# ============================================================

def collect_check(target, extras=False):
    cfg = load_cfg()
    k = classify(target)
    if k == "ip":
        data = sec_check_ip(cfg, target)
    elif k == "domain":
        data = sec_check_domain(cfg, target)
    elif k == "url":
        data = sec_check_url(cfg, target)
    elif k == "email":
        domain = target.split("@", 1)[1] if "@" in target else target
        data = sec_check_domain(cfg, domain)
        data["target"] = target
        data["note"] = "checked domain of email"
    else:
        data = {"target": target, "kind": k, "results": {}}
    data["meta"] = {
        "type": "check", "target": target,
        "generated_at": now_iso(),
        "tool": "ASTRYM " + VERSION,
        "keys_present": [x for x in ("virustotal", "greynoise", "shodan",
                                      "abuseipdb", "safebrowsing")
                         if cfg.get(x)],
    }
    if extras:
        data["extended"] = _x_check(target)
        data["extended_links"] = extras_links_check(target)
    data["risk"] = compute_risk(data)
    return data

# ============================================================
# EXTERNAL LINKS
# ============================================================

def extras_links_check(target):
    kind = classify(target)
    if kind == "ip":
        url = "https://otx.alienvault.com/indicator/IPv4/" + target
    elif kind == "domain":
        url = "https://otx.alienvault.com/indicator/domain/" + target
    else:
        url = "https://otx.alienvault.com/"
    return [
        ("AlienVault OTX", url),
        ("ThreatCrowd", "https://www.threatcrowd.org/"),
        ("CIRCL", "https://www.circl.lu/services/passive-dns/"),
        ("RiskIQ", "https://community.riskiq.com/search/" + target),
        ("Joe Sandbox", "https://www.joesandbox.com/search?q=" + target),
        ("ANY.RUN", "https://app.any.run/submissions"),
        ("Triage", "https://tria.ge/s?q=" + target),
        ("Hybrid Analysis", "https://www.hybrid-analysis.com/search?query=" + target),
        ("Kaspersky OpenTIP", "https://opentip.kaspersky.com/" + target),
        ("URLhaus", "https://urlhaus.abuse.ch/browse.php?search=" + target),
        ("VirusTotal", ("https://www.virustotal.com/gui/ip-address/" + target
                        if kind == "ip"
                        else "https://www.virustotal.com/gui/domain/" + target)),
        ("Shodan", ("https://www.shodan.io/host/" + target
                    if kind == "ip"
                    else "https://www.shodan.io/domain/" + target)),
        ("Censys", "https://search.censys.io/search?resource=hosts&q=" + target),
    ]

# ============================================================
# ENTRY POINT
# ============================================================

def run_check(target, extras=False):
    d = collect_check(target, extras=extras)
    rk = d.get("risk", {})
    hist_record("check", target, {"level": rk.get("level"),
                                    "score": rk.get("score")})
    return d