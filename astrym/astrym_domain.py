#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Domain 8.1.0 — domain + dns + sub + extended sources

import re, time, json
from concurrent.futures import ThreadPoolExecutor, as_completed

from astrym_core import (
    _init_resolver,
    now_iso, is_domain, resolve, resolve_all,
    resolve_detailed, resolve_all_detailed, resolve_mx,
    whois_domain, parse_whois, RECORD_TYPES,
    HAS_DNS, HAS_REQUESTS, c_ok, c_warn, c_err, c_info, c_muted,
    hist_record, _rl_sleep,
)

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from astrym_free import collect_free_for_domain
except ImportError:
    collect_free_for_domain = None


try:
    from astrym_web import (permute_subs as _permute_subs,
                              resolve_permutations as _resolve_permutations,
                              probe_many as _probe_many)
except ImportError:
    _permute_subs = _resolve_permutations = _probe_many = None


import warnings
warnings.filterwarnings('ignore')
VERSION = "8.1.0"

# ============================================================
# DEFAULT WORDS
# ============================================================

# ============================================================
# CT LOGS
# ============================================================

def crt_subdomains(domain, timeout=20):
    if not HAS_REQUESTS:
        return []
    subs = set()
    try:
        r = requests.get("https://crt.sh/",
                         params={"q": "%25." + domain, "output": "json"},
                         timeout=timeout,
                         headers={"User-Agent": "ASTRYM/" + VERSION})
        if r.status_code == 200 and r.text.lstrip().startswith("["):
            for e in r.json():
                for n in e.get("name_value", "").split("\n"):
                    n = n.strip().lower()
                    if n.endswith(domain) and "*" not in n:
                        subs.add(n)
    except Exception:
        pass
    return sorted(subs)

# ============================================================
# BRUTE
# ============================================================

# ============================================================
# ASTRYM 9.1.3 — расширенный wordlist (~1000+ слов)
# ============================================================

_BASE = [
    "www", "mail", "smtp", "imap", "pop", "pop3", "webmail", "mx",
    "mx1", "mx2", "mail1", "mail2", "email", "newsletter",
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "api", "api1", "api2", "api-v1", "api-v2", "api-dev", "api-stg",
    "app", "apps", "web", "web1", "web2", "www1", "www2",
    "mobile", "m", "wap", "touch", "tablet",
    "portal", "auth", "sso", "login", "signin", "account", "my",
    "admin", "administrator", "manage", "manager", "console",
    "panel", "cpanel", "whm", "plesk", "directadmin",
    "dev", "develop", "developer", "developers",
    "test", "testing", "qa", "sandbox", "demo", "sample",
    "staging", "stage", "stg", "preprod", "preview",
    "prod", "production", "live",
    "beta", "alpha", "rc", "nightly", "canary",
    "old", "old1", "old2", "legacy", "archive", "backup", "bak",
    "new", "new1", "new2", "v1", "v2", "v3", "v4",
    "cdn", "cdn1", "cdn2", "static", "assets", "media",
    "img", "images", "image", "photo", "photos", "pic", "pics",
    "files", "file", "download", "downloads", "upload", "uploads",
    "blog", "blogs", "news", "press", "media-room", "pr",
    "forum", "forums", "community", "talk", "discuss",
    "support", "help", "helpdesk", "faq", "kb", "knowledgebase",
    "docs", "documentation", "wiki", "manual", "guide",
    "status", "health", "monitor", "monitoring", "metrics",
    "shop", "store", "cart", "checkout", "payment", "pay",
    "billing", "invoice", "invoices", "orders", "order",
    "customer", "customers", "client", "clients", "partner",
    "sales", "marketing", "promo", "ads", "adserver",
    "git", "gitlab", "github", "bitbucket", "gitea", "gogs",
    "svn", "mercurial", "hg", "repo", "repos", "repository",
    "jenkins", "ci", "cd", "build", "builder", "builds",
    "deploy", "deployment", "release", "releases",
    "docker", "registry", "harbor", "nexus", "artifactory",
    "k8s", "kubernetes", "kube", "rancher", "openshift",
    "aws", "azure", "gcp", "cloud", "cloud1", "cloud2",
    "s3", "storage", "blob", "bucket",
    "db", "database", "mysql", "postgres", "postgresql", "oracle",
    "mssql", "mongo", "mongodb", "redis", "elastic", "elasticsearch",
    "cassandra", "couchdb", "influx", "influxdb", "neo4j",
    "kafka", "rabbitmq", "rabbit", "activemq", "zeromq",
    "queue", "worker", "workers", "job", "jobs", "scheduler",
    "cron", "task", "tasks", "batch",
    "log", "logs", "logging", "syslog", "journal",
    "trace", "tracing", "jaeger", "zipkin",
    "grafana", "prometheus", "kibana", "splunk", "datadog",
    "nagios", "zabbix", "sensu", "icinga",
    "vpn", "remote", "rdp", "citrix", "vdi", "jump", "bastion",
    "ssh", "sftp", "ftp", "ftps", "tftp",
    "proxy", "reverse-proxy", "nginx", "haproxy", "traefik",
    "gateway", "gw", "router", "router1", "switch", "fw", "firewall",
    "intranet", "internal", "corp", "corporate", "office",
    "home", "personal", "me", "self",
    "ftp", "file", "share", "shared", "public", "private",
    "temp", "tmp", "cache", "cached", "session",
    "search", "find", "lookup", "query", "index",
    "chat", "chat1", "im", "messenger", "messaging",
    "video", "videos", "stream", "streaming", "live", "tv",
    "audio", "music", "radio", "podcast", "podcasts",
    "game", "games", "play", "playground",
    "calendar", "cal", "schedule", "meeting", "events",
    "contacts", "addressbook", "book", "phone", "pbx", "voip",
    "sms", "notifications", "notify", "alerts", "alert",
    "webhook", "webhooks", "hook", "hooks", "callback",
    "oauth", "oauth2", "oidc", "saml", "jwt", "token",
    "id", "ids", "identity", "account1", "profile", "user", "users",
    "session", "sessions", "cookie", "cookies",
    "checkout1", "payment1", "stripe", "paypal", "braintree",
    "shipping", "delivery", "track", "tracking",
    "subscribe", "subscription", "subs", "premium", "plus",
    "refer", "referral", "invite", "invites", "promo1",
    "partner1", "affiliate", "affiliates", "reseller",
    "legal", "privacy", "terms", "tos", "policy", "policies",
    "career", "careers", "jobs1", "job", "hr", "hrm", "recruit",
    "team", "teams", "about", "contact", "contacts1",
    "feedback", "complaint", "report", "abuse", "security",
    "bug", "bugs", "bugbounty", "bounty", "vuln", "cve",
    "sitemap", "robots", "sitemap.xml", "sitemap1",
    "analytics", "stats", "statistics", "report1", "reports",
    "bi", "dashboard", "dash", "chart", "charts",
    "etl", "data", "dataset", "datasets", "warehouse", "dwh",
    "ml", "ai", "model", "models", "predict", "prediction",
    "staging1", "staging2", "stage1", "stage2",
    "development", "dev1", "dev2", "devops", "sre", "platform",
    "infra", "infrastructure", "ops", "operations",
    "emergency", "critical", "urgent",
    "test1", "test2", "test3", "testing1", "tester",
    "qa1", "qa2", "uat", "sit", "pit", "uat1",
    "web1", "web2", "web3", "web4", "site", "site1",
    "shop1", "shop2", "store1", "store2",
    "service", "services", "service1", "service2",
    "customer1", "client1", "partner2",
    "news1", "news2", "events1", "media1",
    "careers1", "jobs2", "hr1", "people", "staff",
    "admin1", "admin2", "root", "superuser",
    "backup1", "backup2", "backups", "snapshot", "snapshots",
    "mirror", "mirrors", "replica", "slave",
    "gateway1", "gateway2", "proxy1", "proxy2",
    "apps1", "apps2", "app1", "app2", "app3",
]

_EXTRA_SUFFIXES = [
    "-dev", "-test", "-staging", "-prod", "-prod1",
    "-uat", "-qa", "-beta", "-alpha", "-rc",
    "-v1", "-v2", "-v3", "-old", "-new",
    "-internal", "-external", "-stg", "-preprod",
    "1", "2", "3", "-01", "-02", "-us", "-eu", "-asia",
]

DEFAULT_WORDS_EXTENDED = list(_BASE)
for _w in _BASE:
    for _suf in _EXTRA_SUFFIXES:
        DEFAULT_WORDS_EXTENDED.append(_w + _suf)

# дедупликация
_seen = set()
DEFAULT_WORDS = []
for _w in DEFAULT_WORDS_EXTENDED:
    if _w not in _seen:
        _seen.add(_w)
        DEFAULT_WORDS.append(_w)
del _seen

def brute_subs(domain, words, workers=40):
    if not HAS_DNS:
        return []
    found = []

    def ck(w):
        h = w + "." + domain
        try:
            ans = dns.resolver.resolve(h, "A", lifetime=2.5)
            return (h, [a.to_text() for a in ans])
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(ck, words):
            if r:
                found.append(r)
    return found

# ============================================================
# EXTENDED SOURCES
# ============================================================

def extra_subs(domain):
    out = {}
    if not HAS_REQUESTS:
        return out

    # Certspotter
    try:
        r = requests.get("https://api.certspotter.com/v1/issuances",
                         params={"domain": domain,
                                 "include_subdomains": "true",
                                 "expand": "dns_names"}, timeout=15)
        if r.status_code == 200:
            d = r.json()
            if isinstance(d, list):
                subs = set()
                for e in d:
                    for n in e.get("dns_names", []):
                        n = n.lower()
                        if n.endswith(domain) and "*" not in n:
                            subs.add(n)
                if subs:
                    out["certspotter"] = sorted(subs)
    except Exception:
        pass

    # HackerTarget
    try:
        r = requests.get("https://api.hackertarget.com/hostsearch/",
                         params={"q": domain}, timeout=15)
        if r.status_code == 200:
            subs = set()
            for line in r.text.splitlines():
                p = line.split(",")
                if p and p[0].endswith(domain):
                    subs.add(p[0].lower())
            if subs:
                out["hackertarget"] = sorted(subs)
    except Exception:
        pass

    # AnubisDB
    try:
        r = requests.get("https://jldc.me/anubis/subdomains/" + domain,
                         timeout=10)
        if r.status_code == 200:
            d = r.json()
            if isinstance(d, list):
                out["anubisdb"] = sorted(set(x.lower() for x in d if x))
    except Exception:
        pass

    # RapidDNS
    try:
        r = requests.get("https://rapiddns.io/subdomain/" + domain,
                         params={"full": "1"}, timeout=15)
        if r.status_code == 200:
            subs = set(re.findall(
                r"<td>([a-z0-9.\-]+" + re.escape(domain) + r")</td>",
                r.text, re.I))
            if subs:
                out["rapiddns"] = sorted(subs)
    except Exception:
        pass

    # OTX passive DNS
    try:
        r = requests.get("https://otx.alienvault.com/api/v1/indicators/"
                         "domain/" + domain + "/passive_dns", timeout=15)
        if r.status_code == 200:
            d = r.json()
            subs = set()
            for e in d.get("passive_dns", []):
                h = e.get("hostname", "").lower()
                if h and h.endswith(domain):
                    subs.add(h)
            if subs:
                out["otx_passive"] = sorted(subs)
    except Exception:
        pass

    # CIRCL Passive DNS
    try:
        r = requests.get("https://www.circl.lu/pdns/query/" + domain,
                         timeout=10)
        if r.status_code == 200:
            d = r.json()
            if isinstance(d, list):
                out["circl_passive_dns"] = {"count": len(d),
                                             "records": d[:30]}
    except Exception:
        pass

    # BufferOver
    try:
        r = requests.get("https://dns.bufferover.run/dns",
                         params={"q": "." + domain}, timeout=15)
        if r.status_code == 200:
            d = r.json()
            subs = set()
            for key in ("FDNS_A", "RDNS"):
                for item in d.get(key, []) or []:
                    if "," in item:
                        _, host = item.split(",", 1)
                        if host.endswith(domain):
                            subs.add(host.lower())
            if subs:
                out["bufferover"] = sorted(subs)
    except Exception:
        pass

    return out

# ============================================================
# DoH (Cloudflare + Google)
# ============================================================

def dns_via_doh(domain, rt, provider="cloudflare"):
    if not HAS_REQUESTS:
        return []
    urls = {"cloudflare": "https://cloudflare-dns.com/dns-query",
            "google": "https://dns.google/resolve"}
    url = urls.get(provider)
    if not url:
        return []
    type_map = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15,
                "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257}
    if rt not in type_map:
        return []
    try:
        r = requests.get(url,
                         params={"name": domain, "type": str(type_map[rt])},
                         headers={"Accept": "application/dns-json"},
                         timeout=8)
        if r.status_code == 200:
            d = r.json()
            answers = d.get("Answer", [])
            return [a.get("data", "") for a in answers if a.get("data")]
    except Exception:
        pass
    return []

def dns_zone_transfer(domain):
    if not HAS_DNS:
        return None
    try:
        ans = dns.resolver.resolve(domain, "NS", lifetime=5)
        ns_list = [str(r).rstrip(".") for r in ans]
    except Exception:
        return None
    for ns in ns_list[:3]:
        try:
            import dns.query, dns.zone
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            if z:
                return {"ns": ns,
                        "records": [str(n) for n in z.nodes.keys()][:100]}
        except Exception:
            continue
    return None

# ============================================================
# COLLECTORS
# ============================================================

def collect_domain(domain):
    det = resolve_all_detailed(domain)
    rec = det["records"]
    dns_errors = det["errors"]
    ct = crt_subdomains(domain)
    raw = whois_domain(domain)
    kvw = parse_whois(raw) if raw and not raw.startswith("__error__") else {}
    imp = ["domain name", "registrar", "creation date", "created",
           "updated date", "expiry", "expiration", "registrant",
           "name server", "status", "dnssec"]
    clean = {k: v for k, v in kvw.items() if any(f in k for f in imp)}
    out = {
        "meta": {"type": "domain", "target": domain,
                 "generated_at": now_iso(), "tool": "ASTRYM " + VERSION},
        "dns": rec,
        "subdomains_ct": ct,
        "whois": clean,
    }
    if dns_errors:
        out["dns_errors"] = dns_errors
    return out

def collect_dns(domain):
    det = resolve_all_detailed(domain)
    rec = det["records"]
    dns_errors = det["errors"]
    keys = []
    if HAS_DNS:
        try:
            _r = _init_resolver()
            ans = _r.resolve(domain, "DNSKEY", lifetime=3) if _r else []
            keys = [str(k) for k in ans]
        except Exception:
            pass
    out = {
        "meta": {"type": "dns", "target": domain,
                 "generated_at": now_iso(), "tool": "ASTRYM " + VERSION},
        "records": rec,
        "dnssec": {"enabled": bool(keys), "keys": keys},
    }
    if dns_errors:
        out["dns_errors"] = dns_errors
    return out

def collect_sub(domain, wordlist=None, workers=40):
    ct = crt_subdomains(domain)
    words = DEFAULT_WORDS
    wl = "builtin"
    if wordlist:
        try:
            with open(wordlist, "r", encoding="utf-8") as f:
                words = [l.strip() for l in f
                         if l.strip() and not l.startswith("#")]
            wl = wordlist
        except Exception:
            pass
    bf = brute_subs(domain, words, workers)
    merged = {}
    for s in ct:
        merged.setdefault(s, {"sources": set(), "ips": set()})["sources"].add("ct")
    for h, ips in bf:
        e = merged.setdefault(h, {"sources": set(), "ips": set()})
        e["sources"].add("brute")
        e["ips"].update(ips)
    results = [{"host": h, "sources": sorted(m["sources"]),
                "ips": sorted(m["ips"])} for h, m in sorted(merged.items())]
    out_data = {
        "meta": {"type": "sub", "target": domain,
                 "generated_at": now_iso(), "tool": "ASTRYM " + VERSION},
        "stats": {"ct_count": len(ct), "brute_count": len(bf),
                  "total_unique": len(merged), "wordlist": wl,
                  "wordlist_size": len(words)},
        "subdomains": results,
    }
    if collect_free_for_domain:
        try:
            free_data = collect_free_for_domain(domain)
            if free_data:
                out_data["free_sources"] = free_data
        except Exception:
            pass
    return out_data

# ============================================================
# EXTENDED WRAPPERS
# ============================================================

def _x_domain(domain):
    out = extra_subs(domain)
    return out

def _x_dns(domain):
    out = {}
    if not HAS_REQUESTS:
        return out
    for prov in ("cloudflare", "google"):
        for rt in ("A", "MX", "NS", "TXT"):
            vals = dns_via_doh(domain, rt, prov)
            if vals:
                out[prov + "_" + rt] = vals
    axfr = dns_zone_transfer(domain)
    if axfr:
        out["zone_transfer"] = axfr
    return out

# ============================================================
# EXTERNAL LINKS
# ============================================================

def extras_links_domain(domain):
    return [
        ("SecurityTrails", "https://securitytrails.com/domain/" + domain + "/dns"),
        ("ViewDNS History", "https://viewdns.info/iphistory/?domain=" + domain),
        ("ViewDNS Reverse IP", "https://viewdns.info/reverseip/?host=" + domain),
        ("DNSDumpster", "https://dnsdumpster.com/"),
        ("Netcraft", "https://sitereport.netcraft.com/?url=https://" + domain),
        ("Shodan Domain", "https://www.shodan.io/domain/" + domain),
        ("urlscan.io", "https://urlscan.io/domain/" + domain),
        ("URLVoid", "https://www.urlvoid.com/scan/" + domain),
        ("Sucuri", "https://sitecheck.sucuri.net/results/" + domain),
        ("Qualys SSL Labs", "https://www.ssllabs.com/ssltest/analyze.html?d=" + domain),
        ("Hardenize", "https://www.hardenize.com/report/" + domain),
        ("MXToolbox", "https://mxtoolbox.com/SuperTool.aspx?action=mx%3a" + domain),
        ("IntoDNS", "https://intodns.com/" + domain),
        ("ThreatCrowd", "https://www.threatcrowd.org/domain.php?domain=" + domain),
        ("Wayback", "https://web.archive.org/web/*/" + domain),
        ("SimilarWeb", "https://www.similarweb.com/website/" + domain),
        ("BuiltWith", "https://builtwith.com/" + domain),
        ("Wappalyzer", "https://www.wappalyzer.com/lookup/" + domain),
        ("Censys", "https://search.censys.io/search?q=" + domain),
        ("FOFA", "https://fofa.info/result?qbase64=" +
         __import__("base64").b64encode(('domain="' + domain + '"').encode()).decode()),
        ("ZoomEye", "https://www.zoomeye.org/searchResult?q=" + domain),
    ]

def extras_links_dns(domain):
    return [
        ("Google DNS", "https://dns.google/query?name=" + domain),
        ("Cloudflare DNS", "https://1.1.1.1/dns/#" + domain),
        ("DNSlytics", "https://dnslytics.com/domain/" + domain),
        ("ViewDNS Info", "https://viewdns.info/dnsrecord/?domain=" + domain),
        ("SecurityTrails", "https://securitytrails.com/domain/" + domain + "/history/dns"),
        ("IntoDNS", "https://intodns.com/" + domain),
        ("MXToolbox", "https://mxtoolbox.com/DNSLookup.aspx"),
        ("NSLookup.io", "https://www.nslookup.io/domains/" + domain + "/dns-records/"),
        ("DNSViz", "https://dnsviz.net/d/" + domain + "/dnssec/"),
        ("ZoneMaster", "https://www.zonemaster.net/domain_check"),
        ("Hardenize", "https://www.hardenize.com/report/" + domain + "/dns"),
    ]

def extras_links_sub(domain):
    return [
        ("crt.sh", "https://crt.sh/?q=%25." + domain),
        ("Certspotter", "https://sslmate.com/certspotter/"),
        ("Facebook CT", "https://developers.facebook.com/tools/ct/search/"),
        ("Google CT", "https://transparencyreport.google.com/https/certificates"),
        ("VirusTotal DNS", "https://www.virustotal.com/gui/domain/" +
         domain + "/relations/domains"),
        ("SecurityTrails", "https://securitytrails.com/list/apex_domain/" + domain),
        ("HackerTarget", "https://hackertarget.com/find-dns-host-records/"),
        ("RapidDNS", "https://rapiddns.io/subdomain/" + domain),
        ("DNSDumpster", "https://dnsdumpster.com/"),
        ("URLScan", "https://urlscan.io/domain/" + domain),
        ("AlienVault OTX", "https://otx.alienvault.com/indicator/domain/" + domain),
        ("ThreatCrowd", "https://www.threatcrowd.org/domain.php?domain=" + domain),
        ("BeVigil", "https://bevigil.com/search?query=" + domain),
        ("Censys", "https://search.censys.io/certificates?q=" + domain),
        ("Bufferover", "https://dns.bufferover.run/dns?q=." + domain),
    ]

# ============================================================
# ENTRY POINTS
# ============================================================

def run_domain(target, extras=False):
    t = target.lower().strip()
    if not is_domain(t):
        c_err("not a valid domain: " + target)
        return None
    d = collect_domain(t)
    if extras:
        d["extended"] = _x_domain(t)
        d["extended_links"] = extras_links_domain(t)
    # # ASTRYM consensus-domain patch
    try:
        from astrym_consensus import aggregate_domain as _aggd
        d["consensus"] = _aggd(d)
    except Exception:
        pass
    hist_record("domain", t, {"ct_subs": len(d.get("subdomains_ct", []))})
    return d

def run_dns(target, extras=False):
    t = target.lower().strip()
    if not is_domain(t):
        c_err("not a valid domain: " + target)
        return None
    d = collect_dns(t)
    if extras:
        d["extended"] = _x_dns(t)
        d["extended_links"] = extras_links_dns(t)
    hist_record("dns", t, {"records": sum(len(v) for v in d["records"].values())})
    return d

def run_sub(target, extras=False, wordlist=None, workers=40, args=None):
    import time as _t
    t = target.lower().strip()
    if not is_domain(t):
        c_err("not a valid domain: " + target)
        return None

    d = collect_sub(t, wordlist=wordlist, workers=workers)

    if extras:
        # 1) пассивные источники из extra_subs
        try:
            extra = extra_subs(t)
            merged = {x["host"]: x for x in d["subdomains"]}
            for src_name, subs in extra.items():
                for s in subs:
                    if s in merged:
                        if src_name not in merged[s]["sources"]:
                            merged[s]["sources"].append(src_name)
                    else:
                        merged[s] = {"host": s,
                                     "sources": [src_name], "ips": []}
            d["subdomains"] = [merged[h] for h in sorted(merged)]
            d["stats"]["total_unique"] = len(d["subdomains"])
        except Exception as _e:
            c_warn("extra_subs: " + str(_e)[:100])

        # 2) permutation
        perm_count = 0
        skip_perm = bool(args.get("no_permute")) if args else False
        if _permute_subs and _resolve_permutations and not skip_perm:
            try:
                from astrym_core import section as _sec, c_info as _ci
                _ci("permutation поддоменов...")
                known = [x["host"] for x in d["subdomains"]]
                known += d.get("meta", {}).get("ct_samples", []) or []
                variants = _permute_subs(known, t, limit=150)
                perm_found = _resolve_permutations(variants,
                                                    workers=workers)
                merged2 = {x["host"]: x for x in d["subdomains"]}
                for h, ips in perm_found:
                    if h in merged2:
                        if "permutation" not in merged2[h]["sources"]:
                            merged2[h]["sources"].append("permutation")
                        merged2[h]["ips"] = sorted(
                            set(merged2[h].get("ips", []) + ips))
                    else:
                        merged2[h] = {"host": h,
                                      "sources": ["permutation"],
                                      "ips": ips}
                d["subdomains"] = [merged2[h] for h in sorted(merged2)]
                d["stats"]["permutation_count"] = len(perm_found)
                d["stats"]["total_unique"] = len(d["subdomains"])
                perm_count = len(perm_found)
                c_ok("permutation: +" + str(perm_count))
            except Exception as _e:
                c_warn("permutation: " + str(_e)[:100])

        # 3) HTTP probe
        skip_probe = bool(args.get("no_probe")) if args else False
        if _probe_many and not skip_probe:
            try:
                from astrym_core import c_info as _ci
                hosts = [x["host"] for x in d["subdomains"]][:50]
                if hosts:
                    _ci("HTTP probe для " + str(len(hosts)) + " хостов...")
                    probes = _probe_many(hosts, workers=20)
                    by_host = {p["host"]: p for p in probes if p}
                    probed = 0
                    for x in d["subdomains"]:
                        p = by_host.get(x["host"])
                        if p:
                            x["http"] = {
                                "status": p.get("status"),
                                "title": p.get("title"),
                                "server": p.get("server"),
                                "url": p.get("url"),
                            }
                            probed += 1
                    d["stats"]["probed_count"] = probed
                    c_ok("HTTP: " + str(probed) + "/" +
                         str(len(hosts)) + " отвечают")
            except Exception as _e:
                c_warn("probe: " + str(_e)[:100])

    hist_record("sub", t, {"unique": d["stats"]["total_unique"]})
    return d


