#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Render 8.1.0 — console render функции

from astrym_core import (
    c_ok, c_warn, c_err, c_info, c_muted, console, HAS_RICH,
    kv, section, header, RECORD_TYPES, classify,
)

# ============================================================
# IP
# ============================================================



# ============================================================
# ASTRYM 9.1.5 — friendly empty strings
# ============================================================

_ND = "[muted]нет данных[/muted]"
_ND_MX = "[muted]MX-записи не найдены[/muted]"
_ND_A = "[muted]A-записи не найдены[/muted]"
_ND_NS = "[muted]NS-серверы не найдены[/muted]"
_ND_TXT = "[muted]TXT-записей нет[/muted]"
_ND_SUB = "[muted]поддомены не обнаружены[/muted]"
_ND_WHOIS = "[muted]WHOIS-данные недоступны[/muted]"
_ND_GEO = "[muted]геолокация недоступна[/muted]"
_ND_HIBP = "[muted]проверка утечек недоступна[/muted]"
_ND_PGP = "[muted]публичный PGP-ключ не найден[/muted]"
_ND_GRAVATAR = "[muted]Gravatar-профиль не найден[/muted]"
_ND_SMTP = "[muted]SMTP не отвечает[/muted]"
_ND_SOURCES = "[muted]источники недоступны[/muted]"


def _nd(value, fallback=_ND):
    if value is None:
        return fallback
    if isinstance(value, str) and not value.strip():
        return fallback
    if isinstance(value, (list, dict, tuple)) and len(value) == 0:
        return fallback
    return value



# ============================================================
# ASTRYM 9.3 — Free sources render
# ============================================================

def _render_free_sources(d):
    """Показывает данные из бесплатных источников."""
    fs = d.get("free_sources")
    if not fs:
        return

    # --- email: XposedOrNot ---
    xon = fs.get("xposedornot")
    if xon:
        section("Утечки (XposedOrNot)")
        if xon.get("found"):
            c_err("найден в " + str(xon.get("breach_count", 0)) +
                  " утечках")
            for b in xon.get("breaches", [])[:20]:
                name = b.get("name", "?") if isinstance(b, dict) else str(b)
                c_muted("  · " + name)
        else:
            c_ok("email не найден в утечках")

    # --- domain: ThreatCrowd ---
    tc = fs.get("threatcrowd")
    if tc:
        subs = tc.get("subdomains", []) or []
        if subs:
            section("ThreatCrowd (" + str(len(subs)) + " поддоменов)")
            for s in subs[:30]:
                c_muted("  " + s)
            if len(subs) > 30:
                c_muted("  ... +" + str(len(subs) - 30))
        emails = tc.get("emails", []) or []
        if emails:
            section("ThreatCrowd emails")
            for e in emails[:20]:
                c_muted("  " + e)

    # --- domain: ThreatMiner ---
    tm = fs.get("threatminer")
    if tm:
        subs = tm.get("subdomains", []) or []
        if subs:
            section("ThreatMiner (" + str(len(subs)) + " поддоменов)")
            for s in subs[:30]:
                c_muted("  " + s)
            if len(subs) > 30:
                c_muted("  ... +" + str(len(subs) - 30))

    # --- domain: Wayback ---
    wb = fs.get("wayback")
    if wb:
        cnt = wb.get("count", 0)
        interesting = wb.get("interesting", []) or []
        if cnt:
            section("Wayback Machine (" + str(cnt) + " URL)")
            if interesting:
                c_warn("интересные находки:")
                for u in interesting[:20]:
                    c_muted("  · " + u)
            else:
                c_muted("  интересных URL не найдено")

def render_ip(d):
    header("IP Analysis", d["meta"]["target"])
    section("Overview")
    ov = d.get("overview", {}); g = d.get("geo", {})
    rows = [("Address", ov.get("address")), ("Version", ov.get("version")),
            ("PTR", ov.get("ptr")), ("Private", "yes" if ov.get("private") else "no")]
    if "error" not in g:
        rows += [("Country", str(g.get("country","?")) + " [" +
                  str(g.get("countryCode","?")) + "]"),
                 ("Region", g.get("regionName")), ("City", g.get("city")),
                 ("ISP", g.get("isp")), ("Org", g.get("org")),
                 ("ASN", g.get("as")), ("Source", g.get("source"))]
    else:
        rows.append(("GeoIP", _ND_GEO + " (" + str(g.get("error"))[:60] + ")"))
    kv(rows)

    section("DNSBL")
    kv([(x["zone"],
         "[err]listed[/err]" if x["status"] == "listed"
         else "[ok]clean[/ok]" if x["status"] == "clean"
         else "[muted]" + x["status"] + "[/muted]") for x in d.get("dnsbl", [])])

    section("WHOIS")
    w = d.get("whois", {})
    if not w: c_warn("unavailable")
    else:
        for k, v in w.items():
            c_muted("  " + k.ljust(20) + " " + v)

    # ASTRYM ip-consensus+dnssec fix
    _cons = d.get("consensus") or {}
    if _cons.get("fields"):
        try:
            from astrym_consensus import render_consensus_block
            render_consensus_block(_cons["fields"], section, kv,
                                    c_ok, c_warn, c_err, c_muted)
        except Exception:
            pass
    _render_extended(d)

# ============================================================
# DOMAIN
# ============================================================

def render_domain(d):
    header("Domain Analysis", d["meta"]["target"])
    section("DNS Records")
    rec = d.get("dns", {})
    any_rec = False
    for rt in RECORD_TYPES:
        vs = rec.get(rt, [])
        for i, v in enumerate(vs):
            any_rec = True
            c_muted("  " + (rt if i == 0 else "").ljust(8) + " " + v)
    if not any_rec:
        c_muted("  " + _ND + " (DNS-резолвер недоступен или нет записей)")

    section("Subdomains CT")
    subs = d.get("subdomains_ct", [])
    if subs:
        c_ok("Found " + str(len(subs)))
        for s in subs[:60]: c_muted("  " + s)
        if len(subs) > 60: c_muted("  ... +" + str(len(subs)-60))
    else: c_warn("none")

    section("WHOIS")
    for k, v in d.get("whois", {}).items():
        c_muted("  " + k[:28].ljust(28) + " " + v)
    # # ASTRYM consensus-domain patch
    _cons = d.get("consensus") or {}
    if _cons.get("fields"):
        try:
            from astrym_consensus import render_consensus_block
            render_consensus_block(_cons["fields"], section, kv,
                                    c_ok, c_warn, c_err, c_muted)
        except Exception:
            pass

    _render_dns_errors(d)
    _render_extended(d)

# ============================================================
# DNS
# ============================================================

    _render_free_sources(d)


def render_dns(d):
    header("DNS Records", d["meta"]["target"])
    for rt in RECORD_TYPES:
        section(rt)
        vs = d.get("records", {}).get(rt, [])
        if not vs: c_muted("  - none -")
        else:
            for v in vs: c_muted("  " + v)
    section("DNSSEC")
    if d.get("dnssec", {}).get("enabled"):
        c_ok("enabled · " + str(len(d["dnssec"]["keys"])) + " DNSKEY")
    else: c_warn("not enabled")

    _render_dns_errors(d)
    _render_extended(d)

# ============================================================
# SUB
# ============================================================

def render_sub(d):
    header("Subdomain Enumeration", d["meta"]["target"])
    s = d.get("stats", {})
    section("Stats")
    kv([("CT", s.get("ct_count", 0)), ("Brute", s.get("brute_count", 0)),
        ("Unique", s.get("total_unique", 0)), ("Wordlist", s.get("wordlist"))])

    section("Results")
    subs = d.get("subdomains", [])
    if not subs:
        c_muted("  " + _ND_SUB)
    else:
        for i, x in enumerate(subs[:150], 1):
            http_tag = ""
            if x.get("http") and x["http"].get("status"):
                http_tag = " [" + str(x["http"]["status"]) + "]"
            c_muted("  " + str(i).rjust(3) + ". " + x["host"].ljust(40) +
                    " [" + ",".join(x.get("sources", [])) + "]" + http_tag)
        if len(subs) > 150:
            c_muted("  ... +" + str(len(subs)-150))

    _render_extended(d)

# ============================================================
# EMAIL
# ============================================================

def render_email(d):
    header("Email Analysis", d["meta"]["target"])
    ov = d.get("overview", {})
    section("Overview")
    kv([("Email", ov.get("email")), ("Local", ov.get("local")),
        ("Domain", ov.get("domain")), ("Provider", ov.get("provider")),
        ("Disposable", "yes" if ov.get("disposable") else "no")])

    section("MX")
    mx = d.get("mx", [])
    if not mx:
        c_muted("  " + _ND_MX)
    else:
        for m in mx: c_muted("  " + m)

    smtp = d.get("smtp")
    if smtp:
        section("SMTP")
        st = smtp.get("status", "?")
        if st == "valid": c_ok("SMTP: ящик существует")
        elif st == "invalid": c_err("SMTP: ящик не существует")
        elif st == "no_mx": c_muted("  " + _ND_MX)
        elif st == "connect_error" or st == "timeout":
            c_muted("  " + _ND_SMTP + " (порт 25 заблокирован?)")
        else: c_warn("SMTP: " + str(st))
        kv([("Code", str(smtp.get("code"))),
            ("MX used", smtp.get("mx_used")),
            ("Time", str(smtp.get("timing_ms", 0)) + "ms")])
        if smtp.get("port_blocked"):
            c_info("port 25 blocked by ISP")
        if smtp.get("steps"):
            section("Steps")
            for step in smtp["steps"]:
                for k, v in step.items(): kv([(k, str(v))])

    section("Gravatar")
    g = d.get("gravatar", {})
    if g.get("found"): c_ok("found: " + str(g.get("url")))
    else: c_muted("no avatar")

    section("HIBP")
    h = d.get("hibp", {})
    if h.get("found") is True:
        c_err("BREACHED (" + str(len(h.get("breaches", []))) + ")")
        for b in h.get("breaches", [])[:10]:
            c_muted("  " + str(b.get("Name")) + " · " + str(b.get("BreachDate")))
    elif h.get("found") is False: c_ok("утечек не найдено")
    else:
        if h.get("requires_key"):
            c_muted("  " + _ND_HIBP + " (требуется API-ключ HIBP)")
            if h.get("manual_check_url"):
                c_muted("  → " + h["manual_check_url"])
        elif h.get("error"):
            c_warn("HIBP: " + str(h["error"])[:80])
        else:
            c_muted("  " + _ND_HIBP)

    _render_extended(d)

# ============================================================
# CHECK
# ============================================================

    _render_free_sources(d)


def render_check(d):
    header("Threat Intelligence", d["meta"]["target"])
    rk = d.get("risk", {})
    lvl = rk.get("level", "?"); sc = rk.get("score", 0)
    cls = {"CLEAN":"ok","LOW":"ok","MEDIUM":"warn",
           "HIGH":"err","CRITICAL":"err"}.get(lvl, "muted")
    section("Risk")
    kv([("Score", "[" + cls + "]" + str(sc) + "/100[/" + cls + "]"),
        ("Level", "[" + cls + "]" + lvl + "[/" + cls + "]")])
    for r in rk.get("reasons", []): c_muted("  · " + r)

    _render_api_errors(d)

    for src, res in d.get("results", {}).items():
        section(src.upper())
        if not res: continue
        if res.get("error"): c_err(res["error"]); continue
        if res.get("found") is False: c_ok("not found"); continue
        rows = [(k.replace("_"," "), str(v)) for k, v in res.items()
                if k not in ("source","found","target","kind")
                and not isinstance(v, (list, dict))]
        if rows: kv(rows)

    _render_extended(d)

# ============================================================
# SSL
# ============================================================

def render_ssl(d):
    header("SSL/TLS", d["meta"]["target"])
    if d.get("error"): c_err(d["error"]); return
    section("Certificate")
    kv([("Protocol", d.get("protocol")), ("Cipher", d.get("cipher")),
        ("Subject CN", d.get("subject", {}).get("commonName")),
        ("Issuer CN", d.get("issuer", {}).get("commonName")),
        ("Not before", d.get("not_before")),
        ("Not after", d.get("not_after")),
        ("Days valid", d.get("days_valid"))])
    if d.get("expired"): c_err("EXPIRED")
    elif d.get("days_valid") is not None and d["days_valid"] < 15:
        c_warn("expires soon: " + str(d["days_valid"]) + "d")
    else: c_ok("valid")
    san = d.get("san", [])
    if san:
        section("SAN (" + str(len(san)) + ")")
        for s in san[:30]: c_muted("  " + s)

# ============================================================
# WEB
# ============================================================



# ============================================================
# ASTRYM 9.4 — favicon + analytics
# ============================================================

    _render_favicon_analytics(d)

def _render_favicon_analytics(d):
    fh = d.get("favicon_hash")
    if fh is not None:
        section("Favicon Hash (MurmurHash3)")
        c_ok("mmh3: " + str(fh))
        c_muted("  поиск в Shodan: https://www.shodan.io/search?query=http.favicon.hash:" + str(fh))

    a = d.get("analytics")
    if a:
        section("Shared Analytics IDs")
        for name, ids in a.items():
            for i in ids[:5]:
                c_ok(name.ljust(24) + str(i))

def render_web(d):
    header("Web Fingerprint", d["meta"]["target"])
    kv([("Final URL", d.get("final_url")), ("Status", d.get("status_code")),
        ("Title", d["titles"][0] if d.get("titles") else "-")])
    if d.get("cms_detected"):
        section("Technologies")
        for x in d["cms_detected"]: c_ok(x)
    if d.get("headers"):
        section("Headers")
        for k, v in d["headers"].items(): kv([(k, v)])
    if d.get("leaks"):
        section("Exposed paths")
        for x in d["leaks"]:
            cls = "err" if x["status"] == 200 else "warn"
            if HAS_RICH:
                console.print("  [" + cls + "]" + x["path"] +
                              "[/" + cls + "] " + str(x["status"]))
            else:
                print("  " + x["path"] + " " + str(x["status"]))

# ============================================================
# DARKWEB
# ============================================================

def render_darkweb(d):
    header("Darkweb", d["meta"]["target"])
    if d.get("error"):
        c_err(d["error"])
        if d.get("hint"): c_info(d["hint"])
        return
    section("Overview")
    kv([("Pages", d.get("pages_crawled", 0))])
    for k, vals in d.get("entities", {}).items():
        if vals:
            section(k.upper())
            for v in vals[:20]: c_muted("  " + v)

# ============================================================
# PHONE
# ============================================================

def render_phone(d):
    # ASTRYM phone-final
    from astrym_core import header, section, kv
    if not d:
        return
    meta = d.get("meta") or {}
    header("Phone OSINT", meta.get("target", "?"))
    if d.get("error"):
        c_err(d["error"])
        return

    p = d.get("parsed") or {}

    section("Parsed")
    rows = [
        ("Input", p.get("input")),
        ("Normalized", p.get("normalized")
            if p.get("normalized") != p.get("input") else None),
        ("E.164", p.get("e164")),
        ("International", p.get("international")),
        ("National", p.get("national")),
        ("RFC 3966", p.get("rfc3966")),
        ("Country code", p.get("country_code")),
        ("Region", p.get("region")),
        ("Region desc", p.get("region_description")),
        ("Carrier", p.get("carrier")),
        ("Line type", p.get("line_type")),
        ("Timezones", ", ".join(p.get("timezones") or []) or None),
        ("Valid", "yes" if p.get("valid") else "no"),
        ("Possible", "yes" if p.get("possible") else "no"),
    ]
    kv(rows)

    msgr = d.get("messengers") or {}
    if msgr:
        section("Messengers")
        for name, url in msgr.items():
            c_muted("  " + str(name).ljust(12) + str(url))

    rep = d.get("reputation") or {}
    if rep:
        section("Reputation services")
        for name, url in rep.items():
            c_muted("  " + str(name).ljust(12) + str(url))

    dorks = d.get("google_dorks") or []
    if dorks:
        section("Google Dorks (" + str(len(dorks)) + ")")
        for x in dorks:
            if isinstance(x, dict):
                c_muted("  " + str(x.get("query", ""))[:88])
                if x.get("url"):
                    c_muted("    " + str(x["url"])[:110])
            else:
                c_muted("  " + str(x)[:110])
def render_takeover(d):
    header("Subdomain Takeover", d["meta"]["target"])
    kv([("Checked", d.get("checked", 0)),
        ("Vulnerable", len(d.get("vulnerable", [])))])
    for x in d.get("vulnerable", []):
        c_err(x["subdomain"] + " -> " + x["service"])

# ============================================================
# LEAK
# ============================================================



# ============================================================
# ASTRYM 9.5 — paste dorks render
# ============================================================

    _render_paste_dorks(d)

def _render_paste_dorks(d):
    pd = d.get("paste_dorks")
    if not pd:
        return
    sites = pd.get("sites", [])
    dorks = pd.get("dorks", [])
    if not dorks:
        return
    section("Paste sites dorks (" + str(len(dorks)) + ")")
    c_muted("  sites: " + ", ".join(sites[:8]))
    c_muted("  примеры поиска:")
    interesting = [x for x in dorks if "BEGIN RSA" in x["query"]
                   or "AKIA" in x["query"] or "DB_PASSWORD" in x["query"]
                   or "api_key" in x["query"] or "password" in x["query"]]
    for x in interesting[:10]:
        c_muted("  · " + x["query"][:80])
        c_muted("    " + x["url"])
    c_muted("  всего сгенерировано: " + str(len(dorks)))

def render_leak(d):
    header("Leak Search", d["meta"]["target"])
    section("GitHub")
    for x in d.get("github", [])[:20]:
        c_muted("  " + str(x.get("repo")) + " :: " + str(x.get("path")))

# ============================================================
# ORIGIN
# ============================================================

def render_origin(d):
    header("Origin IP", d["meta"]["target"])
    kv([("Cloudflare", "yes" if d.get("is_cloudflare") else "no"),
        ("Current", ", ".join(d.get("current_ips", [])))])
    for ip in d.get("candidates", [])[:20]: c_ok(ip)

# ============================================================
# WHOIS-HISTORY
# ============================================================

def render_whois_history(d):
    header("WHOIS History", d["meta"]["target"])
    for row in d.get("timeline", [])[:30]:
        c_muted("  " + " | ".join(row))

# ============================================================
# SCAN
# ============================================================

def render_scan(d):
    header("Scan", d["meta"]["target"])
    k = d["meta"].get("detected_kind", "?")
    c_info("detected: " + k)
    if k == "ip": render_ip(d)
    elif k == "domain": render_domain(d)
    elif k == "email": render_email(d)
    sec = d.get("security", {})
    if sec.get("risk"):
        rk = sec["risk"]
        section("Risk")
        kv([("Level", rk.get("level")), ("Score", rk.get("score"))])

# ============================================================
# WATCH DIFF
# ============================================================

def render_watch_diff(diff, target):
    header("Watch diff", target)
    if not any([diff["added"], diff["removed"], diff["changed"]]):
        c_ok("no changes"); return
    for x in diff["added"]: c_ok("+ " + x)
    for x in diff["removed"]: c_err("- " + x)
    for x in diff["changed"]: c_warn("~ " + x)

# ============================================================
# EXTENDED BLOCK (для -x режима)
# ============================================================

def _render_extended(d):
    ext = d.get("extended")
    if ext:
        section("Extended sources")
        for src, vals in ext.items():
            if not vals: continue
            c_info(src)
            if isinstance(vals, dict):
                for k, v in vals.items():
                    if v: c_muted("    " + str(k) + ": " + str(v)[:80])
            elif isinstance(vals, list):
                for v in vals[:15]: c_muted("    " + str(v)[:80])

    links = d.get("extended_links")
    if links:
        section("External services")
        for name, url in links:
            c_muted("  " + name.ljust(22) + " " + url)

# ============================================================
# REGISTRY
# ============================================================

RENDER = {
    "ip": render_ip,
    "domain": render_domain,
    "dns": render_dns,
    "sub": render_sub,
    "email": render_email,
    "check": render_check,
    "ssl": render_ssl,
    "web": render_web,
    "darkweb": render_darkweb,
    "phone": render_phone,
    "takeover": render_takeover,
    "leak": render_leak,
    "origin": render_origin,
    "whois-history": render_whois_history,
    "scan": render_scan,
}

def render_any(d):
    t = d.get("meta", {}).get("type", "?")
    fn = RENDER.get(t)
    if fn:
        fn(d)
    else:
        c_warn("no renderer for type: " + t)

def _render_dns_errors(d):
    """Показать ошибки DNS-запросов, если есть."""
    errors = d.get("dns_errors")
    if not errors:
        return
    section("DNS errors")
    for rt, err in errors.items():
        cls = "warn" if "timeout" in err.lower() else "muted"
        if HAS_RICH:
            console.print("  [" + cls + "]" + rt.ljust(6) + "[/" + cls +
                          "] " + err)
        else:
            print("  " + rt.ljust(6) + " " + err)


def _render_api_errors(d):
    """Показать ошибки API в risk."""
    rk = d.get("risk") or {}
    errors = rk.get("api_errors") or []
    if not errors:
        return
    section("API errors (не влияют на score)")
    for e in errors:
        c_muted("  · " + e)


def _render_clear(d):
    from astrym_core import header, kv, c_ok
    if not d:
        return
    t = (d.get("meta") or {}).get("type", "clear")
    header(t, "-")
    if "cleared" in d:
        c_ok("history cleared: " + str(d["cleared"]) + " entries")
    if "files_cleared" in d:
        c_ok("log files cleared: " + str(d["files_cleared"]))
    if "files_removed" in d:
        c_ok("files removed: " + str(d["files_removed"]))


RENDER["clear-history"] = _render_clear
RENDER["clear-log"] = _render_clear
RENDER["clear-watches"] = _render_clear
RENDER["clear-results"] = _render_clear
