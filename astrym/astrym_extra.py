#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Extra 8.1.0 — ssl, phone, scan, watch, batch

import os, re, json, time, ssl as _ssl, socket, ipaddress
from pathlib import Path
from datetime import datetime, timezone

from astrym_core import (
    now_iso, classify, is_domain, is_ip, is_email, is_phone,
    WATCH_DIR, RESULTS_DIR, load_cfg, hist_record, HAS_DNS,
    HAS_REQUESTS, HAS_PN, HAS_GEOIP2,
    c_ok, c_warn, c_err, c_info, c_muted, _rl_sleep,
    RECORD_TYPES, safe_filename,
)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import phonenumbers
    HAS_PN = True
except ImportError:
    HAS_PN = False

VERSION = "8.1.0"

# ============================================================
# SSL
# ============================================================

def ssl_check(domain, port=443, timeout=10):
    out = {"domain": domain, "port": port}
    try:
        ctx = _ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                out["protocol"] = ssock.version()
                out["cipher"] = ssock.cipher()[0] if ssock.cipher() else None
                out["cipher_bits"] = ssock.cipher()[2] if ssock.cipher() else None
                out["subject"] = dict(x[0] for x in cert.get("subject", []))
                out["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                out["serial"] = cert.get("serialNumber")
                out["not_before"] = cert.get("notBefore")
                out["not_after"] = cert.get("notAfter")
                out["san"] = [x[1] for x in cert.get("subjectAltName", [])]
                try:
                    na = datetime.strptime(cert["notAfter"],
                                           "%b %d %H:%M:%S %Y %Z")
                    now = datetime.utcnow()
                    out["days_valid"] = (na - now).days
                    out["expired"] = now > na
                except Exception:
                    pass
    except _ssl.SSLCertVerificationError as e:
        out["error"] = "verify: " + str(e)
    except _ssl.SSLError as e:
        out["error"] = "ssl: " + str(e)
    except socket.timeout:
        out["error"] = "timeout"
    except Exception as e:
        out["error"] = type(e).__name__ + ": " + str(e)

    # deprecated protocols
    for proto, ctx_attr in (("TLS 1.0", getattr(_ssl.TLSVersion, "TLSv1", None)),
                             ("TLS 1.1", getattr(_ssl.TLSVersion, "TLSv1_1", None))):
        if ctx_attr is None:
            continue
        try:
            ctx2 = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = _ssl.CERT_NONE
            try:
                ctx2.minimum_version = ctx_attr
                ctx2.maximum_version = ctx_attr
            except AttributeError:
                continue
            with socket.create_connection((domain, port), timeout=5) as s:
                with ctx2.wrap_socket(s, server_hostname=domain):
                    out.setdefault("deprecated_protocols", []).append(proto)
        except Exception:
            pass

    # HSTS
    if HAS_REQUESTS:
        try:
            r = requests.get("https://" + domain + "/", timeout=8,
                             headers={"User-Agent": "ASTRYM/" + VERSION},
                             allow_redirects=True)
            hsts = r.headers.get("Strict-Transport-Security")
            if hsts:
                out["hsts"] = hsts
        except Exception:
            pass

    return out

def collect_ssl(domain, port=443):
    d = ssl_check(domain, port=port)
    d["meta"] = {"type": "ssl", "target": domain,
                 "generated_at": now_iso(), "tool": "ASTRYM " + VERSION}
    return d

def run_ssl(target, extras=False, port=443):
    t = target.lower().strip()
    if not is_domain(t):
        c_err("not domain: " + target)
        return None
    d = collect_ssl(t, port=port)
    hist_record("ssl", t, {"days_valid": d.get("days_valid")})
    return d

# ============================================================
# PHONE
# ============================================================

def collect_phone(number):
    # ASTRYM phone-final
    if not HAS_PN:
        return {"error": "phonenumbers not installed"}

    # --- нормализация входа ---
    raw = str(number).strip()
    # убрать разделители: пробелы, дефисы, точки, скобки
    cleaned = re.sub(r"[\s\-\.\(\)]+", "", raw)
    # 8XXX (11 цифр, начинается с 8) → +7XXX
    if len(cleaned) == 11 and cleaned[0] == "8" and cleaned[1:].isdigit():
        cleaned = "+7" + cleaned[1:]
    # 7XXX (11 цифр, начинается с 7) → +7XXX
    elif len(cleaned) == 11 and cleaned[0] == "7" and cleaned.isdigit():
        cleaned = "+" + cleaned
    # всё остальное без + → пытаемся как есть, но добавим +
    elif not cleaned.startswith("+") and cleaned.isdigit() and len(cleaned) > 10:
        cleaned = "+" + cleaned

    # --- парсинг ---
    p = None
    last_err = None
    for attempt in (cleaned, raw):
        try:
            p = phonenumbers.parse(attempt, None)
            break
        except Exception as e:
            last_err = str(e)
            continue
    if p is None:
        return {"error": "parse: " + str(last_err or "unknown")}

    try:
        valid = phonenumbers.is_valid_number(p)
    except Exception:
        valid = False
    try:
        possible = phonenumbers.is_possible_number(p)
    except Exception:
        possible = False
    if not valid and not possible:
        return {"error": "invalid number"}

    # --- форматы ---
    def _fmt(fmt):
        try:
            return phonenumbers.format_number(p, fmt)
        except Exception:
            return None

    e164 = _fmt(phonenumbers.PhoneNumberFormat.E164)
    intl = _fmt(phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    nat = _fmt(phonenumbers.PhoneNumberFormat.NATIONAL)
    rfc3966 = _fmt(phonenumbers.PhoneNumberFormat.RFC3966)

    if not e164:
        return {"error": "cannot format number"}

    digits = e164.replace("+", "").replace(" ", "")
    local = digits[-10:] if len(digits) > 10 else digits

    # --- line_type ---
    line_type = "unknown"
    try:
        raw_type = phonenumbers.number_type(p)
        line_type = str(raw_type).split(".")[-1].lower()
    except Exception:
        pass

    # --- carrier (phonenumbers 9.x требует явный импорт) ---
    carrier = None
    for attempt in ("phonenumbers.carrier", "phonenumbers.geocoder"):
        try:
            mod = __import__(attempt, fromlist=["name_for_number"])
            fn = getattr(mod, "name_for_number", None)
            if fn:
                val = fn(p, "en")
                if val:
                    carrier = val
                    break
        except Exception:
            continue

    # --- region ---
    region = None
    try:
        region = phonenumbers.region_code_for_number(p)
    except Exception:
        pass
    if not region:
        try:
            region = phonenumbers.region_code_for_country_code(p.country_code)
        except Exception:
            region = None

    # --- geocoder (описание региона) ---
    geo_desc = None
    try:
        import phonenumbers.geocoder as _geo
        geo_desc = _geo.description_for_number(p, "en") or None
    except Exception:
        pass

    # --- timezones (безопасно, с двумя путями) ---
    tzs = []
    for path in ("phonenumbers.timezone", "phonenumbers.geocoder"):
        try:
            mod = __import__(path, fromlist=["time_zones_for_number"])
            fn = getattr(mod, "time_zones_for_number", None)
            if fn:
                raw_tzs = list(fn(p))
                tzs = [t for t in raw_tzs if t and t != "Etc/Unknown"]
                if tzs:
                    break
        except Exception:
            continue

    # --- messengers ---
    messengers = {}
    try:
        messengers["whatsapp"] = "https://wa.me/" + digits
        messengers["telegram"] = "https://t.me/+" + digits
        messengers["viber"] = "viber://chat?number=%2B" + digits
        if region == "RU":
            messengers["signal"] = "https://signal.me/#p/+" + digits
    except Exception:
        pass

    # --- reputation ---
    reputation = {}
    try:
        reputation["truecaller"] = ("https://www.truecaller.com/search/"
                                     + digits)
        reputation["getcontact"] = ("https://getcontact.com/en/phone/"
                                     + digits)
        reputation["sync.me"] = "https://sync.me/search/?number=" + digits
        reputation["numlookup"] = ("https://www.numlookup.com/?number=%2B"
                                    + digits)
    except Exception:
        pass

    # --- Google dorks ---
    google_dorks = []
    try:
        from urllib.parse import quote as _q
        patterns = [
            '"' + e164 + '"',
            '"' + digits + '"',
            '"' + local + '"',
            '"' + e164 + '" site:facebook.com',
            '"' + e164 + '" site:vk.com',
            '"' + e164 + '" site:ok.ru',
            '"' + e164 + '" site:t.me',
            '"' + e164 + '" site:wa.me',
            '"' + e164 + '" filetype:pdf',
            '"' + e164 + '" -site:truecaller.com',
            '"' + e164 + '" -site:getcontact.com',
        ]
        for q in patterns:
            google_dorks.append({
                "query": q,
                "url": "https://www.google.com/search?q=" + _q(q),
            })
    except Exception:
        pass

    return {
        "parsed": {
            "input": number,
            "normalized": cleaned,
            "e164": e164,
            "international": intl,
            "national": nat,
            "rfc3966": rfc3966,
            "country_code": p.country_code,
            "region": region,
            "region_description": geo_desc,
            "carrier": carrier,
            "line_type": line_type,
            "timezones": tzs,
            "valid": valid,
            "possible": possible,
        },
        "messengers": messengers,
        "reputation": reputation,
        "google_dorks": google_dorks,
    }
def run_phone(target, extras=False):
    if not is_phone(target):
        c_err("not a valid phone: " + target)
        return None
    d = collect_phone(target)
    if d.get("error"):
        c_err(d["error"])
        return None
    d["meta"] = {"type": "phone", "target": target,
                 "generated_at": now_iso(), "tool": "ASTRYM " + VERSION}
    hist_record("phone", target,
                {"carrier": d["parsed"].get("carrier")})
    return d

# ============================================================
# WATCH
# ============================================================

def _watch_path(name):
    safe = safe_filename(name)
    return WATCH_DIR / (safe + ".json")

def watch_load(name):
    p = _watch_path(name)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def watch_save(name, data):
    try:
        _watch_path(name).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        return True
    except Exception:
        return False

def watch_list():
    out = []
    if not WATCH_DIR.is_dir():
        return out
    for f in WATCH_DIR.glob("*.json"):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            m = d.get("meta", {})
            out.append({"name": f.stem,
                        "target": m.get("target"),
                        "type": m.get("type"),
                        "at": m.get("generated_at")})
        except Exception:
            continue
    return out

def watch_diff(old, new):
    diff = {"added": [], "removed": [], "changed": []}
    if not old or not new:
        return diff
    t = new.get("meta", {}).get("type")
    if t == "sub":
        os_ = set(x["host"] for x in old.get("subdomains", []))
        ns_ = set(x["host"] for x in new.get("subdomains", []))
        diff["added"] = sorted(ns_ - os_)
        diff["removed"] = sorted(os_ - ns_)
    elif t == "dns":
        for rt in RECORD_TYPES:
            ov = set(old.get("records", {}).get(rt, []))
            nv = set(new.get("records", {}).get(rt, []))
            for v in nv - ov:
                diff["added"].append(rt + ": " + v)
            for v in ov - nv:
                diff["removed"].append(rt + ": " + v)
    elif t in ("domain", "ip"):
        ow = old.get("whois", {})
        nw = new.get("whois", {})
        for k in set(list(ow.keys()) + list(nw.keys())):
            if ow.get(k) != nw.get(k):
                diff["changed"].append(k + ": " + str(ow.get(k)) +
                                       " -> " + str(nw.get(k)))
        oc = set(old.get("subdomains_ct", []))
        nc = set(new.get("subdomains_ct", []))
        for s in nc - oc:
            diff["added"].append("ct: " + s)
        for s in oc - nc:
            diff["removed"].append("ct: " + s)
    elif t == "check":
        os_ = old.get("risk", {}).get("score", 0)
        ns_ = new.get("risk", {}).get("score", 0)
        if os_ != ns_:
            diff["changed"].append(
                "risk: " + str(os_) + " -> " + str(ns_))
    return diff

# ============================================================
# BATCH
# ============================================================

def batch_read(path):
    if not os.path.exists(path):
        return None
    lines = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    lines.append(ln)
    except Exception:
        return None
    return lines

# ============================================================
# SCAN (auto-detect)
# ============================================================

def collect_scan(target, extras=False):
    from astrym_ip import collect_ip, _x_ip
    from astrym_domain import collect_domain, _x_domain
    from astrym_email import collect_email, _x_email
    from astrym_check import sec_check_ip, sec_check_domain, compute_risk

    k = classify(target)
    if k == "ip":
        d = collect_ip(target)
        s = sec_check_ip(load_cfg(), target)
        if extras:
            d["extended"] = _x_ip(target)
    elif k == "domain":
        d = collect_domain(target)
        s = sec_check_domain(load_cfg(), target)
        if extras:
            d["extended"] = _x_domain(target)
    elif k == "email":
        d = collect_email(target)
        s = {"results": {}}
        if extras:
            d["extended"] = _x_email(target)
    else:
        d = {"meta": {"type": "scan", "target": target,
                      "generated_at": now_iso(),
                      "tool": "ASTRYM " + VERSION}}
        s = {"results": {}}
    s["risk"] = compute_risk(s)
    d["security"] = s
    d["meta"]["type"] = "scan"
    d["meta"]["detected_kind"] = k
    return d

def run_scan(target, extras=False):
    d = collect_scan(target, extras=extras)
    hist_record("scan", target,
                {"kind": d["meta"].get("detected_kind")})
    return d