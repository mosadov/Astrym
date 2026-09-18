#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Email 8.1.0 — email + SMTP + HIBP + Gravatar + extended

import os, re, time, json, hashlib, socket, smtplib

from astrym_core import (
    now_iso, is_email, is_onion_email, resolve_mx,
    HAS_REQUESTS, HAS_DNS, load_cfg, hist_record,
    c_ok, c_warn, c_err, c_info, c_muted, _rl_sleep,
)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from astrym_free import collect_free_for_email
except ImportError:
    collect_free_for_email = None


VERSION = "8.1.0"

# ============================================================
# PROVIDERS
# ============================================================

PROVIDER_MAP = {
    "gmail.com": "Google Gmail", "googlemail.com": "Google Gmail",
    "protonmail.com": "Proton Mail", "protonmail.ch": "Proton Mail",
    "proton.me": "Proton Mail", "pm.me": "Proton Mail",
    "tutanota.com": "Tutanota", "tuta.io": "Tutanota",
    "outlook.com": "Microsoft Outlook",
    "hotmail.com": "Microsoft Outlook",
    "live.com": "Microsoft Outlook",
    "yahoo.com": "Yahoo", "yandex.ru": "Yandex",
    "mail.ru": "Mail.ru", "icloud.com": "Apple iCloud",
    "me.com": "Apple iCloud", "zoho.com": "Zoho",
    "aol.com": "AOL", "gmx.com": "GMX", "gmx.de": "GMX",
    "fastmail.com": "Fastmail", "fastmail.fm": "Fastmail",
    "tormail.org": "Tor Mail (legacy)", "mail2tor.com": "Mail2Tor",
    "secmail.pro": "SecMail", "cock.li": "Cock.li",
    "danwin1210.de": "DanWin", "dnmx.org": "DNMX",
    "onionmail.org": "OnionMail",
}

DISPOSABLE = {
    "mailinator.com", "tempmail.com", "guerrillamail.com",
    "10minutemail.com", "throwaway.email", "yopmail.com",
    "trashmail.com", "sharklasers.com", "grr.la", "spam4.me",
    "temp-mail.org", "dispostable.com", "maildrop.cc",
    "getnada.com", "mohmal.com", "tempmail.net",
}

def email_parse(email):
    email = (email or "").strip().lower()
    if "@" not in email:
        return None, None, None
    local, domain = email.rsplit("@", 1)
    return local, domain, PROVIDER_MAP.get(domain)

# ============================================================
# GRAVATAR
# ============================================================

def gravatar_check(email):
    if not HAS_REQUESTS:
        return {"found": None}
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    try:
        r = requests.get("https://www.gravatar.com/avatar/" + h + "?d=404&s=200",
                         timeout=8)
        if r.status_code == 200:
            return {"found": True, "hash": h,
                    "url": "https://www.gravatar.com/avatar/" + h + "?s=400"}
        return {"found": False, "hash": h}
    except Exception as e:
        return {"found": None, "error": str(e)}

# ============================================================
# HIBP
# ============================================================

def hibp_check(email):
    if not HAS_REQUESTS:
        return {"found": None}
    try:
        r = requests.get("https://haveibeenpwned.com/api/v3/breachedaccount/" + email,
                         headers={"User-Agent": "ASTRYM/" + VERSION},
                         timeout=10)
        if r.status_code == 200:
            return {"found": True, "breaches": r.json()}
        if r.status_code == 404:
            return {"found": False, "breaches": [],
                    "note": "not in HIBP database"}
        if r.status_code == 401 or r.status_code == 403:
            return {"found": None,
                    "requires_key": True,
                    "message": "HIBP requires paid API key (401/403)",
                    "manual_check_url":
                    "https://haveibeenpwned.com/account/" + email,
                    "env": "HIBP_API_KEY"}
        if r.status_code == 429:
            return {"found": None, "error": "rate limit"}
        return {"found": None, "error": "HTTP " + str(r.status_code)}
    except Exception as e:
        return {"found": None, "error": str(e)}

# ============================================================
# SMTP VERIFY
# ============================================================



def _helo_name():
    """FIX 9.1.3: не светим .local в SMTP HELO — провайдеры банят."""
    return os.environ.get("ASTRYM_SMTP_HELO", "mailcheck.org")

def smtp_verify(email, mx_hosts=None, timeout=8,
                sender=os.environ.get("ASTRYM_SMTP_SENDER", "verify@mailcheck.org")):
    res = {
        "status": "unknown", "code": None, "message": None,
        "mx_used": None, "timing_ms": 0, "steps": [],
        "mx_records": [], "port_blocked": False,
    }
    if not is_email(email):
        res["status"] = "invalid_syntax"
        return res
    if not mx_hosts:
        _, domain, _ = email_parse(email)
        mx_hosts = [h for _, h in resolve_mx(domain)]
    res["mx_records"] = list(mx_hosts)
    if not mx_hosts:
        res["status"] = "no_mx"
        return res

    t0 = time.time()
    all_conn_err = True

    for host in mx_hosts:
        try:
            s = smtplib.SMTP(host, 25, timeout=timeout)
            all_conn_err = False
            res["steps"].append({"connect": {"host": host, "code": 220}})

            ehlo_code, _ = s.ehlo(_helo_name())
            res["steps"].append({"ehlo": {"code": ehlo_code}})

            try:
                s.starttls()
                s.ehlo(_helo_name())
            except Exception:
                pass

            mail_code, _ = s.mail(sender)
            res["steps"].append({"mail_from": {"email": sender,
                                                "code": mail_code}})

            rcpt_code, rcpt_msg = s.rcpt(email)
            if isinstance(rcpt_msg, bytes):
                rcpt_msg = rcpt_msg.decode("utf-8", errors="replace")
            res["steps"].append({"rcpt_to": {
                "email": email, "code": rcpt_code,
                "message": (rcpt_msg or "")[:200]}})

            try:
                s.quit()
            except Exception:
                pass

            res["mx_used"] = host
            res["code"] = rcpt_code
            res["message"] = (rcpt_msg or "")[:200]

            if rcpt_code in (250, 251):
                res["status"] = "valid"
            elif rcpt_code in (550, 551, 552, 553):
                res["status"] = "invalid"
            elif rcpt_code in (450, 451, 452):
                res["status"] = "greylisted"
            elif rcpt_code in (421, 554):
                res["status"] = "blocked"
            else:
                res["status"] = "smtp_" + str(rcpt_code)
            break

        except smtplib.SMTPServerDisconnected:
            res["status"] = "disconnected"
            res["mx_used"] = host
        except smtplib.SMTPConnectError:
            res["status"] = "connect_error"
            res["mx_used"] = host
        except (socket.timeout, TimeoutError):
            res["status"] = "timeout"
            res["mx_used"] = host
        except OSError as e:
            res["status"] = "connect_error"
            res["mx_used"] = host
            res["message"] = str(e)
        except Exception as e:
            res["status"] = "error"
            res["message"] = type(e).__name__ + ": " + str(e)
            res["mx_used"] = host

    if all_conn_err and res["status"] in ("connect_error", "timeout"):
        res["port_blocked"] = True

    res["timing_ms"] = int((time.time() - t0) * 1000)
    return res

# ============================================================
# EXTENDED
# ============================================================

def _x_email(email):
    out = {}
    if not HAS_REQUESTS:
        return out

    # EmailRep
    try:
        r = requests.get("https://emailrep.io/" + email, timeout=10,
                         headers={"User-Agent": "ASTRYM/" + VERSION})
        if r.status_code == 200:
            d = r.json()
            out["emailrep"] = {
                "reputation": d.get("reputation"),
                "suspicious": d.get("suspicious"),
                "references": d.get("references"),
                "details": d.get("details", {}),
            }
    except Exception:
        pass

    # Disify
    try:
        r = requests.get("https://www.disify.com/api/email/" + email,
                         timeout=10)
        if r.status_code == 200:
            out["disify"] = r.json()
    except Exception:
        pass

    # MTA-STS
    _, dom, _ = email_parse(email)
    if dom:
        try:
            r = requests.get("https://mta-sts." + dom +
                             "/.well-known/mta-sts.txt", timeout=8)
            if r.status_code == 200 and "version" in r.text.lower():
                out["mta_sts"] = r.text[:500]
        except Exception:
            pass

    # PGP (keys.openpgp.org)
    try:
        r = requests.get("https://keys.openpgp.org/vks/v1/by-email/" + email,
                         timeout=10)
        if r.status_code == 200 and "BEGIN PGP PUBLIC KEY BLOCK" in r.text:
            out["pgp"] = {"found": True, "size": len(r.text)}
    except Exception:
        pass

    return out

# ============================================================
# EXTERNAL LINKS
# ============================================================

def extras_links_email(email):
    return [
        ("HaveIBeenPwned", "https://haveibeenpwned.com/account/" + email),
        ("Hunter.io", "https://hunter.io/email-verifier/" + email),
        ("EmailRep", "https://emailrep.io/" + email),
        ("Firefox Monitor", "https://monitor.firefox.com/"),
        ("Dehashed", "https://dehashed.com/"),
        ("LeakCheck", "https://leakcheck.io/"),
        ("IntelX", "https://intelx.io/?s=" + email),
        ("Snusbase", "https://snusbase.com/"),
        ("BreachDirectory", "https://breachdirectory.org/"),
        ("Epieos", "https://epieos.com/?q=" + email),
        ("WhatsMyName", "https://whatsmyname.app/?q=" + email),
        ("ThatsThem", "https://thatsthem.com/email/" + email),
        ("PSBDMP", "https://psbdmp.ws/search?q=" + email),
        ("Disify", "https://www.disify.com/"),
        ("MXToolbox", "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a" + email),
    ]

# ============================================================
# COLLECTOR
# ============================================================

def collect_email(email):
    email = email.strip().lower()
    local, domain, prov = email_parse(email)
    mx = []
    if domain and not domain.endswith(".onion"):
        try:
            mx = [h for _, h in resolve_mx(domain)]
        except Exception:
            mx = []
    return {
        "meta": {"type": "email", "target": email,
                 "generated_at": now_iso(), "tool": "ASTRYM " + VERSION},
        "overview": {
            "email": email,
            "local": local,
            "domain": domain,
            "provider": prov,
            "disposable": domain in DISPOSABLE if domain else False,
        },
        "mx": mx,
        "gravatar": gravatar_check(email),
        "smtp": smtp_verify(email, mx),
        "hibp": hibp_check(email),
        "free_sources": (collect_free_for_email(email)
                          if collect_free_for_email else {}),
    }

# ============================================================
# ENTRY POINT
# ============================================================

def run_email(target, extras=False):
    if not (is_email(target) or is_onion_email(target)):
        c_err("not a valid email: " + target)
        return None
    d = collect_email(target)
    if extras:
        d["extended"] = _x_email(target)
        d["extended_links"] = extras_links_email(target)
    _, dom, _ = email_parse(target)
    hist_record("email", target, {"provider": dom,
                                    "smtp": d["smtp"].get("status")})
    return d