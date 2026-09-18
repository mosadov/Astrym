#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Core 8.1.0 — базовые утилиты, конфиг, история, валидаторы, рендер-хелперы

CORE_VERSION = "8.1.0"

import os
import sys
import re
import json
import time
import socket
import hashlib
import ipaddress
import tempfile
import subprocess
import base64
import random
import string
from datetime import datetime, timezone, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# SAFE DIRECTORIES WITH /tmp FALLBACK
# ============================================================

def _test_write(path):
    try:
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        t = path / ".write_test_astrym"
        t.write_text("x", encoding="utf-8")
        t.unlink()
        return True
    except Exception:
        return False


def _resolve_dirs():
    try:
        base = Path(__file__).parent.resolve()
    except Exception:
        base = Path.cwd()
    results = base / "results"
    config = Path.home() / ".astrym"
    fallback = Path(tempfile.gettempdir()) / "astrym"

    if not _test_write(base):
        sys.stderr.write("[ASTRYM] WARN: " + str(base) +
                         " read-only, fallback " + str(fallback) + "\n")
        try:
            fallback.mkdir(parents=True, exist_ok=True)
            base = fallback
            results = fallback / "results"
        except Exception:
            pass

    if not _test_write(config):
        alt = fallback / ".astrym"
        sys.stderr.write("[ASTRYM] WARN: " + str(config) +
                         " read-only, fallback " + str(alt) + "\n")
        config = alt

    for d in (results, config):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    return base, results, config


BASE_DIR, RESULTS_DIR, CONFIG_DIR = _resolve_dirs()
CONFIG_PATH = CONFIG_DIR / "config.json"
HISTORY_PATH = CONFIG_DIR / "history.json"
WATCH_DIR = CONFIG_DIR / "watches"
GEOIP_DIR = CONFIG_DIR / "geoip"
CACHE_DIR = CONFIG_DIR / "cache"

for _d in (WATCH_DIR, GEOIP_DIR, CACHE_DIR):
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

for _p, _default in [(CONFIG_PATH, {}), (HISTORY_PATH, {"entries": []})]:
    if not _p.exists():
        try:
            _p.write_text(json.dumps(_default), encoding="utf-8")
        except Exception:
            pass


# ============================================================
# OPTIONAL DEPENDENCIES
# ============================================================

try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.theme import Theme
    from rich.rule import Rule
    from rich.align import Align
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib import colors as rl_colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

try:
    import phonenumbers
    HAS_PN = True
except ImportError:
    HAS_PN = False


# ============================================================
# CONSOLE
# ============================================================

if HAS_RICH:
    THEME = Theme({
        "ok": "green", "warn": "yellow", "err": "red",
        "info": "cyan", "muted": "grey50",
        "accent": "medium_purple1", "accent2": "purple",
        "link": "cyan underline", "value": "bright_white",
        "header": "bold medium_purple1",
    })
    console = Console(theme=THEME, highlight=False)
else:
    console = None


def c_ok(m):
    (console.print("[ok][+][/ok] " + str(m)) if HAS_RICH else print("[+] " + str(m)))


def c_warn(m):
    (console.print("[warn][!][/warn] " + str(m)) if HAS_RICH else print("[!] " + str(m)))


def c_err(m):
    (console.print("[err][-][/err] " + str(m)) if HAS_RICH else print("[-] " + str(m)))


def c_info(m):
    (console.print("[info].[/info] " + str(m)) if HAS_RICH else print(". " + str(m)))


def c_muted(m):
    (console.print("[muted]" + str(m) + "[/muted]") if HAS_RICH else print(str(m)))


def _clear():
    try:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
    except Exception:
        os.system("cls" if os.name == "nt" else "clear")


def print_deps():
    print("\n  Dependencies:")
    for name, ok, hint in [
        ("dnspython", HAS_DNS, "pip install dnspython"),
        ("requests",  HAS_REQUESTS, "pip install requests"),
        ("rich",      HAS_RICH, "pip install rich"),
        ("reportlab", HAS_PDF, "pip install reportlab"),
        ("geoip2",    HAS_GEOIP2, "pip install geoip2 (opt)"),
        ("phonenumbers", HAS_PN, "pip install phonenumbers (opt)"),
    ]:
        mark = "[ok]ok[/ok]" if ok else "[warn]opt[/warn]"
        if HAS_RICH:
            console.print("    " + name.ljust(14) + " " + mark)
            if not ok and "opt" not in hint:
                console.print("      [muted]Install: " + hint + "[/muted]")
        else:
            print("    " + name.ljust(14) + (" ok" if ok else " opt"))


# ============================================================
# RENDER HELPERS (header, section, kv)
# ============================================================

def header(title, subtitle=None):
    if HAS_RICH:
        _t = Text()
        _t.append("ASTRYM", style="header")
        _t.append("  |  ", style="muted")
        _t.append(str(title), style="accent")
        if subtitle:
            _t.append("\n")
            _t.append(str(subtitle), style="value")
        console.print()
        console.print(Panel(_t, border_style="medium_purple1",
                            box=box.ROUNDED, padding=(1, 2)))
    else:
        print("\n== " + str(title) + " ==")
        if subtitle:
            print(str(subtitle))


def section(title):
    if HAS_RICH:
        console.print()
        console.print(Rule(" " + str(title) + " ", style="accent"))
    else:
        print("\n-- " + str(title) + " --")


def kv(rows):
    if HAS_RICH:
        _t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        _t.add_column("k", style="accent", no_wrap=True)
        _t.add_column("v")
        for k, v in rows:
            _t.add_row(str(k),
                       str(v) if v not in (None, "") else "[muted]-[/muted]")
        console.print(_t)
    else:
        for k, v in rows:
            print("  " + str(k) + ": " + str(v))


# ============================================================
# CONFIG
# ============================================================

def load_cfg():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_cfg(cfg):
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        return True
    except Exception:
        return False


def has_key(cfg, name):
    return bool((cfg or {}).get(name))


# ============================================================
# HISTORY
# ============================================================

def hist_record(kind, target, summary=None):
    try:
        d = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
    except Exception:
        d = {"entries": []}
    h = hashlib.sha1((kind + ":" + target).encode()).hexdigest()[:12]
    e = {"id": h, "kind": kind, "target": target,
         "at": datetime.now().isoformat(timespec="seconds"),
         "summary": summary or {}}
    d["entries"] = [x for x in d.get("entries", []) if x.get("id") != h]
    d["entries"].append(e)
    d["entries"] = d["entries"][-500:]
    try:
        HISTORY_PATH.write_text(
            json.dumps(d, ensure_ascii=False, indent=2),
            encoding="utf-8")
    except Exception:
        pass


def hist_all():
    try:
        return json.loads(HISTORY_PATH.read_text(encoding="utf-8")).get("entries", [])
    except Exception:
        return []


def hist_search(q):
    q = (q or "").lower().strip()
    if not q:
        return []
    return [e for e in hist_all()
            if q in e.get("target", "").lower()
            or q in e.get("kind", "").lower()]


def hist_clear():
    try:
        HISTORY_PATH.write_text('{"entries": []}', encoding="utf-8")
        return True, "cleared"
    except Exception as e:
        return False, str(e)


# ============================================================
# VALIDATORS
# ============================================================

def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False


def is_domain(s):
    return bool(re.match(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$", s or "", re.I))


def is_email(s):
    return bool(re.match(
        r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", s or ""))


def is_onion_email(s):
    return bool(re.match(
        r"^[A-Za-z0-9._%+\-]+@[a-z2-7]{16,56}\.onion$", s or ""))


def is_phone(s):
    if not re.match(r"^\+?[\d\s\-()]{7,20}$", s or ""):
        return False
    return 7 <= len(re.sub(r"\D", "", s)) <= 15


def classify(t):
    t = (t or "").strip()
    if is_ip(t):
        return "ip"
    if is_email(t) or is_onion_email(t):
        return "email"
    if t.startswith(("http://", "https://")):
        return "url"
    if is_domain(t):
        return "domain"
    if is_phone(t):
        return "phone"
    return "unknown"


# ============================================================
# TIME / IO HELPERS
# ============================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def ensure_dir(p):
    try:
        Path(p).mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def safe_filename(s):
    return re.sub(r"[^a-zA-Z0-9._\-]", "_", s or "unknown")[:80]


# # ASTRYM profile patch
PROFILE = {
    "name": "normal",
    "rl_sleep": 0.4,
    "http_timeout": 10,
    "dns_timeout": 3.0,
    "workers": 40,
    "sub_workers": 40,
    "probe_workers": 20,
}

_PROFILES = {
    "stealth": {
        "name": "stealth",
        "rl_sleep": 3.0,
        "http_timeout": 30,
        "dns_timeout": 8.0,
        "workers": 8,
        "sub_workers": 10,
        "probe_workers": 5,
    },
    "normal": dict(PROFILE),
    "aggressive": {
        "name": "aggressive",
        "rl_sleep": 0.05,
        "http_timeout": 5,
        "dns_timeout": 2.0,
        "workers": 150,
        "sub_workers": 200,
        "probe_workers": 60,
    },
}


def set_profile(name):
    global PROFILE
    name = (name or "normal").lower()
    if name not in _PROFILES:
        name = "normal"
    PROFILE = dict(_PROFILES[name])
    return PROFILE


def get_profile():
    return dict(PROFILE)


def _rl_sleep():
    time.sleep(PROFILE.get("rl_sleep", 0.4))


# ============================================================
# DNS HELPERS
# ============================================================

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]


# ============================================================
# ASTRYM 9.1.2 — safe DNS resolver (fixes /etc/resolv.conf issues)
# ============================================================

_DNS_RESOLVER = None
_DNS_NAMESERVERS_USED = None


def _init_resolver():
    """Создаёт DNS resolver с fallback на явные nameservers.

    Проблема: в Termux/Docker/PyDroid нет /etc/resolv.conf, из-за чего
    dnspython падает с NoResolverConfiguration.
    Решение: явно указываем 8.8.8.8 / 1.1.1.1 / 9.9.9.9.
    """
    global _DNS_RESOLVER, _DNS_NAMESERVERS_USED
    if _DNS_RESOLVER is not None:
        return _DNS_RESOLVER
    if not HAS_DNS:
        return None

    candidates = [
        ["8.8.8.8", "8.8.4.4"],
        ["1.1.1.1", "1.0.0.1"],
        ["9.9.9.9"],
        ["208.67.222.222"],
    ]

    # 1) пробуем системный resolver (если resolv.conf есть)
    try:
        r = dns.resolver.Resolver(configure=True)
        if r.nameservers:
            try:
                r.resolve("example.com", "A", lifetime=3)
                _DNS_RESOLVER = r
                _DNS_NAMESERVERS_USED = list(r.nameservers)
                return r
            except Exception:
                pass
    except Exception:
        pass

    # 2) явные nameservers
    for ns_list in candidates:
        try:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = ns_list
            r.timeout = 5
            r.lifetime = 5
            try:
                r.resolve("example.com", "A", lifetime=3)
                _DNS_RESOLVER = r
                _DNS_NAMESERVERS_USED = ns_list
                return r
            except Exception:
                continue
        except Exception:
            continue

    return None


def dns_health():
    """Возвращает инфо о текущем resolver (для selfcheck)."""
    r = _init_resolver()
    return {
        "available": r is not None,
        "nameservers": _DNS_NAMESERVERS_USED or [],
    }


def resolve(domain, rt, timeout=3.0):
    if not HAS_DNS:
        return []
    resolver = _init_resolver()
    if resolver is None:
        return []
    try:
        ans = resolver.resolve(domain, rt, lifetime=timeout,
                                raise_on_no_answer=False)
        return [r.to_text() for r in ans] if ans else []
    except Exception:
        return []


def resolve_all(domain):
    res = {}
    with ThreadPoolExecutor(max_workers=len(RECORD_TYPES)) as ex:
        fu = {ex.submit(resolve, domain, rt): rt for rt in RECORD_TYPES}
        for f in as_completed(fu):
            rt = fu[f]
            try:
                res[rt] = f.result()
            except Exception:
                res[rt] = []
    return res


def resolve_detailed(domain, rt, timeout=3.0):
    """DNS resolve с явной ошибкой.

    # ASTRYM two-bugs fix
    Использует _init_resolver() с fallback на 8.8.8.8 / 1.1.1.1 / 9.9.9.9,
    чтобы работать в Termux/Docker/PyDroid без /etc/resolv.conf.
    """
    if not HAS_DNS:
        return {"records": [], "error": "dnspython not installed"}

    resolver = _init_resolver()
    if resolver is None:
        return {"records": [],
                "error": "no DNS resolver available (all fallbacks failed)"}

    try:
        ans = resolver.resolve(domain, rt, lifetime=timeout,
                               raise_on_no_answer=False)
        return {
            "records": [r.to_text() for r in ans] if ans else [],
            "error": None,
        }
    except dns.resolver.NXDOMAIN:
        return {"records": [], "error": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"records": [], "error": "no answer"}
    except dns.resolver.NoNameservers:
        return {"records": [], "error": "no nameservers"}
    except dns.resolver.LifetimeTimeout:
        return {"records": [], "error": "timeout"}
    except dns.exception.Timeout:
        return {"records": [], "error": "timeout"}
    except Exception as e:
        return {"records": [], "error": type(e).__name__ + ": " + str(e)[:80]}


def resolve_all_detailed(domain):
    """Параллельный резолв всех типов с ошибками.

    Returns:
        {"records": {rt: [str]}, "errors": {rt: str}}
    """
    records = {}
    errors = {}
    with ThreadPoolExecutor(max_workers=len(RECORD_TYPES)) as ex:
        fu = {ex.submit(resolve_detailed, domain, rt): rt
              for rt in RECORD_TYPES}
        for f in as_completed(fu):
            rt = fu[f]
            try:
                r = f.result()
                records[rt] = r["records"]
                if r["error"]:
                    errors[rt] = r["error"]
            except Exception as e:
                records[rt] = []
                errors[rt] = type(e).__name__ + ": " + str(e)[:80]
    return {"records": records, "errors": errors}


def _mx_parse(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(\d+)\s+([A-Za-z0-9._\-]+)\.?$", line)
        if m:
            out.append((int(m.group(1)), m.group(2).lower().rstrip(".")))
            continue
        m = re.search(r"mail exchanger\s*=\s*(\d+)\s+([A-Za-z0-9._\-]+)",
                      line, re.I)
        if m:
            out.append((int(m.group(1)), m.group(2).lower().rstrip(".")))
            continue
        m = re.search(r"handled by\s+(\d+)\s+([A-Za-z0-9._\-]+)", line, re.I)
        if m:
            out.append((int(m.group(1)), m.group(2).lower().rstrip(".")))
    seen, result = set(), []
    for p, h in out:
        if h in seen:
            continue
        seen.add(h)
        result.append((p, h))
    result.sort()
    return result


def resolve_mx(domain):
    if not domain:
        return []
    if HAS_DNS:
        try:
            resolver = _init_resolver()
            if resolver is not None:
                ans = resolver.resolve(domain, "MX", lifetime=5)
                out = [(r.preference, str(r.exchange).rstrip(".").lower())
                       for r in ans]
                out.sort()
                if out:
                    return out
        except Exception:
            pass
    for cmd in (["nslookup", "-type=MX", domain],
                ["host", "-t", "MX", domain],
                ["dig", "+short", "MX", domain]):
        try:
            out = subprocess.check_output(cmd, timeout=8,
                                          stderr=subprocess.DEVNULL)
            mx = _mx_parse(out.decode("utf-8", errors="replace"))
            if mx:
                return mx
        except Exception:
            continue
    return []


# ============================================================
# WHOIS
# ============================================================

TLD_WHOIS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org", "io": "whois.nic.io", "co": "whois.nic.co",
    "ru": "whois.tcinet.ru", "su": "whois.tcinet.ru", "de": "whois.denic.de",
    "uk": "whois.nic.uk", "fr": "whois.nic.fr", "it": "whois.nic.it",
    "xyz": "whois.nic.xyz", "info": "whois.afilias.net", "me": "whois.nic.me",
    "tv": "whois.nic.tv", "cc": "whois.nic.cc", "app": "whois.nic.google",
    "dev": "whois.nic.google", "ai": "whois.nic.ai", "sh": "whois.nic.sh",
    "us": "whois.nic.us", "ca": "whois.cira.ca", "au": "whois.auda.org.au",
    "jp": "whois.jprs.jp", "cn": "whois.cnnic.cn", "in": "whois.registry.in",
    "br": "whois.registro.br",
}


def whois_query(server, query, timeout=10):
    try:
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode())
            data = b""
            while True:
                ch = s.recv(4096)
                if not ch:
                    break
                data += ch
                if len(data) > 500000:
                    break
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        return "__error__: " + str(e)


def whois_domain(domain):
    tld = domain.rsplit(".", 1)[-1].lower()
    server = TLD_WHOIS.get(tld)
    if not server:
        iana = whois_query("whois.iana.org", tld)
        m = re.search(r"^\s*whois:\s*(\S+)", iana, re.MULTILINE)
        server = m.group(1) if m else None
        if not server:
            return iana
    return whois_query(server, domain)


def whois_ip(ip):
    resp = whois_query("whois.arin.net", "n + " + ip)
    if not resp or resp.startswith("__error__"):
        return ""
    m = re.search(r"ReferralServer:\s*whois://([^\s/]+)", resp)
    if m:
        ref = whois_query(m.group(1).split(":")[0], ip)
        if ref and not ref.startswith("__error__"):
            return ref
    return resp


def parse_whois(raw):
    out = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k and v and k not in out:
            out[k] = v
    return out


# ============================================================
# NETWORK HELPERS
# ============================================================

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


DNSBL = [
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("Barracuda", "b.barracudacentral.org"),
    ("SORBS", "dnsbl.sorbs.net"),
    ("UCEPROTECT", "dnsbl-1.uceprotect.net"),
    ("CBL", "cbl.abuseat.org"),
    ("NiX Spam", "ix.dnsbl.manitu.net"),
    ("PSBL", "psbl.surriel.com"),
    ("Spamhaus PBL", "pbl.spamhaus.org"),
    ("Spamhaus SBL", "sbl.spamhaus.org"),
    ("Spamhaus XBL", "xbl.spamhaus.org"),
]


def check_dnsbl(ip):
    try:
        rev = ".".join(reversed(ip.split(".")))
    except Exception:
        return []

    def ck(item):
        name, zone = item
        try:
            socket.gethostbyname(rev + "." + zone)
            return {"zone": name, "status": "listed"}
        except socket.gaierror:
            return {"zone": name, "status": "clean"}
        except Exception:
            return {"zone": name, "status": "unknown"}

    with ThreadPoolExecutor(max_workers=len(DNSBL)) as ex:
        return list(ex.map(ck, DNSBL))


# ============================================================
# GEOIP (local MaxMind + ip-api.com fallback)
# ============================================================

_GEOIP_READER = None


def _geoip_open():
    global _GEOIP_READER
    if _GEOIP_READER is not None:
        return _GEOIP_READER
    if not HAS_GEOIP2:
        return None
    mmdb = GEOIP_DIR / "GeoLite2-City.mmdb"
    if not mmdb.exists():
        return None
    try:
        _GEOIP_READER = geoip2.database.Reader(str(mmdb))
        return _GEOIP_READER
    except Exception:
        return None


def ip_geo(ip):
    r = _geoip_open()
    if r:
        try:
            d = r.city(ip)
            return {
                "country": d.country.name,
                "countryCode": d.country.iso_code,
                "regionName": (d.subdivisions.most_specific.name
                               if d.subdivisions else None),
                "city": d.city.name,
                "lat": d.location.latitude,
                "lon": d.location.longitude,
                "timezone": d.location.time_zone,
                "isp": None, "org": None, "as": None,
                "source": "local-mmdb",
            }
        except Exception:
            pass
    if not HAS_REQUESTS:
        return {"error": "no requests"}
    try:
        r2 = requests.get(
            "http://ip-api.com/json/" + ip,
            params={"fields": "status,message,country,countryCode,regionName,"
                    "city,lat,lon,timezone,isp,org,as,reverse,query"},
            timeout=8)
        d = r2.json()
        if d.get("status") == "success":
            d["source"] = "ip-api.com"
            return d
        return {"error": d.get("message", "?")}
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# BANNER + GRADIENT
# ============================================================

BANNER = r"""
 █████╗ ███████╗████████╗██████╗ ██╗   ██╗███╗   ███╗
██╔══██╗██╔════╝╚══██╔══╝██╔══██╗╚██╗ ██╔╝████╗ ████║
███████║███████╗   ██║   ██████╔╝ ╚████╔╝ ██╔████╔██║
██╔══██║╚════██║   ██║   ██╔══██╗  ╚██╔╝  ██║╚██╔╝██║
██║  ██║███████║   ██║   ██║  ██║   ██║   ██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝
"""

TAGLINE = ("OSINT utility  ·  ip · domain · dns · sub · email · "
           "check · ssl · web · darkweb")


def _lerp(a, b, t):
    return tuple(int(round(x + (y - x) * t)) for x, y in zip(a, b))


def _color_at(pos, c1, c2, c3):
    pos = max(0.0, min(1.0, pos))
    if pos <= 0.5:
        return _lerp(c1, c2, pos * 2.0)
    return _lerp(c2, c3, (pos - 0.5) * 2.0)


def gradient_text(text, c1=(168, 85, 247), c2=(255, 255, 255),
                  c3=(168, 85, 247), slant=1.8, bold=True):
    if not HAS_RICH:
        return text
    lines = text.split("\n")
    max_w = max((len(l) for l in lines), default=1)
    total = max_w + len(lines) * abs(slant)
    if total <= 0:
        total = 1
    t = Text()
    for r, line in enumerate(lines):
        if r > 0:
            t.append("\n")
        for c, ch in enumerate(line):
            if ch in (" ", "\t"):
                t.append(ch)
                continue
            pos = (r * slant + c) / total
            rr, gg, bb = _color_at(pos, c1, c2, c3)
            style = "#%02x%02x%02x" % (rr, gg, bb)
            if bold:
                style = "bold " + style
            t.append(ch, style=style)
    return t


def print_banner():
    if HAS_RICH:
        console.print(gradient_text(BANNER))
        tag = gradient_text(TAGLINE,
                            c1=(130, 90, 200),
                            c2=(215, 215, 215),
                            c3=(130, 90, 200),
                            slant=0.4, bold=False)
        console.print(Align.center(tag))
    else:
        sys.stdout.write(BANNER + "\n   " + TAGLINE + "\n")


# ============================================================
# FLAGS PARSER
# ============================================================

KNOWN_CMDS = (
    "ip", "domain", "dns", "sub", "email", "check", "ssl", "scan",
    "web", "darkweb", "takeover", "leak", "origin", "whois-history",
    "phone", "watch", "batch",
    "related", "correlate", "graph",
    "community", "tree", "gexf",
    "username", "dork",
    "clear-history", "clear-log",
    "clear-watches", "clear-results",
    "asn", "cname",
    "ahmia",
    "timeline",
    "consensus",
    "domain-consensus",
    "stix",)


NO_TARGET_OK = {
    "community", "gexf", "graph", "related", "correlate",
    "clear-history", "clear-log", "clear-watches", "clear-results",
}


def parse_cli_line(line):
    parts = line.split()
    if not parts:
        return None
    cmd = parts[0].lower()
    if cmd not in KNOWN_CMDS:
        return None
    targets = []
    fmt = "console"
    extras = False
    sec = False
    workers = 40
    profile = "normal"
    since_days = None
    port = 443
    pages = 3
    depth = 1
    wordlist = None
    no_probe = False
    no_permute = False
    i = 1
    while i < len(parts):
        a = parts[i]
        if a in ("-f", "--format") and i + 1 < len(parts):
            i += 1
            fmt = parts[i]
        elif a in ("-x", "--extras", "--extended"):
            extras = True
        elif a == "--since" and i + 1 < len(parts):
            i += 1
            try: since_days = int(parts[i])
            except Exception: pass
        elif a in ("--stealth", "--slow", "--quiet-net"):
            profile = "stealth"
            workers = 8
        elif a in ("--aggressive", "--fast", "--max"):
            profile = "aggressive"
            workers = 150
        elif a in ("--security", "-s"):
            sec = True
        elif a in ("-w", "--workers") and i + 1 < len(parts):
            i += 1
            try:
                workers = int(parts[i])
            except Exception:
                pass
        elif a == "--no-probe":
            no_probe = True
        elif a == "--no-permute":
            no_permute = True
        elif a in ("-W", "--wordlist") and i + 1 < len(parts):
            i += 1
            wordlist = parts[i]
        elif a == "--port" and i + 1 < len(parts):
            i += 1
            try:
                port = int(parts[i])
            except Exception:
                pass
        elif a == "--pages" and i + 1 < len(parts):
            i += 1
            try:
                pages = int(parts[i])
            except Exception:
                pass
        elif a == "--depth" and i + 1 < len(parts):
            i += 1
            try:
                depth = int(parts[i])
            except Exception:
                pass
        elif not a.startswith("-"):
            targets.append(a)
        i += 1
    # # ASTRYM parse_cli no-target fix
    {"community", "graph", "related", "correlate", "gexf", "clear-history", "clear-log", "clear-watches", "clear-results",}
    if not targets and cmd not in {"community", "gexf", "graph", "related", "correlate", "clear-history", "clear-log", "clear-watches", "clear-results"}:
        return None
    return {
        "command": cmd, "targets": targets, "format": fmt,
        "extras": extras, "security": sec, "workers": workers,
        "port": port, "pages": pages, "depth": depth,
        "wordlist": wordlist,
        "no_probe": no_probe,
        "profile": profile,
        "since_days": since_days,
        "no_permute": no_permute,
    }


# === ASTRYM clear commands (appended) ===
KNOWN_CMDS = KNOWN_CMDS + (
    "clear-history",
    "clear-log",
    "clear-watches",
    "clear-results",
)
# === end ASTRYM clear commands ===

