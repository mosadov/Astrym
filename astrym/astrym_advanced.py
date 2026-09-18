#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Advanced 8.1.0 — web, takeover, leak, origin, whois-history, darkweb

import re, time, socket, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from astrym_core import (
    now_iso, is_domain, resolve, resolve_all,
    HAS_REQUESTS, HAS_DNS, hist_record,
    c_ok, c_warn, c_err, c_info, c_muted,
)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from astrym_web import (favicon_hash as _fav_hash,
                              fetch_and_extract_analytics as _analytics)
except ImportError:
    _fav_hash = _analytics = None


VERSION = "8.1.0"

# ============================================================
# WEB FINGERPRINT (PARALLEL - FIX #1)
# ============================================================

CMS_PATHS = [
    ("/wp-login.php", "WordPress"),
    ("/wp-admin/", "WordPress"),
    ("/administrator/", "Joomla"),
    ("/user/login", "Drupal"),
    ("/admin/login", "admin panel"),
    ("/login", "login"),
    ("/.git/config", "git leak"),
    ("/.env", "env leak"),
    ("/phpmyadmin/", "phpMyAdmin"),
    ("/server-status", "apache status"),
    ("/swagger.json", "swagger"),
    ("/api/", "api endpoint"),
]

WEB_SIGS = {
    "server": [("nginx", "Nginx"), ("apache", "Apache"), ("iis", "IIS"),
               ("cloudflare", "Cloudflare"), ("litespeed", "LiteSpeed"),
               ("gunicorn", "Gunicorn"), ("caddy", "Caddy")],
    "cms": [("wordpress", "WordPress"), ("joomla", "Joomla"),
            ("drupal", "Drupal"), ("magento", "Magento"), ("ghost", "Ghost"),
            ("shopify", "Shopify"), ("wix", "Wix"),
            ("squarespace", "Squarespace"), ("hugo", "Hugo")],
}

# ============================================================
# ASTRYM 9.1.3 — wildcard 200 detection
# ============================================================

def _random_path():
    import random, string as _s
    return "/" + "".join(random.choice(_s.ascii_lowercase + _s.digits)
                          for _ in range(24))


def _probe_wildcard(base, timeout=5):
    """Запрос на заведомо несуществующий путь.

    Returns:
        {
            "wildcard": bool,       # сервер отдаёт 200 на всё
            "status": int,          # код ответа
            "content_len": int,     # длина тела
            "content_hash": str,    # хэш первых 2KB
            "redirect_to": str,     # куда редиректит (если есть)
        }
    """
    import hashlib as _h
    rand_path = _random_path()
    try:
        r = requests.get(base + rand_path, timeout=timeout,
                         headers={"User-Agent": "ASTRYM/" + VERSION},
                         allow_redirects=False)
        body = (r.text or "")[:2048]
        return {
            "wildcard": r.status_code == 200,
            "status": r.status_code,
            "content_len": len(r.text or ""),
            "content_hash": _h.sha1(body.encode("utf-8", errors="replace")).hexdigest()[:16],
            "redirect_to": r.headers.get("Location") if r.status_code in (301, 302, 307, 308) else None,
            "path_probed": rand_path,
        }
    except Exception:
        return {"wildcard": False, "status": None}


def _is_wildcard_false_positive(candidate, wildcard_info, baseline_body):
    """Проверяет, является ли найденный путь ложным срабатыванием wildcard.

    Args:
        candidate: {"path": ..., "status": ..., "what": ..., "content": ...}
        wildcard_info: результат _probe_wildcard
        baseline_body: содержимое случайного пути для сравнения

    Returns:
        (is_false, reason)
    """
    # если сервер не wildcard — не может быть ложного 200
    if not wildcard_info.get("wildcard"):
        return False, None

    # если у candidate статус не 200 — не наш случай
    if candidate.get("status") != 200:
        return False, None

    body = (candidate.get("content") or "")[:2048]
    import hashlib as _h
    cand_hash = _h.sha1(body.encode("utf-8", errors="replace")).hexdigest()[:16]

    # если хэш совпадает с wildcard-страницей — это точно false positive
    if cand_hash == wildcard_info.get("content_hash"):
        return True, "identical to random-path response (wildcard)"

    # если тело пустое или короче wildcard — тоже подозрительно
    if len(body) < 100:
        return True, "response too short (<100 bytes)"

    return False, None


def _validate_path_content(path, body):
    """Проверяет содержимое ответа на реальную уязвимость.

    Returns:
        (valid: bool, reason: str)
    """
    if not body:
        return False, "empty body"

    low = body[:8192].lower()

    # --- .env ---
    if path == "/.env":
        markers = ["db_password", "db_host", "db_user", "api_key",
                   "secret_key", "app_key", "database_url",
                   "aws_access_key", "aws_secret"]
        hits = [m for m in markers if m in low]
        if hits:
            return True, "ENV markers: " + ",".join(hits[:3])
        return False, "no .env markers"

    # --- .git/config ---
    if "/.git" in path:
        if "[core]" in low and "repositoryformatversion" in low:
            return True, "valid git config"
        return False, "not a git config"

    # --- /wp-admin/ ---
    if "wp-admin" in path or "wp-login" in path:
        markers = ["wordpress", "wp-login", "wp-admin",
                   "user_login", "wp-submit"]
        hits = [m for m in markers if m in low]
        if hits:
            return True, "WordPress markers: " + ",".join(hits[:2])
        return False, "not WordPress"

    # --- /phpmyadmin/ ---
    if "phpmyadmin" in path:
        if "phpmyadmin" in low or "pma_" in low:
            return True, "phpMyAdmin found"
        return False, "not phpMyAdmin"

    # --- /server-status ---
    if "server-status" in path:
        if "apache server status" in low or "server version" in low:
            return True, "Apache status page"
        return False, "not apache status"

    # --- /administrator (Joomla) ---
    if "administrator" in path:
        if "joomla" in low or "mod-login" in low:
            return True, "Joomla admin"
        return False, "not Joomla"

    # --- /swagger.json ---
    if "swagger" in path:
        if '"swagger"' in body[:1000] or '"openapi"' in low[:1000]:
            return True, "OpenAPI spec"
        return False, "not swagger"

    # --- generic: не может быть <200 байт ---
    if len(body) < 200:
        return False, "body too short"

    return True, "no specific validator (assume valid)"


def web_fingerprint(domain):
    out = {
        "domain": domain, "headers": {}, "cms_detected": [],
        "leaks": [], "titles": [], "final_url": None, "status_code": None,
    }
    if not HAS_REQUESTS:
        return out

    base = "https://" + domain
    try:
        r = requests.get(base, timeout=10,
                         headers={"User-Agent": "ASTRYM/" + VERSION},
                         allow_redirects=True)
        out["final_url"] = r.url
        out["status_code"] = r.status_code

        for h in ("Server", "X-Powered-By", "X-Generator",
                  "X-Frame-Options", "Strict-Transport-Security",
                  "Content-Security-Policy", "X-AspNet-Version"):
            v = r.headers.get(h)
            if v:
                out["headers"][h] = v

        body = r.text[:30000]
        tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if tm:
            out["titles"].append(tm.group(1).strip()[:120])

        for gen in re.findall(
                r'<meta[^>]+name=["\']generator["\'][^>]+'
                r'content=["\']([^"\']+)', body, re.I):
            out["cms_detected"].append(gen)

        srv = r.headers.get("Server", "").lower()
        for sig, name in WEB_SIGS["server"]:
            if sig in srv:
                out["cms_detected"].append(name)

        lower = body.lower()
        for sig, name in WEB_SIGS["cms"]:
            if sig in lower:
                out["cms_detected"].append(name)

        base = r.url.rstrip("/")
    except Exception:
        pass

    # PARALLEL path check (FIX #1)
    # --- wildcard 200 detection (FIX 9.1.3) ---
    wildcard_info = _probe_wildcard(base)
    out["wildcard_probe"] = wildcard_info

    # baseline body для сравнения
    baseline_body = ""
    if wildcard_info.get("wildcard"):
        try:
            r0 = requests.get(base + wildcard_info.get("path_probed", "/"),
                              timeout=5, allow_redirects=False)
            baseline_body = (r0.text or "")[:2048]
        except Exception:
            pass

    def check_one(item):
        path, name = item
        try:
            rr = requests.get(base + path, timeout=5,
                              headers={"User-Agent": "ASTRYM/" + VERSION},
                              allow_redirects=False)
            if rr.status_code not in (200, 401, 403):
                return None

            candidate = {
                "path": path,
                "status": rr.status_code,
                "what": name,
                "content": (rr.text or "")[:2048],
            }

            # 1. Проверка на wildcard false positive
            is_false, reason_false = _is_wildcard_false_positive(
                candidate, wildcard_info, baseline_body)
            if is_false:
                candidate["false_positive"] = True
                candidate["reason"] = reason_false
                return candidate  # вернём для лога, но пометим

            # 2. Для 200 — валидация по контенту
            if rr.status_code == 200:
                valid, reason = _validate_path_content(path, rr.text or "")
                if not valid:
                    candidate["false_positive"] = True
                    candidate["reason"] = reason
                    return candidate
                candidate["validated"] = True
                candidate["evidence"] = reason

            # 3. 401/403 — почти всегда реальные (нет смысла в wildcard)
            return candidate
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        all_results = list(ex.map(check_one, CMS_PATHS))

    # фильтруем: false_positive в отдельный список
    for r in all_results:
        if not r:
            continue
        if r.get("false_positive"):
            out.setdefault("false_positives", []).append(r)
        else:
            out["leaks"].append(r)

    out["cms_detected"] = sorted(set(out["cms_detected"]))
    # favicon hash (v9.4)
    if _fav_hash:
        try:
            fh = _fav_hash(base)
            if fh is not None:
                out["favicon_hash"] = fh
        except Exception:
            pass
    # shared analytics (v9.4)
    if _analytics:
        try:
            a = _analytics(base)
            if a:
                out["analytics"] = a
        except Exception:
            pass
    return out

def collect_web(domain):
    d = web_fingerprint(domain)
    d["meta"] = {"type": "web", "target": domain,
                 "generated_at": now_iso(), "tool": "ASTRYM " + VERSION}
    return d

# ============================================================
# SUBDOMAIN TAKEOVER
# ============================================================

TAKEOVER_SIGS = [
    ("GitHub Pages", "github.io",
     ["There isn't a GitHub Pages site here", "For root URLs"]),
    ("Heroku", "herokuapp.com", ["No such app", "heroku | no such app"]),
    ("AWS S3", "s3.amazonaws.com",
     ["NoSuchBucket", "The specified bucket does not exist"]),
    ("AWS S3 (alt)", "amazonaws.com", ["NoSuchBucket"]),
    ("Azure", "azurewebsites.net", ["Error 404 - Web app not found"]),
    ("Azure (cloudapp)", "cloudapp.azure.com", ["404"]),
    ("Shopify", "myshopify.com",
     ["Sorry, this shop is currently unavailable"]),
    ("Tumblr", "tumblr.com",
     ["There's nothing here.", "Whatever you were looking for"]),
    ("WordPress", "wordpress.com", ["Do you want to register"]),
    ("Zendesk", "zendesk.com", ["Help Center Closed"]),
    ("Fastly", "fastly.net", ["Fastly error: unknown domain"]),
    ("Pantheon", "pantheonsite.io", ["The gods are wise"]),
    ("Bitbucket", "bitbucket.io", ["Repository not found"]),
    ("Netlify", "netlify.app", ["Not Found - Request ID"]),
    ("Netlify (alt)", "netlify.com", ["Not Found - Request ID"]),
    ("Surge.sh", "surge.sh", ["project not found"]),
    ("Cargo", "cargocollective.com", ["404 Not Found"]),
    ("Ghost", "ghost.io",
     ["The thing you were looking for is no longer here"]),
    ("Unbounce", "unbouncepages.com",
     ["The requested URL was not found on this server"]),
    ("Vercel", "vercel.app", ["The deployment could not be found"]),
]

def _check_takeover_sub(sub):
    if not HAS_REQUESTS:
        return None
    cname = None
    if HAS_DNS:
        try:
            ans = dns.resolver.resolve(sub, "CNAME", lifetime=4)
            if ans:
                cname = str(ans[0]).rstrip(".")
        except Exception:
            pass
    target = cname or sub
    for svc, sig, fps in TAKEOVER_SIGS:
        if sig not in target:
            continue
        try:
            r = requests.get("http://" + sub, timeout=10,
                             headers={"User-Agent": "ASTRYM/" + VERSION},
                             allow_redirects=True)
            body = r.text[:5000].lower()
            for fp in fps:
                if fp.lower() in body:
                    return {"subdomain": sub, "service": svc,
                            "cname": cname, "matched": fp,
                            "status_code": r.status_code}
        except Exception:
            continue
    return None

def collect_takeover(domain, subs=None):
    if subs is None:
        # fetch CT
        if HAS_REQUESTS:
            try:
                r = requests.get("https://crt.sh/",
                                 params={"q": "%25." + domain, "output": "json"},
                                 timeout=20,
                                 headers={"User-Agent": "ASTRYM/" + VERSION})
                subs = set()
                if r.status_code == 200 and r.text.lstrip().startswith("["):
                    for e in r.json():
                        for n in e.get("name_value", "").split("\n"):
                            n = n.strip().lower()
                            if n.endswith(domain) and "*" not in n:
                                subs.add(n)
                subs = sorted(subs)
            except Exception:
                subs = []
        else:
            subs = []
    hits = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        for r in ex.map(_check_takeover_sub, subs[:150]):
            if r:
                hits.append(r)
    return {
        "meta": {"type": "takeover", "target": domain,
                 "generated_at": now_iso(), "tool": "ASTRYM " + VERSION},
        "domain": domain,
        "checked": len(subs[:150]),
        "vulnerable": hits,
    }

# ============================================================
# LEAK SEARCH
# ============================================================



# ============================================================
# ASTRYM 9.5 — Paste sites dorks
# ============================================================

_PASTE_SITES = [
    "pastebin.com", "ghostbin.co", "controlc.com",
    "rentry.co", "paste.ee", "justpaste.it", "telegra.ph",
    "pastebin.pl", "paste.gg", "hastebin.com", "dpaste.org",
    "paste.opensuse.org", "ideone.com", "pastebin.ai",
]

_PASTE_DORK_PATTERNS = [
    ('"{t}"', 'прямой поиск'),
    ('"{t}" password', 'пароли'),
    ('"{t}" passwd', 'passwd'),
    ('"{t}" api_key', 'API ключи'),
    ('"{t}" apikey', 'apikey'),
    ('"{t}" secret', 'секреты'),
    ('"{t}" token', 'токены'),
    ('"{t}" leaked', 'утечки'),
    ('"{t}" dump', 'дампы'),
    ('"{t}" credentials', 'креды'),
    ('"{t}" "BEGIN RSA PRIVATE KEY"', 'приватные ключи'),
    ('"{t}" "@gmail.com"', 'связь с gmail'),
    ('"{t}" ".env"', '.env файлы'),
    ('"{t}" "DB_PASSWORD"', 'пароли БД'),
    ('"{t}" "AKIA"', 'AWS-ключи'),
]


def _paste_dorks(target):
    """Генерирует dorks для поиска в paste-сайтах."""
    from urllib.parse import quote_plus
    out = []
    for site in _PASTE_SITES:
        for pattern, desc in _PASTE_DORK_PATTERNS:
            q = pattern.format(t=target) + " site:" + site
            out.append({
                "site": site,
                "description": desc,
                "query": q,
                "url": "https://www.google.com/search?q=" + quote_plus(q),
            })
    return out


def _paste_dorks_summary(target):
    """Дополняет leak-результат."""
    return {
        "sites": _PASTE_SITES,
        "dorks": _paste_dorks(target),
        "count": len(_PASTE_SITES) * len(_PASTE_DORK_PATTERNS),
    }

def collect_leak(domain):
    out = {"github": [], "gists": []}
    if not HAS_REQUESTS:
        out["meta"] = {"type": "leak", "target": domain,
                       "generated_at": now_iso(), "tool": "ASTRYM " + VERSION}
        return out

    # GitHub code search
    try:
        r = requests.get("https://api.github.com/search/code",
                         params={"q": domain + " in:file", "per_page": "10"},
                         headers={"Accept": "application/vnd.github+json",
                                  "User-Agent": "ASTRYM/" + VERSION},
                         timeout=15)
        if r.status_code == 200:
            for i in r.json().get("items", []):
                out["github"].append({
                    "repo": i.get("repository", {}).get("full_name"),
                    "path": i.get("path"),
                    "url": i.get("html_url"),
                })
    except Exception:
        pass

    # .env gists
    try:
        r = requests.get("https://api.github.com/search/code",
                         params={"q": domain + " in:file filename:.env",
                                 "per_page": "5"},
                         headers={"Accept": "application/vnd.github+json",
                                  "User-Agent": "ASTRYM/" + VERSION},
                         timeout=15)
        if r.status_code == 200:
            for i in r.json().get("items", []):
                out["gists"].append({
                    "path": i.get("path"),
                    "url": i.get("html_url"),
                })
    except Exception:
        pass

    out["paste_dorks"] = _paste_dorks_summary(domain)
    out["meta"] = {"type": "leak", "target": domain,
                   "generated_at": now_iso(), "tool": "ASTRYM " + VERSION}
    return out

# ============================================================
# ORIGIN IP
# ============================================================

CLOUDFLARE_NETS = [
    "104.16.0.0/13", "172.64.0.0/13", "103.21.244.0/22",
    "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15",
    "131.0.72.0/22",
]

def collect_origin(domain):
    out = {"domain": domain, "candidates": [], "sources": {}}
    cf_ips = set()
    if HAS_DNS:
        try:
            for a in dns.resolver.resolve(domain, "A", lifetime=5):
                cf_ips.add(str(a))
        except Exception:
            pass

    is_cf = False
    for ip in cf_ips:
        try:
            addr = ipaddress.ip_address(ip)
            for net in CLOUDFLARE_NETS:
                if addr in ipaddress.ip_network(net):
                    is_cf = True
                    break
        except Exception:
            pass
    out["is_cloudflare"] = is_cf
    out["current_ips"] = sorted(cf_ips)

    # TXT/SPF
    if HAS_DNS:
        try:
            for a in dns.resolver.resolve(domain, "TXT", lifetime=5):
                txt = str(a)
                ips = re.findall(r'(\d{1,3}(?:\.\d{1,3}){3})', txt)
                for ip in ips:
                    try:
                        addr = ipaddress.ip_address(ip)
                        if addr.is_global and ip not in cf_ips:
                            out.setdefault("sources", {}).setdefault(
                                "txt_spf", []).append(ip)
                            out["candidates"].append(ip)
                    except Exception:
                        continue
        except Exception:
            pass

    # Common subdomains
    if HAS_DNS:
        for s in ("direct", "origin", "backend", "cpanel", "webmail",
                  "mail", "ftp", "vpn", "mailer"):
            try:
                for a in dns.resolver.resolve(s + "." + domain, "A",
                                              lifetime=2):
                    ip = str(a)
                    try:
                        addr = ipaddress.ip_address(ip)
                        if addr.is_global and ip not in cf_ips:
                            out.setdefault("sources", {}).setdefault(
                                "subdomains", {})[s + "." + domain] = ip
                            out["candidates"].append(ip)
                    except Exception:
                        continue
            except Exception:
                continue

    out["candidates"] = sorted(set(out["candidates"]))
    out["meta"] = {"type": "origin", "target": domain,
                   "generated_at": now_iso(), "tool": "ASTRYM " + VERSION}
    return out

# ============================================================
# WHOIS HISTORY
# ============================================================

def collect_whois_history(domain):
    """WHOIS timeline через несколько публичных источников.

    Note: viewdns.info закрыт Cloudflare. Используем:
      - whoisxmlapi free tier (если ключ)
      - crt.sh: даты выдачи сертификатов = история активности домена
      - WhoisXML (без ключа отдаёт только current)
    """
    out = {"domain": domain, "timeline": [], "sources_used": []}
    if not HAS_REQUESTS:
        out["meta"] = {"type": "whois-history", "target": domain,
                       "generated_at": now_iso(), "tool": "ASTRYM " + VERSION}
        return out

    # источник 1: crt.sh timeline
    try:
        r = requests.get("https://crt.sh/",
                         params={"q": domain, "output": "json"},
                         timeout=20)
        if r.status_code == 200 and r.text.lstrip().startswith("["):
            events = {}
            for e in r.json():
                ts = e.get("not_before", "")[:10]
                issuer = (e.get("issuer_name") or "")[:100]
                if ts:
                    events.setdefault(ts, set()).add(issuer)
            for ts in sorted(events.keys()):
                issuers = list(events[ts])[:2]
                out["timeline"].append([ts, "; ".join(issuers)])
            if out["timeline"]:
                out["sources_used"].append("crt.sh")
    except Exception:
        pass

    # источник 2: WHOISXML free (без ключа вернёт ошибку, но попробуем)
    try:
        r = requests.get("https://www.whoisxmlapi.com/whoisserver/WhoisService",
                         params={"domainName": domain, "outputFormat": "JSON"},
                         timeout=10)
        if r.status_code == 200:
            d = r.json()
            whois_rec = (d.get("WhoisRecord") or {})
            created = whois_rec.get("createdDate")
            updated = whois_rec.get("updatedDate")
            expires = whois_rec.get("expiresDate")
            if created:
                out["timeline"].append(["created", created[:19]])
            if updated:
                out["timeline"].append(["updated", updated[:19]])
            if expires:
                out["timeline"].append(["expires", expires[:19]])
            if created or updated:
                out["sources_used"].append("whoisxmlapi")
    except Exception:
        pass

    # источник 3: RDAP (RFC 7483) — заменяет WHOIS
    try:
        r = requests.get("https://rdap.org/domain/" + domain, timeout=10)
        if r.status_code == 200:
            d = r.json()
            for event in d.get("events", []):
                action = event.get("eventAction", "?")
                date = event.get("eventDate", "")
                if date:
                    out["timeline"].append([action, date[:19]])
            if d.get("events"):
                out["sources_used"].append("rdap.org")
    except Exception:
        pass

    out["meta"] = {"type": "whois-history", "target": domain,
                   "generated_at": now_iso(), "tool": "ASTRYM " + VERSION}
    return out

# ============================================================
# DARKWEB (ReDoS-safe, short timeouts - FIX #3)
# ============================================================

DW_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,16}")
DW_PHONE_RE = re.compile(r"\+\d{7,18}")
DW_BTC_RE = re.compile(
    r"\b(?:bc1[a-z0-9]{20,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,40})\b")
DW_ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b")
DW_MAX_CHARS = 500000

def _tor_available():
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=3)
        s.close()
        return True
    except Exception:
        return False

def collect_darkweb(url, max_pages=3, max_depth=1):
    if not HAS_REQUESTS:
        return {"error": "requests not installed",
                "meta": {"type": "darkweb", "target": url,
                         "generated_at": now_iso(),
                         "tool": "ASTRYM " + VERSION}}
    if ".onion" not in url:
        return {"error": "url is not .onion",
                "meta": {"type": "darkweb", "target": url,
                         "generated_at": now_iso(),
                         "tool": "ASTRYM " + VERSION}}
    if not _tor_available():
        return {"error": "Tor not running on 127.0.0.1:9050",
                "hint": "install Tor Browser or start tor service",
                "meta": {"type": "darkweb", "target": url,
                         "generated_at": now_iso(),
                         "tool": "ASTRYM " + VERSION}}

    session = requests.Session()
    session.proxies = {"http": "socks5h://127.0.0.1:9050",
                       "https": "socks5h://127.0.0.1:9050"}
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; ASTRYM)"})

    visited, queue, pages = set(), [(url, 0)], []
    emails, phones, btcs, onions = set(), set(), set(), set()

    while queue and len(pages) < max_pages:
        current, depth = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        try:
            # FIX #3: (connect, read) instead of 30
            r = session.get(current, timeout=(5, 15), allow_redirects=True)
            if r.status_code != 200:
                pages.append({"url": current, "status": r.status_code})
                continue
            text = r.text[:DW_MAX_CHARS]
            emails.update(DW_EMAIL_RE.findall(text))
            phones.update(DW_PHONE_RE.findall(text))
            btcs.update(DW_BTC_RE.findall(text))
            onions.update(DW_ONION_RE.findall(text))
            tm = re.search(r"<title[^>]*>(.*?)</title>", text[:5000],
                            re.I | re.S)
            pages.append({
                "url": current, "status": 200,
                "title": tm.group(1).strip()[:120] if tm else "",
                "size": len(r.text),
            })
            if depth < max_depth:
                for l in re.findall(r'href=["\']([^"\']{4,500})["\']', text):
                    if (l.startswith("http") and ".onion" in l
                            and l not in visited):
                        queue.append((l, depth + 1))
        except Exception as e:
            pages.append({"url": current, "error": str(e)})

    return {
        "meta": {"type": "darkweb", "target": url,
                 "generated_at": now_iso(), "tool": "ASTRYM " + VERSION},
        "start": url,
        "pages_crawled": len(pages),
        "entities": {
            "emails": sorted(emails)[:100],
            "phones": sorted(phones)[:100],
            "bitcoin": sorted(btcs)[:100],
            "onions": sorted(onions)[:100],
        },
        "pages": pages,
    }

# ============================================================
# EXTERNAL LINKS
# ============================================================

def extras_links_web(domain):
    return [
        ("URLVoid", "https://www.urlvoid.com/scan/" + domain),
        ("Sucuri SiteCheck", "https://sitecheck.sucuri.net/results/" + domain),
        ("Wappalyzer", "https://www.wappalyzer.com/lookup/" + domain),
        ("BuiltWith", "https://builtwith.com/" + domain),
        ("SimilarWeb", "https://www.similarweb.com/website/" + domain),
        ("Qualys SSL Labs", "https://www.ssllabs.com/ssltest/analyze.html?d=" + domain),
        ("Hardenize", "https://www.hardenize.com/report/" + domain),
        ("urlscan.io", "https://urlscan.io/domain/" + domain),
        ("SecurityHeaders", "https://securityheaders.com/?q=" + domain),
        ("Mozilla Observatory", "https://observatory.mozilla.org/analyze/" + domain),
    ]

def extras_links_takeover(domain):
    return [
        ("Can I take over XYZ", "https://github.com/EdOverflow/can-i-take-over-xyz"),
        ("HackerOne reports", "https://hackerone.com/hacktivity?querystring=takeover"),
    ]

def extras_links_origin(domain):
    return [
        ("ViewDNS IP History", "https://viewdns.info/iphistory/?domain=" + domain),
        ("Censys", "https://search.censys.io/search?q=" + domain),
        ("CrimeFlare", "https://crimeflare.com/?domain=" + domain),
        ("Cloudflare Detector", "https://cloudflare-detect.com/"),
    ]

# ============================================================
# ENTRY POINTS
# ============================================================

def run_web(target, extras=False):
    t = target.lower().strip()
    if not is_domain(t):
        c_err("not domain: " + target)
        return None
    d = collect_web(t)
    if extras:
        d["extended_links"] = extras_links_web(t)
    hist_record("web", t, {})
    return d

def run_takeover(target, extras=False):
    t = target.lower().strip()
    if not is_domain(t):
        c_err("not domain: " + target)
        return None
    d = collect_takeover(t)
    if extras:
        d["extended_links"] = extras_links_takeover(t)
    hist_record("takeover", t,
                {"vulnerable": len(d.get("vulnerable", []))})
    return d

def run_leak(target, extras=False):
    d = collect_leak(target)
    hist_record("leak", target, {})
    return d

def run_origin(target, extras=False):
    t = target.lower().strip()
    if not is_domain(t):
        c_err("not domain: " + target)
        return None
    d = collect_origin(t)
    if extras:
        d["extended_links"] = extras_links_origin(t)
    hist_record("origin", t, {})
    return d

def run_whois_history(target, extras=False):
    t = target.lower().strip()
    if not is_domain(t):
        c_err("not domain: " + target)
        return None
    d = collect_whois_history(t)
    hist_record("whois-history", t, {})
    return d

def run_darkweb(target, extras=False, max_pages=3, max_depth=1):
    d = collect_darkweb(target, max_pages=max_pages, max_depth=max_depth)
    if d.get("error"):
        c_err(d["error"])
        if d.get("hint"):
            c_info(d["hint"])
        return None
    hist_record("darkweb", target,
                {"pages": d.get("pages_crawled", 0)})
    return d