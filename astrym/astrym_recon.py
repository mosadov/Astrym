#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ASTRYM Recon — username search + Google dorks."""

RECON_VERSION = "1.0.0"

import re
from urllib.parse import quote

from astrym_core import (HAS_REQUESTS, now_iso, hist_record,
                          c_ok, c_warn, c_err, c_info, c_muted)

try:
    import requests
except ImportError:
    requests = None


USERNAME_SITES = [
    ("GitHub",     "https://github.com/{}",                "Not Found"),
    ("GitLab",     "https://gitlab.com/{}",                "404"),
    ("Reddit",     "https://www.reddit.com/user/{}",       "page not found"),
    ("Telegram",   "https://t.me/{}",                      "tgme_page_icon"),
    ("Twitter/X",  "https://x.com/{}",                     "This account doesn"),
    ("Instagram",  "https://www.instagram.com/{}/",        "Sorry, this page"),
    ("TikTok",     "https://www.tiktok.com/@{}",           "Couldn"),
    ("VK",         "https://vk.com/{}",                    "not found"),
    ("OK.ru",      "https://ok.ru/{}",                     "not found"),
    ("Habr",       "https://habr.com/ru/users/{}/",        "Страница не найдена"),
    ("Pikabu",     "https://pikabu.ru/@{}",                "не найден"),
    ("Medium",     "https://medium.com/@{}",               "404"),
    ("Dev.to",     "https://dev.to/{}",                    "404"),
    ("StackOverflow","https://stackoverflow.com/users/{}", "Page not found"),
    ("Pinterest",  "https://www.pinterest.com/{}/",        "Sorry! We couldn"),
    ("Twitch",     "https://www.twitch.tv/{}",             "Sorry. Unless"),
    ("YouTube",    "https://www.youtube.com/@{}",          "does not exist"),
    ("Steam",      "https://steamcommunity.com/id/{}",     "profile could not be found"),
    ("SoundCloud", "https://soundcloud.com/{}",            "can't find that user"),
    ("Spotify",    "https://open.spotify.com/user/{}",     "404"),
    ("Patreon",    "https://www.patreon.com/{}",           "404"),
    ("Mastodon",   "https://mastodon.social/@{}",          "not found"),
    ("Bluesky",    "https://bsky.app/profile/{}",          "not found"),
    ("Keybase",    "https://keybase.io/{}",                "not found"),
    ("Replit",     "https://replit.com/@{}",               "not found"),
    ("Kaggle",     "https://www.kaggle.com/{}",            "404"),
    ("Codeberg",   "https://codeberg.org/{}",              "Page Not Found"),
    ("HackerNews", "https://news.ycombinator.com/user?id={}", "No such user"),
]


def _check_username_site(session, name, template, marker, username, timeout=8):
    url = template.format(username)
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent":
                                 "Mozilla/5.0 (compatible; ASTRYM)"})
        if r.status_code == 404:
            return {"site": name, "url": url, "status": "not_found", "code": 404}
        if r.status_code != 200:
            return {"site": name, "url": url, "status": "unknown", "code": r.status_code}
        body = (r.text or "")[:60000].lower()
        if marker and marker.lower() in body:
            return {"site": name, "url": url, "status": "not_found", "code": r.status_code}
        return {"site": name, "url": url, "status": "found", "code": r.status_code}
    except Exception as e:
        return {"site": name, "url": url, "status": "error", "error": str(e)[:100]}


def collect_username(username):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    u = username.strip().lstrip("@").strip("/")
    if not u or len(u) < 2:
        return {"error": "username too short"}

    session = requests.Session()
    found, missing, errors = [], [], []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_check_username_site, session, name, tmpl,
                              marker, u): name
                   for name, tmpl, marker in USERNAME_SITES}
        for f in as_completed(futures):
            try:
                r = f.result()
            except Exception as e:
                errors.append({"site": futures[f], "error": str(e)[:80]})
                continue
            if r["status"] == "found":
                found.append(r)
            elif r["status"] == "not_found":
                missing.append(r)
            else:
                errors.append(r)

    found.sort(key=lambda x: x["site"])
    return {
        "username": u,
        "found": found,
        "not_found": len(missing),
        "errors": errors,
        "total_checked": len(USERNAME_SITES),
    }


def run_username(target, extras=False):
    d = collect_username(target)
    if d.get("error"):
        c_err(d["error"])
        return None
    d["meta"] = {"type": "username", "target": target,
                 "generated_at": now_iso(),
                 "tool": "ASTRYM " + RECON_VERSION}
    hist_record("username", target, {"found": len(d.get("found", []))})
    return d


def render_username(d):
    from astrym_core import header, section, kv
    if d.get("error"):
        c_err(d["error"]); return
    header("Username Search", d["username"])
    found = d.get("found", [])
    kv([("checked", d.get("total_checked")),
        ("found", len(found)),
        ("not_found", d.get("not_found")),
        ("errors", len(d.get("errors", [])))])
    if found:
        section("Найдено на " + str(len(found)) + " платформах")
        for x in found:
            c_ok(x["site"].ljust(16) + " " + x["url"])
    else:
        c_muted("  нигде не найдено")


DORK_TEMPLATES = [
    ("general", '"{t}"'),
    ("general", '"{t}" -site:{t}'),
    ("files",   '"{t}" filetype:pdf'),
    ("files",   '"{t}" filetype:doc OR filetype:docx'),
    ("files",   '"{t}" filetype:xls OR filetype:xlsx'),
    ("files",   '"{t}" filetype:sql'),
    ("files",   '"{t}" filetype:env OR filetype:ini'),
    ("files",   '"{t}" ext:log'),
    ("files",   '"{t}" ext:bak'),
    ("files",   '"{t}" ext:conf'),
    ("backup",  '"{t}" intitle:index.of'),
    ("backup",  '"{t}" inurl:backup'),
    ("backup",  '"{t}" inurl:.git'),
    ("admin",   'site:{t} inurl:admin'),
    ("admin",   'site:{t} inurl:login'),
    ("admin",   'site:{t} intitle:admin'),
    ("admin",   'site:{t} intitle:dashboard'),
    ("admin",   'site:{t} inurl:phpmyadmin'),
    ("admin",   'site:{t} inurl:wp-admin'),
    ("admin",   'site:{t} inurl:cpanel'),
    ("leak",    '"{t}" "BEGIN RSA PRIVATE KEY"'),
    ("leak",    '"{t}" "BEGIN OPENSSH PRIVATE KEY"'),
    ("leak",    '"{t}" api_key'),
    ("leak",    '"{t}" apikey'),
    ("leak",    '"{t}" password'),
    ("leak",    '"{t}" secret'),
    ("leak",    '"{t}" token'),
    ("leak",    '"{t}" DB_PASSWORD'),
    ("leak",    '"{t}" AWS_ACCESS_KEY'),
    ("leak",    '"{t}" "AKIA"'),
    ("leak",    '"{t}" "-----BEGIN CERTIFICATE-----"'),
    ("emails",  '"@{t}" email'),
    ("emails",  '"@{t}" "@gmail.com"'),
    ("emails",  '"@{t}" "@outlook.com"'),
    ("emails",  '"@{t}" contact'),
    ("dirs",    'site:{t} inurl:api'),
    ("dirs",    'site:{t} inurl:swagger'),
    ("dirs",    'site:{t} inurl:graphql'),
    ("dirs",    'site:{t} inurl:actuator'),
    ("dirs",    'site:{t} inurl:console'),
    ("dirs",    'site:{t} inurl:debug'),
    ("dirs",    'site:{t} inurl:test'),
    ("dirs",    'site:{t} inurl:dev'),
    ("dirs",    'site:{t} inurl:staging'),
    ("paste",   'site:pastebin.com "{t}"'),
    ("paste",   'site:ghostbin.com "{t}"'),
    ("paste",   'site:rentry.co "{t}"'),
    ("paste",   'site:paste.ee "{t}"'),
    ("paste",   'site:justpaste.it "{t}"'),
    ("paste",   'site:telegra.ph "{t}"'),
]


def collect_dork(target):
    t = target.strip().lower()
    if not t:
        return {"error": "empty target"}
    is_domain = bool(re.match(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$", t))
    dorks = []
    for cat, tmpl in DORK_TEMPLATES:
        q = tmpl.format(t=t)
        dorks.append({
            "category": cat,
            "query": q,
            "url": "https://www.google.com/search?q=" + quote(q),
        })
    return {"target": t, "is_domain": is_domain,
            "count": len(dorks), "dorks": dorks}


def run_dork(target, extras=False):
    d = collect_dork(target)
    if d.get("error"):
        c_err(d["error"])
        return None
    d["meta"] = {"type": "dork", "target": target,
                 "generated_at": now_iso(),
                 "tool": "ASTRYM " + RECON_VERSION}
    hist_record("dork", target, {"count": d.get("count", 0)})
    return d


def render_dork(d):
    from astrym_core import header, section, kv
    if d.get("error"):
        c_err(d["error"]); return
    header("Google Dorks", d["target"])
    kv([("category", "domain" if d.get("is_domain") else "string"),
        ("dorks", d.get("count"))])
    by_cat = {}
    for x in d.get("dorks", []):
        by_cat.setdefault(x["category"], []).append(x)
    for cat in sorted(by_cat.keys()):
        section(cat.upper())
        for x in by_cat[cat][:15]:
            c_muted("  " + x["query"][:100])
