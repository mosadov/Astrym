#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Ahmia 9.7.0 — search .onion indexes via Ahmia (clearweb)

AHMIA_VERSION = "9.7.0"

import re
import html as _html
from astrym_core import (HAS_REQUESTS, now_iso, hist_record,
                          c_ok, c_warn, c_err, c_info, c_muted)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
    "Accept-Language": "en-US,en;q=0.9",
}

AHMIA_SEARCH = "https://ahmia.fi/search/"
AHMIA_BANNED = "https://ahmia.fi/blacklist/banned/"


def _strip_html(s):
    s = re.sub(r"<[^>]+>", "", s or "")
    s = _html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def ahmia_search(query, timeout=20):
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    if not query or len(query) < 2:
        return {"error": "query too short"}
    try:
        r = requests.get(AHMIA_SEARCH, params={"q": query},
                         headers=HEADERS, timeout=timeout)
    except Exception as e:
        return {"error": "network: " + str(e)[:120]}
    if r.status_code != 200:
        return {"error": "HTTP " + str(r.status_code)}
    text = r.text or ""
    blocks = re.findall(
        r'<li[^>]*class="result[^"]*"[^>]*>(.*?)</li>',
        text, re.S | re.I)
    results = []
    for b in blocks:
        m_url = re.search(r'href="(http[^"]+)"', b)
        m_title = re.search(r"<h4[^>]*>(.*?)</h4>", b, re.S | re.I)
        m_desc = re.search(r"<p[^>]*>(.*?)</p>", b, re.S | re.I)
        m_onion = re.search(r"([a-z2-7]{16,56}\.onion)", b)
        url = m_url.group(1) if m_url else ""
        results.append({
            "title": _strip_html(m_title.group(1)) if m_title else "",
            "url": url,
            "description": _strip_html(m_desc.group(1)) if m_desc else "",
            "onion": m_onion.group(1) if m_onion else "",
        })
    m_total = re.search(r"([\d,]+)\s+results?", text, re.I)
    total = int(m_total.group(1).replace(",", "")) if m_total else len(results)
    return {
        "source": "ahmia",
        "query": query,
        "total": total,
        "results": results[:50],
    }


def ahmia_banned(timeout=20):
    if not HAS_REQUESTS:
        return {"error": "requests not installed"}
    try:
        r = requests.get(AHMIA_BANNED, headers=HEADERS, timeout=timeout)
        if r.status_code == 200:
            onions = re.findall(r"([a-z2-7]{16,56}\.onion)", r.text)
            return {"count": len(set(onions)),
                    "onions": sorted(set(onions))[:500]}
    except Exception as e:
        return {"error": str(e)[:120]}
    return {"count": 0, "onions": []}


def run_ahmia(target, extras=False):
    query = (target or "").strip()
    if query.lower() in ("--banned", "banned", "list"):
        d = ahmia_banned()
        d["meta"] = {"type": "ahmia", "target": "banned",
                     "generated_at": now_iso(),
                     "tool": "ASTRYM " + AHMIA_VERSION}
        return d
    if not query:
        c_err("usage: ahmia <query>  |  ahmia --banned")
        return None
    d = ahmia_search(query)
    if d.get("error"):
        c_err(d["error"])
        return None
    d["meta"] = {"type": "ahmia", "target": query,
                 "generated_at": now_iso(),
                 "tool": "ASTRYM " + AHMIA_VERSION}
    hist_record("ahmia", query, {"total": d.get("total", 0)})
    return d


def render_ahmia(d):
    from astrym_core import header, section, kv
    if d.get("error"):
        c_err(d["error"]); return
    t = d.get("meta", {}).get("target", "?")
    if t == "banned":
        header("Ahmia banned .onion", str(d.get("count", 0)))
        for o in d.get("onions", [])[:100]:
            c_muted("  " + o)
        return
    header("Ahmia search", t)
    kv([("query", d.get("query")),
        ("total", d.get("total")),
        ("shown", len(d.get("results", [])))])
    for i, r in enumerate(d.get("results", [])[:40], 1):
        section("#" + str(i) + "  " + (r.get("title") or r.get("onion") or "?")[:70])
        if r.get("onion"):
            c_ok("  onion: " + r["onion"])
        if r.get("url"):
            c_muted("  url:   " + r["url"][:120])
        if r.get("description"):
            c_muted("  desc:  " + r["description"][:200])
