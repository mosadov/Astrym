#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Graph 9.0.0 — SQLite-based infrastructure graph
# Хранит все сканы в единой базе, позволяет искать связи между целями

GRAPH_VERSION = "9.0.0"

import os
import re
import json
import time
import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timezone

from astrym_core import CONFIG_DIR, now_iso


# ============================================================
# ПУТИ
# ============================================================

GRAPH_DIR = CONFIG_DIR / "graph"
GRAPH_DB = GRAPH_DIR / "astrym.db"

try:
    GRAPH_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass


# ============================================================
# SCHEMA
# ============================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,
    type        TEXT NOT NULL,
    source_file TEXT,
    timestamp   TEXT NOT NULL,
    version     TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_type   ON scans(type);
CREATE INDEX IF NOT EXISTS idx_scans_ts     ON scans(timestamp);

CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    attrs       TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    seen_count  INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);

CREATE TABLE IF NOT EXISTS edges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    src         TEXT NOT NULL,
    dst         TEXT NOT NULL,
    label       TEXT,
    attrs       TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    seen_count  INTEGER DEFAULT 1,
    UNIQUE(src, dst, label)
);

CREATE INDEX IF NOT EXISTS idx_edges_src   ON edges(src);
CREATE INDEX IF NOT EXISTS idx_edges_dst   ON edges(dst);
CREATE INDEX IF NOT EXISTS idx_edges_label ON edges(label);

CREATE TABLE IF NOT EXISTS snapshots (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL,
    node_id   TEXT NOT NULL,
    attrs     TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);

CREATE INDEX IF NOT EXISTS idx_snap_scan ON snapshots(scan_id);
CREATE INDEX IF NOT EXISTS idx_snap_node ON snapshots(node_id);
"""


# ============================================================
# CONNECTION
# ============================================================

_lock = threading.Lock()
_conn = None


def _connect():
    global _conn
    if _conn is not None:
        return _conn
    try:
        GRAPH_DIR.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(GRAPH_DB), timeout=30,
                                check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        _conn.commit()
        return _conn
    except Exception as e:
        print("[graph] cannot open DB: " + str(e))
        return None


def init_graph():
    """Инициализация БД. Возвращает True если удалось."""
    c = _connect()
    return c is not None


def _q(sql, params=()):
    """SELECT запрос."""
    c = _connect()
    if c is None:
        return []
    with _lock:
        try:
            cur = c.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            print("[graph] query error: " + str(e))
            return []


def _exec(sql, params=()):
    """INSERT/UPDATE/DELETE."""
    c = _connect()
    if c is None:
        return None
    with _lock:
        try:
            cur = c.execute(sql, params)
            c.commit()
            return cur.lastrowid
        except Exception as e:
            print("[graph] exec error: " + str(e))
            return None


# ============================================================
# NODE / EDGE НОРМАЛИЗАЦИЯ
# ============================================================

def _nid(kind, value):
    """Уникальный ID узла."""
    v = str(value).strip().lower()
    return kind + ":" + v


def _hash_short(s, n=8):
    import hashlib
    return hashlib.sha1(str(s).encode()).hexdigest()[:n]


# ============================================================
# EXTRACTOR — превращает JSON результата в nodes/edges
# ============================================================

def extract_from_result(result):
    """Принимает dict результата ASTRYM, возвращает:
        (nodes, edges)

    node = (id, kind, attrs_dict)
    edge = (src, dst, label, attrs_dict)
    """
    nodes = []
    edges = []
    seen_n = set()

    def add_node(nid, kind, attrs=None):
        if nid in seen_n:
            return
        seen_n.add(nid)
        nodes.append((nid, kind, attrs or {}))

    def add_edge(src, dst, label, attrs=None):
        edges.append((src, dst, label, attrs or {}))

    meta = result.get("meta", {}) or {}
    t = meta.get("type", "unknown")
    detected = meta.get("detected_kind", t)
    if t == "scan" and detected:
        t = detected
    target = meta.get("target", "")
    if not target:
        return nodes, edges

    # target node
    target_id = _nid(t, target)
    add_node(target_id, t, {
        "target": target,
        "risk_score": (result.get("risk") or {}).get("score"),
        "risk_level": (result.get("risk") or {}).get("level"),
    })

    # ---------- DNS ----------
    dns = result.get("dns") or result.get("records") or {}
    if isinstance(dns, dict):
        for rt in ("A", "AAAA"):
            for ip in (dns.get(rt) or [])[:50]:
                ip_id = _nid("ip", ip)
                add_node(ip_id, "ip", {"ip": ip, "record_type": rt})
                add_edge(target_id, ip_id, rt)
        for mx in (dns.get("MX") or [])[:20]:
            mx_s = str(mx)
            parts = mx_s.split()
            host = parts[-1].rstrip(".") if parts else mx_s
            pref = parts[0] if len(parts) > 1 else None
            nid = _nid("mx", host)
            add_node(nid, "mx", {"host": host, "priority": pref})
            add_edge(target_id, nid, "MX")
        for ns in (dns.get("NS") or [])[:20]:
            ns_clean = str(ns).rstrip(".").lower()
            nid = _nid("ns", ns_clean)
            add_node(nid, "ns", {"host": ns_clean})
            add_edge(target_id, nid, "NS")
        for txt in (dns.get("TXT") or [])[:30]:
            txt_s = str(txt)[:300]
            low = txt_s.lower()
            kind = "txt"
            if low.startswith("v=spf1"):
                kind = "spf"
            elif "v=dmarc1" in low:
                kind = "dmarc"
            elif "v=dkim1" in low:
                kind = "dkim"
            elif "google-site-verification" in low:
                kind = "gverify"
            nid = _nid(kind, _hash_short(txt_s))
            add_node(nid, kind, {"value": txt_s})
            add_edge(target_id, nid, kind.upper())
        for cname in (dns.get("CNAME") or [])[:10]:
            c_s = str(cname).rstrip(".").lower()
            nid = _nid("cname", c_s)
            add_node(nid, "cname", {"host": c_s})
            add_edge(target_id, nid, "CNAME")

    # ---------- email_security ----------
    es = result.get("email_security") or {}
    if isinstance(es, dict):
        if es.get("spf"):
            nid = _nid("spf", _hash_short(es["spf"]))
            add_node(nid, "spf", {"value": str(es["spf"])[:300]})
            add_edge(target_id, nid, "SPF")
        if es.get("dmarc"):
            nid = _nid("dmarc", _hash_short(es["dmarc"]))
            add_node(nid, "dmarc", {"value": str(es["dmarc"])[:300]})
            add_edge(target_id, nid, "DMARC")
        for dk in (es.get("dkim") or [])[:5]:
            if isinstance(dk, dict):
                sel = dk.get("selector", "?")
                nid = _nid("dkim", str(sel))
                add_node(nid, "dkim", {"selector": sel,
                                        "value": str(dk.get("value"))[:200]})
                add_edge(target_id, nid, "DKIM")

    # ---------- subdomains_ct ----------
    for sub in (result.get("subdomains_ct") or [])[:300]:
        s = str(sub).strip().lower()
        if not s:
            continue
        nid = _nid("subdomain", s)
        add_node(nid, "subdomain", {"host": s, "source": "ct"})
        add_edge(target_id, nid, "HAS_SUB")

    # ---------- subdomains (sub scan) ----------
    for x in (result.get("subdomains") or [])[:500]:
        if not isinstance(x, dict):
            continue
        host = str(x.get("host", "")).strip().lower()
        if not host:
            continue
        nid = _nid("subdomain", host)
        add_node(nid, "subdomain",
                 {"host": host, "sources": x.get("sources", [])})
        add_edge(target_id, nid, "HAS_SUB")
        for ip in (x.get("ips") or [])[:5]:
            ip_id = _nid("ip", ip)
            add_node(ip_id, "ip", {"ip": ip})
            add_edge(nid, ip_id, "RESOLVES")

    # ---------- extended ----------
    ext = result.get("extended") or {}
    if isinstance(ext, dict):
        for src_name, items in ext.items():
            if not isinstance(items, list):
                continue
            for it in items[:200]:
                if not isinstance(it, str):
                    continue
                s = it.strip().lower()
                if not s or len(s) < 3:
                    continue
                nid = _nid("subdomain", s)
                add_node(nid, "subdomain",
                         {"host": s, "source": src_name})
                add_edge(target_id, nid, "HAS_SUB")

    # ---------- geo (ip scan) ----------
    geo = result.get("geo") or {}
    if isinstance(geo, dict) and "country" in geo:
        cc = str(geo.get("country", "?"))
        isp = str(geo.get("isp", "?"))
        asn = str(geo.get("as", "?"))
        if cc and cc != "?":
            nid = _nid("country", cc)
            add_node(nid, "country", {"code": geo.get("countryCode"),
                                       "name": cc})
            add_edge(target_id, nid, "IN_COUNTRY")
        if isp and isp != "?":
            nid = _nid("isp", isp)
            add_node(nid, "isp", {"name": isp})
            add_edge(target_id, nid, "ON_ISP")
        if asn and asn != "?":
            nid = _nid("asn", asn)
            add_node(nid, "asn", {"name": asn})
            add_edge(target_id, nid, "IN_ASN")

    # ---------- whois ----------
    whois = result.get("whois") or {}
    if isinstance(whois, dict) and whois:
        registrar = whois.get("registrar")
        if registrar and registrar != "?":
            nid = _nid("registrar", registrar)
            add_node(nid, "registrar", {"name": str(registrar)[:200]})
            add_edge(target_id, nid, "REGISTERED_BY")
        for ns in (whois.get("name server") or "").split("\n"):
            ns = ns.strip().rstrip(".").lower()
            if ns:
                nid = _nid("ns", ns)
                add_node(nid, "ns", {"host": ns})
                add_edge(target_id, nid, "NS")

    # ---------- email ----------
    if t == "email":
        ov = result.get("overview") or {}
        prov = ov.get("provider")
        if prov:
            nid = _nid("provider", prov)
            add_node(nid, "provider", {"name": prov})
            add_edge(target_id, nid, "PROVIDED_BY")
        for mx in (result.get("mx") or [])[:10]:
            mx_s = str(mx).rstrip(".").lower()
            if mx_s:
                nid = _nid("mx", mx_s)
                add_node(nid, "mx", {"host": mx_s})
                add_edge(target_id, nid, "MX")
        smtp = result.get("smtp") or {}
        if smtp.get("status"):
            nid = _nid("smtp_status", smtp["status"])
            add_node(nid, "smtp_status", {"status": smtp["status"]})
            add_edge(target_id, nid, "SMTP")
        h = result.get("hibp") or {}
        if h.get("found") is True:
            n = len(h.get("breaches") or [])
            nid = _nid("breach", "count_" + str(n))
            add_node(nid, "breach", {"count": n})
            add_edge(target_id, nid, "BREACHED_IN")

    # ---------- check ----------
    if t == "check":
        for src_name, res in (result.get("results") or {}).items():
            if not isinstance(res, dict):
                continue
            if res.get("error"):
                continue
            found = res.get("found")
            if found is True:
                nid = _nid("threat_hit", src_name)
                add_node(nid, "threat_hit",
                         {"source": src_name,
                          "data": {k: v for k, v in res.items()
                                   if isinstance(v, (str, int, float, bool))}})
                add_edge(target_id, nid, "FLAGGED_BY")

    # ---------- ssl ----------
    if t == "ssl" or result.get("protocol"):
        issuer = (result.get("issuer") or {}).get("commonName")
        if issuer:
            nid = _nid("cert_issuer", issuer)
            add_node(nid, "cert_issuer", {"name": str(issuer)[:200]})
            add_edge(target_id, nid, "CERT_ISSUED_BY")
        proto = result.get("protocol")
        if proto:
            nid = _nid("tls_protocol", proto)
            add_node(nid, "tls_protocol", {"protocol": proto})
            add_edge(target_id, nid, "USES_TLS")

    # ---------- ip: ports ----------
    if t == "ip":
        idb = None
        if isinstance(ext, dict):
            idb = ext.get("shodan_internetdb")
        if isinstance(idb, dict) and idb.get("ports"):
            for port in idb["ports"][:20]:
                nid = _nid("port", str(port))
                add_node(nid, "port", {"port": port})
                add_edge(target_id, nid, "OPEN_PORT")

    # ---------- web: leaks ----------
    if t == "web":
        for leak in (result.get("leaks") or [])[:20]:
            if not isinstance(leak, dict):
                continue
            path = leak.get("path", "?")
            nid = _nid("leak_path", path)
            add_node(nid, "leak_path",
                     {"path": path, "status": leak.get("status"),
                      "what": leak.get("what")})
            add_edge(target_id, nid, "EXPOSES")

    # ---------- takeover ----------
    if t == "takeover":
        for v in (result.get("vulnerable") or [])[:30]:
            if not isinstance(v, dict):
                continue
            sub = v.get("subdomain")
            svc = v.get("service")
            if sub:
                nid = _nid("subdomain", sub)
                add_node(nid, "subdomain", {"host": sub})
                add_edge(target_id, nid, "HAS_SUB")
                if svc:
                    svc_nid = _nid("takeover_service", svc)
                    add_node(svc_nid, "takeover_service", {"name": svc})
                    add_edge(nid, svc_nid, "VULNERABLE_TO")

    # ---------- origin ----------
    if t == "origin":
        for ip in (result.get("candidates") or [])[:50]:
            nid = _nid("ip", ip)
            add_node(nid, "ip", {"ip": ip})
            add_edge(target_id, nid, "ORIGIN")

    return nodes, edges


# ============================================================
# PUBLIC API
# ============================================================

def add_scan(target, scan_type, result, source_file=None):
    """Добавляет скан в граф.

    Returns:
        scan_id (int) or None
    """
    c = _connect()
    if c is None:
        return None

    ts = now_iso()

    try:
        # 1) запись скана
        scan_id = _exec(
            "INSERT INTO scans (target, type, source_file, timestamp, version) "
            "VALUES (?, ?, ?, ?, ?)",
            (target, scan_type, source_file, ts, GRAPH_VERSION))

        if scan_id is None:
            return None

        # 2) извлечение узлов и рёбер
        nodes, edges = extract_from_result(result)

        # 3) запись узлов (upsert)
        for nid, kind, attrs in nodes:
            _upsert_node(nid, kind, attrs, ts)

        # 4) запись рёбер (upsert)
        for src, dst, label, attrs in edges:
            _upsert_edge(src, dst, label, attrs, ts)

        # 5) snapshot ключевых узлов
        for nid, kind, attrs in nodes:
            _exec(
                "INSERT INTO snapshots (scan_id, node_id, attrs, timestamp) "
                "VALUES (?, ?, ?, ?)",
                (scan_id, nid, json.dumps(attrs, default=str), ts))

        return scan_id
    except Exception as e:
        print("[graph] add_scan error: " + str(e))
        return None


def _upsert_node(nid, kind, attrs, ts):
    """Обновить или создать узел."""
    try:
        attrs_json = json.dumps(attrs, default=str)
    except Exception:
        attrs_json = "{}"

    existing = _q("SELECT id FROM nodes WHERE id = ?", (nid,))
    if existing:
        _exec(
            "UPDATE nodes SET last_seen = ?, seen_count = seen_count + 1, "
            "attrs = ? WHERE id = ?",
            (ts, attrs_json, nid))
    else:
        _exec(
            "INSERT INTO nodes (id, kind, attrs, first_seen, last_seen, "
            "seen_count) VALUES (?, ?, ?, ?, ?, 1)",
            (nid, kind, attrs_json, ts, ts))


def _upsert_edge(src, dst, label, attrs, ts):
    """Обновить или создать ребро."""
    try:
        attrs_json = json.dumps(attrs, default=str)
    except Exception:
        attrs_json = "{}"

    existing = _q(
        "SELECT id FROM edges WHERE src = ? AND dst = ? AND "
        "COALESCE(label,'') = COALESCE(?,'')",
        (src, dst, label))

    if existing:
        _exec(
            "UPDATE edges SET last_seen = ?, seen_count = seen_count + 1, "
            "attrs = ? WHERE id = ?",
            (ts, attrs_json, existing[0]["id"]))
    else:
        _exec(
            "INSERT INTO edges (src, dst, label, attrs, first_seen, "
            "last_seen, seen_count) VALUES (?, ?, ?, ?, ?, ?, 1)",
            (src, dst, label, attrs_json, ts, ts))


# ============================================================
# QUERIES
# ============================================================

def get_target(target):
    """Найти целевой узел по значению (без kind)."""
    t = str(target).strip().lower()
    rows = _q(
        "SELECT id, kind, attrs FROM nodes WHERE id LIKE ?",
        ("%:" + t,))
    if not rows:
        rows = _q(
            "SELECT id, kind, attrs FROM nodes WHERE attrs LIKE ? LIMIT 1",
            ("%\"target\": \"" + t + "\"%",))
    return rows


def get_nodes_for_target(target):
    """Все узлы, достижимые из target по рёбрам (1 шаг)."""
    rows = _q("SELECT * FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1",
              (target,))
    if not rows:
        # попробуем найти по узлам
        tid = _nid("domain", target)
        tid2 = _nid("ip", target)
        tid3 = _nid("email", target)
        for candidate in (tid, tid2, tid3):
            r = _q("SELECT 1 FROM nodes WHERE id = ?", (candidate,))
            if r:
                tid = candidate
                break
        else:
            return []
    else:
        # определить тип
        stype = rows[0]["type"]
        tid = _nid(stype, target)

    return _q(
        "SELECT n.* FROM nodes n "
        "JOIN edges e ON e.dst = n.id "
        "WHERE e.src = ?",
        (tid,))


def get_edges_for_target(target):
    """Все рёбра, исходящие из target."""
    # найдём все узлы, у которых attrs содержат target
    rows = _q("SELECT id FROM nodes WHERE attrs LIKE ?",
              ("%\"target\": \"" + str(target).lower() + "\"%",))
    if not rows:
        # fallback: пробуем известные типы
        for kind in ("domain", "ip", "email", "url"):
            tid = _nid(kind, target)
            r = _q("SELECT 1 FROM nodes WHERE id = ?", (tid,))
            if r:
                rows = [{"id": tid}]
                break
    if not rows:
        return []
    tid = rows[0]["id"]
    return _q(
        "SELECT * FROM edges WHERE src = ? OR dst = ?",
        (tid, tid))


def find_related_nodes(target, max_depth=2):
    """BFS-поиск связанных узлов.

    Returns:
        dict: {
            "target_id": str,
            "nodes": [ {id, kind, attrs, depth} ],
            "edges": [ {src, dst, label, depth} ],
            "depth_max": int,
        }
    """
    tid = None
    # ищем ID
    for kind in ("domain", "ip", "email", "url", "subdomain"):
        cand = _nid(kind, target)
        r = _q("SELECT id FROM nodes WHERE id = ?", (cand,))
        if r:
            tid = cand
            break
    if tid is None:
        # через attrs
        r = _q("SELECT id FROM nodes WHERE attrs LIKE ?",
               ("%\"target\": \"" + str(target).lower() + "\"%",))
        if r:
            tid = r[0]["id"]
        else:
            return {"target_id": None, "nodes": [], "edges": [],
                    "depth_max": 0}

    visited = {tid: 0}
    nodes_out = []
    edges_out = []
    queue = [(tid, 0)]
    edges_seen = set()

    while queue:
        current, depth = queue.pop(0)
        if depth >= max_depth:
            continue

        # исходящие
        outgoing = _q(
            "SELECT * FROM edges WHERE src = ?", (current,))
        for e in outgoing:
            key = (e["src"], e["dst"], e["label"])
            if key not in edges_seen:
                edges_seen.add(key)
                edges_out.append({
                    "src": e["src"], "dst": e["dst"],
                    "label": e["label"], "depth": depth + 1,
                })
            if e["dst"] not in visited:
                visited[e["dst"]] = depth + 1
                queue.append((e["dst"], depth + 1))

        # входящие (только на depth 0 — контекст)
        if depth == 0:
            incoming = _q(
                "SELECT * FROM edges WHERE dst = ?", (current,))
            for e in incoming:
                key = (e["src"], e["dst"], e["label"])
                if key not in edges_seen:
                    edges_seen.add(key)
                    edges_out.append({
                        "src": e["src"], "dst": e["dst"],
                        "label": e["label"], "depth": depth + 1,
                    })
                if e["src"] not in visited:
                    visited[e["src"]] = depth + 1
                    queue.append((e["src"], depth + 1))

    for nid, depth in visited.items():
        r = _q("SELECT * FROM nodes WHERE id = ?", (nid,))
        if r:
            n = dict(r[0])
            n["depth"] = depth
            try:
                n["attrs"] = json.loads(n.get("attrs") or "{}")
            except Exception:
                n["attrs"] = {}
            nodes_out.append(n)

    return {
        "target_id": tid,
        "nodes": nodes_out,
        "edges": edges_out,
        "depth_max": max(visited.values()) if visited else 0,
    }


def get_snapshots(target, limit=50):
    """История сканов цели."""
    return _q(
        "SELECT id, timestamp, type, version FROM scans "
        "WHERE target = ? ORDER BY id DESC LIMIT ?",
        (target, limit))


def stats():
    """Общая статистика графа."""
    total_nodes = _q("SELECT COUNT(*) AS c FROM nodes")
    total_edges = _q("SELECT COUNT(*) AS c FROM edges")
    total_scans = _q("SELECT COUNT(*) AS c FROM scans")
    by_kind = _q(
        "SELECT kind, COUNT(*) AS c FROM nodes GROUP BY kind "
        "ORDER BY c DESC")
    top_targets = _q(
        "SELECT target, COUNT(*) AS c FROM scans GROUP BY target "
        "ORDER BY c DESC LIMIT 20")
    return {
        "nodes": total_nodes[0]["c"] if total_nodes else 0,
        "edges": total_edges[0]["c"] if total_edges else 0,
        "scans": total_scans[0]["c"] if total_scans else 0,
        "by_kind": by_kind,
        "top_targets": top_targets,
        "db_path": str(GRAPH_DB),
    }


def all_targets():
    """Все уникальные цели в графе."""
    return _q("SELECT DISTINCT target, type FROM scans ORDER BY target")


def remove_target(target):
    """Удалить всё, что связано с целью."""
    try:
        with _lock:
            c = _connect()
            if c is None:
                return False
            c.execute(
                "DELETE FROM snapshots WHERE scan_id IN "
                "(SELECT id FROM scans WHERE target = ?)", (target,))
            c.execute("DELETE FROM scans WHERE target = ?", (target,))
            c.commit()
        return True
    except Exception as e:
        print("[graph] remove: " + str(e))
        return False


def clear_all():
    """Полная очистка графа."""
    global _conn
    try:
        with _lock:
            c = _connect()
            if c is None:
                return False
            c.execute("DELETE FROM snapshots")
            c.execute("DELETE FROM edges")
            c.execute("DELETE FROM nodes")
            c.execute("DELETE FROM scans")
            c.commit()
        return True
    except Exception as e:
        print("[graph] clear: " + str(e))
        return False


def export_json(path=None):
    """Экспорт всего графа в JSON (для отладки)."""
    data = {
        "version": GRAPH_VERSION,
        "exported_at": now_iso(),
        "stats": stats(),
        "nodes": _q("SELECT * FROM nodes ORDER BY id"),
        "edges": _q("SELECT src, dst, label, first_seen, last_seen, "
                    "seen_count FROM edges ORDER BY src, dst"),
        "scans": _q("SELECT id, target, type, timestamp FROM scans "
                    "ORDER BY id"),
    }
    if path is None:
        return data
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        return path
    except Exception as e:
        print("[graph] export: " + str(e))
        return None


# ============================================================
# CLI (для теста)
# ============================================================

if __name__ == "__main__":
    import sys

    init_graph()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stats"

    if cmd == "stats":
        s = stats()
        print("ASTRYM Graph " + GRAPH_VERSION)
        print("DB:      " + s["db_path"])
        print("Nodes:   " + str(s["nodes"]))
        print("Edges:   " + str(s["edges"]))
        print("Scans:   " + str(s["scans"]))
        print()
        print("By kind:")
        for row in s["by_kind"]:
            print("  " + str(row["kind"]).ljust(20) + str(row["c"]))
        print()
        print("Top targets:")
        for row in s["top_targets"]:
            print("  " + str(row["target"]).ljust(40) + str(row["c"]))

    elif cmd == "targets":
        for row in all_targets():
            print(row["type"].ljust(15) + row["target"])

    elif cmd == "related" and len(sys.argv) > 2:
        target = sys.argv[2]
        depth = int(sys.argv[3]) if len(sys.argv) > 3 else 2
        res = find_related_nodes(target, max_depth=depth)
        print("Target: " + str(res.get("target_id")))
        print("Depth:  " + str(res.get("depth_max")))
        print("Nodes:  " + str(len(res["nodes"])))
        for n in res["nodes"][:50]:
            print("  [" + str(n["depth"]) + "] " + n["id"])

    elif cmd == "clear":
        confirm = input("Очистить весь граф? [y/N]: ").strip().lower()
        if confirm == "y":
            if clear_all():
                print("Граф очищен")
            else:
                print("Ошибка")

    elif cmd == "export" and len(sys.argv) > 2:
        out = sys.argv[2]
        p = export_json(out)
        if p:
            print("Экспортировано: " + p)

    else:
        print("Usage: astrym_graph.py {stats|targets|related <target>|"
              "clear|export <file>}")