#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Community 9.6.0 — Louvain communities + GEXF export
# Работает поверх SQLite-графа astrym_graph.py

COMMUNITY_VERSION = "9.6.0"

import json
from collections import defaultdict
from pathlib import Path

from astrym_core import c_ok, c_warn, c_err, c_info, c_muted, now_iso
from astrym_graph import _q, init_graph, GRAPH_DB


# ============================================================
# 1. GRAPH LOADER (из SQLite)
# ============================================================

def load_networkx_graph(min_kind=None):
    """Читает nodes/edges из astrym_graph → networkx.Graph.

    Args:
        min_kind: опционально фильтр kinds узлов (set[str])

    Returns:
        (nx.Graph, dict{node_id: attrs})
    """
    try:
        import networkx as nx
    except ImportError:
        return None, None

    init_graph()
    rows_n = _q("SELECT id, kind, attrs FROM nodes")
    rows_e = _q("SELECT src, dst, label FROM edges")

    G = nx.Graph()
    attrs_by_id = {}

    for r in rows_n:
        nid = r["id"]
        kind = r["kind"]
        if min_kind and kind not in min_kind:
            continue
        try:
            attrs = json.loads(r.get("attrs") or "{}")
        except Exception:
            attrs = {}
        G.add_node(nid, kind=kind, **{k: str(v)[:120] for k, v in attrs.items()})
        attrs_by_id[nid] = {"kind": kind, "attrs": attrs}

    for e in rows_e:
        src, dst = e["src"], e["dst"]
        if src not in G or dst not in G:
            continue
        G.add_edge(src, dst, label=e.get("label") or "")

    return G, attrs_by_id


# ============================================================
# 2. LOUVAIN
# ============================================================

def louvain_communities(G, resolution=1.0, seed=42):
    """networkx.algorithms.community.louvain_communities.

    Встроено в networkx >= 2.8 — python-louvain НЕ нужен.
    """
    import networkx as nx
    try:
        return nx.algorithms.community.louvain_communities(
            G, resolution=resolution, seed=seed)
    except AttributeError:
        raise RuntimeError(
            "networkx >= 2.8 required. Run: pip install -U networkx")


def modularity(G, communities):
    import networkx as nx
    return nx.algorithms.community.modularity(G, communities)


def summarize_community(community, G, attrs_by_id, top_n=8):
    """Сводка по сообществу: размер, kinds, топ-узлы, общий target."""
    kinds = defaultdict(int)
    targets = []
    hubs = []

    for nid in community:
        info = attrs_by_id.get(nid) or {}
        kind = info.get("kind", "?")
        kinds[kind] += 1
        if kind in ("domain", "ip", "email", "url"):
            targets.append(nid.split(":", 1)[-1])
        hubs.append((nid, G.degree(nid)))

    hubs.sort(key=lambda x: -x[1])
    return {
        "size": len(community),
        "kinds": dict(kinds),
        "targets": sorted(set(targets)),
        "hubs": [{"id": h, "degree": d} for h, d in hubs[:top_n]],
    }


# ============================================================
# 3. DETECT + REPORT
# ============================================================

def detect_communities(resolution=1.0, min_size=3, exclude_kinds=None):
    """Полный анализ: Louvain + сводка + метрики.

    Returns:
        {
            "version": ...,
            "generated_at": ...,
            "graph_stats": {"nodes": N, "edges": M},
            "modularity": float,
            "communities_count": int,
            "communities": [ {...}, ... ],
        }
    """
    G, attrs_by_id = load_networkx_graph()
    if G is None:
        return {"error": "networkx not installed — pip install networkx"}
    if G.number_of_nodes() == 0:
        return {"error": "graph is empty — run some scans first"}

    # фильтр по kinds
    if exclude_kinds:
        drop = [n for n, d in G.nodes(data=True)
                if d.get("kind") in exclude_kinds]
        G.remove_nodes_from(drop)

    if G.number_of_nodes() < 3:
        return {"error": "graph too small for community detection (<3 nodes)"}

    comms = louvain_communities(G, resolution=resolution)
    mod = modularity(G, comms) if G.number_of_edges() > 0 else 0.0

    enriched = []
    for i, c in enumerate(comms):
        if len(c) < min_size:
            continue
        s = summarize_community(c, G, attrs_by_id)
        s["id"] = i
        enriched.append(s)

    enriched.sort(key=lambda x: -x["size"])

    return {
        "version": COMMUNITY_VERSION,
        "generated_at": now_iso(),
        "graph_stats": {"nodes": G.number_of_nodes(),
                        "edges": G.number_of_edges()},
        "modularity": round(mod, 4),
        "communities_count": len(enriched),
        "communities": enriched,
    }


# ============================================================
# 4. GEXF EXPORT (Gephi / Cytoscape / yEd)
# ============================================================

# ASTRYM gexf-fix v2
def _hex_to_rgba(hex_str):
    """'#a855f7' → {'r':168,'g':85,'b':247,'a':0}"""
    h = (hex_str or "#888888").lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    try:
        r = int(h[0:2], 16)
        g = int(h[2:4], 16)
        b = int(h[4:6], 16)
    except Exception:
        r, g, b = 136, 136, 136
    return {"r": r, "g": g, "b": b, "a": 0}


def export_gexf(path, color_by_community=True, resolution=1.0):
    """Экспорт графа в GEXF 1.2 с подсветкой Louvain-сообществ."""
    try:
        import networkx as nx
    except ImportError:
        return None

    G, attrs_by_id = load_networkx_graph()
    if G is None or G.number_of_nodes() == 0:
        return None

    if color_by_community and G.number_of_edges() > 0:
        try:
            comms = louvain_communities(G, resolution=resolution)
            palette = _community_palette(len(comms))
            node_color = {}
            node_comm = {}
            for i, c in enumerate(comms):
                for nid in c:
                    node_color[nid] = palette[i % len(palette)]
                    node_comm[nid] = i
            for nid, d in G.nodes(data=True):
                d["community"] = int(node_comm.get(nid, -1))
                # GEXF требует формат {"r","g","b","a"} — int, не hex-строка
                d["viz"] = {"color": _hex_to_rgba(
                    node_color.get(nid, "#888888"))}
        except Exception as e:
            print("[gexf] color step skipped: " + str(e))

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        nx.write_gexf(G, str(p))
    except Exception as e:
        print("[gexf] write_gexf failed: " + repr(e))
        return None
    return str(p)


def _community_palette(n):
    """Простая палитра на N цветов (HSL→hex)."""
    import colorsys
    if n <= 0:
        return ["#a855f7"]
    out = []
    for i in range(n):
        h = (i / n) % 1.0
        r, g, b = colorsys.hsv_to_rgb(h, 0.65, 0.95)
        out.append("#%02x%02x%02x" % (int(r * 255), int(g * 255), int(b * 255)))
    return out


# ============================================================
# 5. RENDER (console)
# ============================================================

def render_communities(data):
    from astrym_core import header, section, kv
    if data.get("error"):
        c_err(data["error"])
        return

    header("Louvain Communities",
           f"{data['communities_count']} communities · "
           f"modularity {data['modularity']}")

    section("Graph")
    kv([("nodes", data["graph_stats"]["nodes"]),
        ("edges", data["graph_stats"]["edges"]),
        ("communities (>=3)", data["communities_count"]),
        ("modularity", data["modularity"])])

    for i, c in enumerate(data["communities"][:20]):
        section(f"#{i+1}  size={c['size']}")
        kinds_str = ", ".join(f"{k}:{v}" for k, v in
                              sorted(c["kinds"].items(), key=lambda x: -x[1]))
        c_muted("  kinds:   " + kinds_str)
        if c["targets"]:
            c_ok("  targets: " + ", ".join(c["targets"][:6]) +
                 (f" (+{len(c['targets'])-6})" if len(c["targets"]) > 6 else ""))
        c_muted("  top hubs:")
        for h in c["hubs"][:5]:
            c_muted(f"    deg={h['degree']:>3}  {h['id'][:70]}")

    if len(data["communities"]) > 20:
        c_muted(f"\n  ... +{len(data['communities'])-20} communities")


# ============================================================
# 6. CLI
# ============================================================

if __name__ == "__main__":
    import sys
    init_graph()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "detect"

    if cmd == "detect":
        res = detect_communities()
        render_communities(res)

    elif cmd == "export" and len(sys.argv) > 2:
        out = sys.argv[2]
        p = export_gexf(out)
        if p:
            print(f"[+] GEXF exported: {p}")
            print(f"    DB: {GRAPH_DB}")
        else:
            print("[-] export failed (empty graph or networkx missing)")

    elif cmd == "json":
        res = detect_communities()
        print(json.dumps(res, indent=2, ensure_ascii=False, default=str))

    else:
        print("Usage:")
        print("  astrym_community.py detect")
        print("  astrym_community.py export <out.gexf>")
        print("  astrym_community.py json")