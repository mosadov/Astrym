#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ASTRYM ASCII — рендер графа в терминал."""

ASCII_VERSION = "1.0.0"

from astrym_core import c_ok, c_warn, c_err, c_info, c_muted
from astrym_graph import _q, _nid, init_graph

T_BRANCH = "\u251c\u2500 "
L_BRANCH = "\u2514\u2500 "
V_PIPE   = "\u2502  "
SPACE    = "   "


def _label(nid, max_len=50):
    if ":" in nid:
        kind, val = nid.split(":", 1)
        return val[:max_len]
    return str(nid)[:max_len]


def _kind(nid):
    if ":" in nid:
        return nid.split(":", 1)[0]
    return "?"


def _find_target_id(target):
    for kind in ("domain", "ip", "email", "url", "subdomain"):
        cand = _nid(kind, target)
        r = _q("SELECT id FROM nodes WHERE id = ?", (cand,))
        if r:
            return cand
    r = _q("SELECT id FROM nodes WHERE attrs LIKE ? LIMIT 1",
           ('%"target": "' + str(target).lower() + '"%',))
    if r:
        return r[0]["id"]
    return None


def ascii_tree(target, max_depth=3, max_per_group=10, max_total=200):
    init_graph()
    tid = _find_target_id(target)
    if not tid:
        return None

    lines = []

    def walk(nid, prefix="", depth=0, is_last=True, is_root=False):
        if len(lines) >= max_total:
            return
        label = _label(nid, 60)
        if is_root:
            lines.append("\u25cf " + label)
        else:
            connector = L_BRANCH if is_last else T_BRANCH
            lines.append(prefix + connector + label)

        if depth >= max_depth:
            return

        edges = _q(
            "SELECT dst, label FROM edges WHERE src = ? ORDER BY dst",
            (nid,))
        if not edges:
            return

        by_kind = {}
        for e in edges:
            k = _kind(e["dst"])
            by_kind.setdefault(k, []).append(e)

        order = ["ip", "ns", "mx", "subdomain", "cert_issuer",
                 "registrar", "asn", "country", "isp", "email",
                 "cname", "spf", "dmarc", "provider"]
        kinds = sorted(by_kind.keys(),
                        key=lambda k: (order.index(k) if k in order else 99, k))

        new_prefix = (prefix if is_root
                      else prefix + (SPACE if is_last else V_PIPE))

        for i, k in enumerate(kinds):
            group = by_kind[k]
            is_last_group = (i == len(kinds) - 1)
            group_label = f"{k} ({len(group)})"
            connector = L_BRANCH if is_last_group else T_BRANCH
            lines.append(new_prefix + connector + group_label)
            group_prefix = new_prefix + (SPACE if is_last_group else V_PIPE)
            shown = group[:max_per_group]
            for j, e in enumerate(shown):
                is_last_child = (j == len(shown) - 1) and (len(group) <= max_per_group)
                walk(e["dst"], group_prefix, depth + 1,
                      is_last_child, False)
            if len(group) > max_per_group:
                more = len(group) - max_per_group
                lines.append(group_prefix + L_BRANCH + f"... \u0438 \u0435\u0449\u0451 {more}")

    walk(tid, "", 0, True, True)
    return "\n".join(lines)


def render_tree(target, max_depth=3, max_per_group=10):
    from astrym_core import header
    graph = ascii_tree(target, max_depth=max_depth,
                        max_per_group=max_per_group)
    if not graph:
        c_warn("no graph for target: " + str(target))
        c_info("сначала запусти: astrym.py domain " + str(target))
        return None
    header("Graph tree", str(target))
    print()
    print(graph)
    print()
    return graph


def render_communities_ascii(data, max_show=8):
    from astrym_core import header
    if data.get("error"):
        c_err(data["error"]); return

    header("Louvain Communities",
           f"{data['communities_count']} communities \u00b7 "
           f"modularity {data['modularity']}")
    print()
    print(f"  nodes:        {data['graph_stats']['nodes']}")
    print(f"  edges:        {data['graph_stats']['edges']}")
    print(f"  communities:  {data['communities_count']}")
    print(f"  modularity:   {data['modularity']}")
    print()

    W = 60
    for i, c in enumerate(data["communities"][:max_show]):
        size = c["size"]
        kinds = c.get("kinds", {})
        targets = c.get("targets", [])
        hubs = c.get("hubs", [])

        print("\u2554" + "\u2550" * (W - 2) + "\u2557")
        print("\u2551" + f" # {i+1} \u00b7 size {size} ".ljust(W - 2) + "\u2551")
        print("\u255f" + "\u2500" * (W - 2) + "\u2562")

        kinds_str = ", ".join(
            f"{k}:{v}" for k, v in
            sorted(kinds.items(), key=lambda x: -x[1])[:8])
        print("\u2551 " + f"kinds:   {kinds_str}"[:W - 3].ljust(W - 3) + "\u2551")

        if targets:
            tt = ", ".join(targets[:5])
            if len(targets) > 5:
                tt += f" (+{len(targets)-5})"
            print("\u2551 " + f"targets: {tt}"[:W - 3].ljust(W - 3) + "\u2551")

        if hubs:
            print("\u2551 " + "hubs:".ljust(W - 3) + "\u2551")
            for h in hubs[:5]:
                hid = h.get("id", "?")
                deg = h.get("degree", 0)
                line = f"  \u25cf {_label(hid, 40)}  deg {deg}"
                print("\u2551 " + line[:W - 3].ljust(W - 3) + "\u2551")

        print("\u255a" + "\u2550" * (W - 2) + "\u255d")
        print()

    if len(data["communities"]) > max_show:
        c_muted(f"  ... \u0438 \u0435\u0449\u0451 {len(data['communities']) - max_show}")


def render_correlate_ascii(res):
    from astrym_core import header
    header("Cross-target correlation",
           f"{len(res.get('targets', []))} targets")

    if not res.get("target_ids"):
        c_warn("нет данных в графе")
        return

    print()
    print("  targets in graph:")
    for t, tid in res["target_ids"].items():
        print(f"    \u2713 {t}")
    print()

    if res["shared_by_all"]:
        print(f"  Shared by ALL ({len(res['shared_by_all'])}):")
        items = res["shared_by_all"][:30]
        for i, item in enumerate(items):
            last = (i == len(items) - 1)
            conn = L_BRANCH if last else T_BRANCH
            print(f"  {conn}{item['kind']}: {item['value'][:60]}")
        print()

    if res["shared_pairs"]:
        print(f"  Shared by SOME ({len(res['shared_pairs'])}):")
        items = res["shared_pairs"][:30]
        for i, item in enumerate(items):
            last = (i == len(items) - 1)
            conn = L_BRANCH if last else T_BRANCH
            cnt = item["count"]
            total = len(res["target_ids"])
            print(f"  {conn}{item['kind']}: "
                  f"{item['value'][:40]:40}  {cnt}/{total}")
        print()

    if not res["shared_by_all"] and not res["shared_pairs"]:
        c_info("\u043e\u0431\u0449\u0435\u0439 \u0438\u043d\u0444\u0440\u0430\u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u044b \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d\u043e")


def render_related_ascii(res, target=None):
    from astrym_core import header
    header(f"Related to {target}",
           f"{len(res.get('nodes', []))} nodes \u00b7 depth {res.get('depth_max', 0)}")

    if not res.get("nodes"):
        c_warn("no related nodes")
        c_info("run more scans to build the graph")
        return

    by_depth = {}
    for n in res["nodes"]:
        d = n.get("depth", 0)
        by_depth.setdefault(d, []).append(n)

    for d in sorted(by_depth.keys()):
        nodes = by_depth[d]
        print()
        print(f"  depth {d} ({len(nodes)}):")

        by_kind = {}
        for n in nodes:
            k = n.get("kind") or _kind(n.get("id", "?"))
            by_kind.setdefault(k, []).append(n)

        for k in sorted(by_kind.keys()):
            items = by_kind[k]
            shown = items[:15]
            for i, n in enumerate(shown):
                last = (i == len(shown) - 1) and (len(items) <= 15)
                conn = L_BRANCH if last else T_BRANCH
                val = _label(n.get("id", ""), 60)
                print(f"    {conn}{k}: {val}")
            if len(items) > 15:
                print(f"    {L_BRANCH}... \u0438 \u0435\u0449\u0451 {len(items) - 15}")


def run_tree(target, depth=3, extras=False):
    depth = int(depth) if depth else 3
    return render_tree(target, max_depth=depth)
