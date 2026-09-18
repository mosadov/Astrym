#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Correlate 9.0.0 — поиск связей между целями
# Находит общую инфраструктуру: ASN, NS, IP, registrar, TLS issuer

CORRELATE_VERSION = "9.0.0"

import json
from collections import defaultdict
from astrym_core import c_ok, c_warn, c_err, c_info, c_muted
from astrym_graph import _q, _nid, init_graph


# ============================================================
# ТИПЫ КОРРЕЛЯЦИЙ
# ============================================================

# kind → человекочитаемое название
CORRELATABLE = {
    "asn":             "Autonomous System",
    "ns":              "Name Server",
    "mx":              "Mail Server",
    "ip":              "IP Address",
    "registrar":       "Domain Registrar",
    "cert_issuer":     "TLS Certificate Issuer",
    "provider":        "Email Provider",
    "isp":             "Internet Provider",
    "country":         "Country",
}


# ============================================================
# ОСНОВНАЯ КОРРЕЛЯЦИЯ ДЛЯ ОДНОЙ ЦЕЛИ
# ============================================================

def correlate_for_target(target):
    """Ищет связи с другими целями в графе.

    Returns:
        {
            "target": str,
            "target_id": str,
            "shared": {kind: [{"value": ..., "targets": [...], "count": N}]},
            "neighbors": [...],
            "total_related": int,
        }
    """
    init_graph()

    # 1) найти все target-узлы
    target_id = _find_target_id(target)
    if not target_id:
        return {"target": target, "target_id": None, "shared": {},
                "neighbors": [], "total_related": 0}

    # 2) получить прямых соседей (то, с чем связан target)
    neighbors = _q(
        "SELECT dst, label FROM edges WHERE src = ?",
        (target_id,))

    out = {
        "target": target,
        "target_id": target_id,
        "shared": {},
        "neighbors": [],
        "total_related": 0,
    }

    related_targets = set()

    # 3) для каждого соседа — кто ещё имеет такой же узел?
    for row in neighbors:
        neighbor_id = row["dst"]
        label = row["label"]

        # извлечь kind из id ("ns:ns1.example.com" → "ns")
        if ":" not in neighbor_id:
            continue
        kind = neighbor_id.split(":", 1)[0]
        if kind not in CORRELATABLE:
            continue

        # найти все target-узлы, связанные с этим neighbor
        others = _q(
            "SELECT DISTINCT src FROM edges WHERE dst = ? AND src != ?",
            (neighbor_id, target_id))

        # оставить только узлы, которые выглядят как target
        other_targets = []
        for o in others:
            src = o["src"]
            src_kind = src.split(":", 1)[0] if ":" in src else ""
            if src_kind in ("domain", "ip", "email", "url", "scan"):
                # извлечь значение
                value = src.split(":", 1)[1] if ":" in src else src
                other_targets.append({"id": src, "value": value})

        if other_targets:
            shared_value = neighbor_id.split(":", 1)[1]
            if kind not in out["shared"]:
                out["shared"][kind] = []
            out["shared"][kind].append({
                "value": shared_value,
                "shared_with": other_targets,
                "count": len(other_targets),
                "label": label,
            })
            for ot in other_targets:
                related_targets.add(ot["value"])

    # сортировка по количеству связей
    for kind in out["shared"]:
        out["shared"][kind].sort(key=lambda x: -x["count"])

    out["neighbors"] = [dict(r) for r in neighbors]
    out["total_related"] = len(related_targets)

    return out


# ============================================================
# CROSS-TARGET КОРРЕЛЯЦИЯ
# ============================================================

def correlate_targets(targets):
    """Общие свойства для группы целей.

    Args:
        targets: список значений (["github.com", "gitlab.com"])

    Returns:
        {
            "targets": [...],
            "target_ids": {...},
            "shared_by_all": [...],
            "shared_pairs": [...],
            "by_kind": {kind: [{value, targets, count}]},
        }
    """
    init_graph()

    # 1) найти ID для всех целей
    target_ids = {}
    for t in targets:
        tid = _find_target_id(t)
        if tid:
            target_ids[t] = tid

    if not target_ids:
        return {"targets": targets, "target_ids": {},
                "shared_by_all": [], "shared_pairs": [],
                "by_kind": {}}

    # 2) собрать neighbors для каждой цели
    by_target = {}
    for t, tid in target_ids.items():
        rows = _q("SELECT dst FROM edges WHERE src = ?", (tid,))
        by_target[t] = set(r["dst"] for r in rows)

    # 3) у каждого neighbor — сколько целей с ним связано
    neighbor_count = defaultdict(set)
    for t, neighbors in by_target.items():
        for n in neighbors:
            neighbor_count[n].add(t)

    # 4) разделить: все vs пары
    shared_by_all = []
    shared_by_some = []
    n_targets = len(target_ids)

    for neighbor, who in neighbor_count.items():
        if ":" not in neighbor:
            continue
        kind = neighbor.split(":", 1)[0]
        if kind not in CORRELATABLE:
            continue
        value = neighbor.split(":", 1)[1]
        item = {
            "kind": kind,
            "value": value,
            "targets": sorted(who),
            "count": len(who),
        }
        if len(who) == n_targets:
            shared_by_all.append(item)
        elif len(who) >= 2:
            shared_by_some.append(item)

    # 5) группировка по kind
    by_kind = defaultdict(list)
    for item in shared_by_all + shared_by_some:
        by_kind[item["kind"]].append(item)

    for kind in by_kind:
        by_kind[kind].sort(key=lambda x: -x["count"])

    shared_by_all.sort(key=lambda x: x["kind"])
    shared_by_some.sort(key=lambda x: (-x["count"], x["kind"]))

    return {
        "targets": targets,
        "target_ids": target_ids,
        "shared_by_all": shared_by_all,
        "shared_pairs": shared_by_some,
        "by_kind": dict(by_kind),
    }


# ============================================================
# ПОИСК СВЯЗАННЫХ ЦЕЛЕЙ (для watch / diff)
# ============================================================

def find_all_targets_sharing_with(target):
    """Список всех целей в графе, которые связаны с данной."""
    init_graph()
    target_id = _find_target_id(target)
    if not target_id:
        return []

    shared = _q(
        "SELECT DISTINCT e2.src "
        "FROM edges e1 "
        "JOIN edges e2 ON e1.dst = e2.dst "
        "WHERE e1.src = ? AND e2.src != ?",
        (target_id, target_id))

    out = []
    for row in shared:
        src = row["src"]
        if ":" in src:
            kind, value = src.split(":", 1)
            if kind in ("domain", "ip", "email", "url", "scan"):
                out.append({"id": src, "kind": kind, "value": value})
    return out


# ============================================================
# ВСПОМОГАТЕЛЬНОЕ
# ============================================================

def _find_target_id(target):
    """Ищет ID целевого узла по значению."""
    t = str(target).strip().lower()
    # точное совпадение с префиксом
    for kind in ("domain", "ip", "email", "url"):
        nid = _nid(kind, t)
        r = _q("SELECT id FROM nodes WHERE id = ?", (nid,))
        if r:
            return r[0]["id"]
    # поиск по attrs
    r = _q(
        "SELECT id FROM nodes WHERE attrs LIKE ? LIMIT 1",
        ("%\"target\": \"" + t + "\"%",))
    if r:
        return r[0]["id"]
    return None


def format_shared(shared, show_targets=True, limit=10):
    """Форматирование для печати."""
    out = []
    for kind in sorted(shared.keys()):
        items = shared[kind]
        if not items:
            continue
        title = CORRELATABLE.get(kind, kind)
        out.append("[" + title.upper() + "]")
        for item in items[:limit]:
            line = "  " + str(item["value"])[:60].ljust(60) + " (" + \
                   str(item["count"]) + ")"
            out.append(line)
            if show_targets:
                for t in item.get("shared_with", [])[:5]:
                    out.append("    → " + str(t.get("value", "?"))[:60])
        if len(items) > limit:
            out.append("  ... +" + str(len(items) - limit) + " more")
        out.append("")
    return "\n".join(out)


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":
    import sys

    init_graph()
    if len(sys.argv) < 2:
        print("Usage:")
        print("  astrym_correlate.py <target>")
        print("  astrym_correlate.py <target1> <target2> [...]")
        sys.exit(0)

    if len(sys.argv) == 2:
        target = sys.argv[1]
        res = correlate_for_target(target)
        print("Correlate: " + target)
        print("Target ID: " + str(res.get("target_id")))
        print("Related:   " + str(res.get("total_related")))
        print()
        if res["shared"]:
            print(format_shared(res["shared"]))
        else:
            print("No shared infrastructure found in graph.")
            print("(add more targets first)")
    else:
        targets = sys.argv[1:]
        res = correlate_targets(targets)
        print("Cross-target: " + ", ".join(targets))
        print()
        if res["shared_by_all"]:
            print("Shared by ALL (" + str(len(res["shared_by_all"])) + "):")
            for item in res["shared_by_all"][:30]:
                print("  " + item["kind"].ljust(15) + item["value"][:60])
            print()
        if res["shared_pairs"]:
            print("Shared by SOME (" + str(len(res["shared_pairs"])) + "):")
            for item in res["shared_pairs"][:30]:
                print("  " + item["kind"].ljust(15) +
                      item["value"][:50].ljust(50) +
                      " " + str(item["count"]) + "/" + str(len(targets)))
        if not res["shared_by_all"] and not res["shared_pairs"]:
            print("No shared properties found.")