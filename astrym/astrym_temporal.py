#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Temporal 9.8.0 — timeline изменений инфраструктуры

TEMPORAL_VERSION = "9.8.0"

from datetime import datetime, timedelta, timezone
from astrym_core import c_ok, c_warn, c_err, c_info, c_muted
from astrym_graph import _q, init_graph


def _get_scans(target, limit=500):
    init_graph()
    return _q(
        "SELECT id, target, type, timestamp FROM scans "
        "WHERE target = ? ORDER BY id ASC LIMIT ?",
        (target, limit))


def _get_snapshot(scan_id):
    rows = _q("SELECT node_id, attrs FROM snapshots WHERE scan_id = ?",
              (scan_id,))
    return {r["node_id"]: (r.get("attrs") or "{}") for r in rows}


def _diff(prev, curr):
    added = [n for n in curr if n not in prev]
    removed = [n for n in prev if n not in curr]
    changed = [n for n in curr if n in prev and prev[n] != curr[n]]
    return added, removed, changed


def build_timeline(target, since_days=None):
    # ASTRYM timeline fix (no flicker)
    #
    # Мерцание (cname-chain появляется/исчезает между сканами разных
    # команд) устраняется так: узел added только если его никогда не
    # было раньше; removed — только если его больше нигде нет после.
    scans = _get_scans(target)
    if not scans:
        return {"error": "no scans found for target: " + str(target)}

    if since_days:
        cutoff = (datetime.now(timezone.utc) -
                  timedelta(days=since_days)).isoformat()
        scans = [s for s in scans if (s.get("timestamp") or "") >= cutoff]
        if not scans:
            return {"error": "no scans in last " + str(since_days) + "d"}

    snapshots = [_get_snapshot(s["id"]) for s in scans]

    events = []
    for i in range(1, len(scans)):
        prev = snapshots[i - 1]
        curr = snapshots[i]

        # ключи, которые встречались хоть раз до текущего скана
        earlier_keys = set()
        for j in range(i):
            earlier_keys.update(snapshots[j].keys())

        # ключи, которые встретятся хоть раз после текущего скана
        later_keys = set()
        for j in range(i + 1, len(snapshots)):
            later_keys.update(snapshots[j].keys())

        # added: только если узел реально впервые появился
        added = [k for k in curr
                 if k not in prev and k not in earlier_keys]

        # removed: только если узел реально исчез навсегда
        removed = [k for k in prev
                   if k not in curr and k not in later_keys]

        # changed: атрибуты в обоих снимках, но разные
        changed = [k for k in curr
                   if k in prev and prev[k] != curr[k]]

        if added or removed or changed:
            events.append({
                "at": scans[i].get("timestamp"),
                "scan_id": scans[i]["id"],
                "prev_scan_id": scans[i - 1]["id"],
                "added": added[:30],
                "removed": removed[:30],
                "changed": changed[:30],
                "total_added": len(added),
                "total_removed": len(removed),
                "total_changed": len(changed),
            })

    return {
        "target": target,
        "scans_count": len(scans),
        "first_scan": scans[0].get("timestamp") if scans else None,
        "last_scan": scans[-1].get("timestamp") if scans else None,
        "events": events,
        "events_count": len(events),
    }
def run_temporal(target, extras=False, since_days=None):
    if not target:
        c_err("usage: timeline <target> [--since N]")
        return None
    d = build_timeline(target, since_days=since_days)
    if d.get("error"):
        c_err(d["error"]); return None
    return d


def render_timeline(data):
    from astrym_core import header, section, kv
    if data.get("error"):
        c_err(data["error"]); return
    header("Timeline", data["target"])
    kv([("scans", data["scans_count"]),
        ("first", (data.get("first_scan") or "?")[:19]),
        ("last", (data.get("last_scan") or "?")[:19]),
        ("events", data["events_count"])])
    if data["events_count"] == 0:
        c_muted("  изменений между сканами не найдено "
                "(или только 1 скан)")
        return
    for e in data["events"][:30]:
        section("[" + (e.get("at") or "?")[:19] +
                "]  scan#" + str(e["scan_id"]))
        c_muted("  +" + str(e["total_added"]) +
                "  -" + str(e["total_removed"]) +
                "  ~" + str(e["total_changed"]))
        for nid in e["added"][:10]: c_ok("    + " + nid[:80])
        for nid in e["removed"][:10]: c_err("    - " + nid[:80])
        for nid in e["changed"][:10]: c_warn("    ~ " + nid[:80])
