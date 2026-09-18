#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Monitor 9.7.0 — периодический watch с алертами

MONITOR_VERSION = "9.7.0"

import os
import time
from pathlib import Path
from astrym_core import (CONFIG_DIR, now_iso, classify,
                          c_ok, c_warn, c_err, c_info, c_muted)

ALERTS_DIR = CONFIG_DIR / "alerts"
try:
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass


def _alert_path(target):
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in target)[:80]
    return ALERTS_DIR / (safe + ".log")


def _write_alert(target, text):
    try:
        with open(_alert_path(target), "a", encoding="utf-8") as f:
            f.write("[" + now_iso() + "] " + text + "\n")
    except Exception:
        pass


def _run_one(target):
    """Один проход watch: собрать, сравнить, сохранить."""
    import astrym as _a  # late — избегаем circular
    from astrym_extra import watch_load, watch_save, watch_diff

    k = classify(target)
    cmd = "check" if k in ("ip", "domain", "url") else k
    if cmd not in _a.DISPATCH:
        return None, "unsupported kind: " + k
    try:
        new = _a.DISPATCH[cmd](target, False)
    except Exception as e:
        return None, "collect error: " + str(e)[:120]
    if not new:
        return None, "no data"

    old = watch_load(target)
    diff = watch_diff(old, new) if old else {"added": [], "removed": [], "changed": []}
    watch_save(target, new)
    return (new, diff), None


def _summarize_diff(diff):
    if not diff:
        return "no changes"
    parts = []
    if diff.get("added"):
        parts.append("+" + str(len(diff["added"])))
    if diff.get("removed"):
        parts.append("-" + str(len(diff["removed"])))
    if diff.get("changed"):
        parts.append("~" + str(len(diff["changed"])))
    return " ".join(parts) if parts else "no changes"


def run_monitor(target, interval=3600, cycles=0, quiet=False):
    if interval < 30:
        c_warn("interval < 30s, поднято до 30s")
        interval = 30

    log_path = _alert_path(target)
    if not quiet:
        c_info("monitor: " + str(target))
        c_info("interval: " + str(interval) + "s, cycles: " +
               ("inf" if cycles == 0 else str(cycles)))
        c_info("alerts log: " + str(log_path))
        c_info("Ctrl+C to stop")

    n = 0
    try:
        while True:
            n += 1
            if not quiet:
                c_info("--- cycle " + str(n) + " ---")
            result, err = _run_one(target)
            if err:
                _write_alert(target, "ERROR: " + err)
                if not quiet:
                    c_err(err)
            else:
                new, diff = result
                s = _summarize_diff(diff)
                _write_alert(target, "OK: " + s)
                if not quiet:
                    if diff.get("added") or diff.get("removed") or diff.get("changed"):
                        c_warn("CHANGES: " + s)
                        for x in (diff.get("added") or [])[:5]:
                            c_ok("  + " + str(x)[:80])
                        for x in (diff.get("removed") or [])[:5]:
                            c_err("  - " + str(x)[:80])
                        for x in (diff.get("changed") or [])[:5]:
                            c_warn("  ~ " + str(x)[:80])
                    else:
                        c_ok("no changes")
            if cycles and n >= cycles:
                if not quiet:
                    c_info("done: " + str(n) + " cycles")
                break
            try:
                time.sleep(interval)
            except KeyboardInterrupt:
                if not quiet:
                    c_info("interrupted")
                break
    except KeyboardInterrupt:
        if not quiet:
            c_info("interrupted at cycle " + str(n))
    return {"target": target, "cycles_done": n, "log": str(log_path)}


def run_monitor_cli(line):
    """Разбор строки 'monitor <target> [--interval N] [--cycles M] [--quiet]'."""
    parts = line.split()
    if not parts:
        c_err("usage: monitor <target> [--interval N] [--cycles M] [--quiet]")
        return None
    target = None
    interval = 3600
    cycles = 0
    quiet = False
    i = 0
    while i < len(parts):
        a = parts[i]
        if a == "--interval" and i + 1 < len(parts):
            i += 1
            try: interval = int(parts[i])
            except Exception: pass
        elif a == "--cycles" and i + 1 < len(parts):
            i += 1
            try: cycles = int(parts[i])
            except Exception: pass
        elif a == "--quiet":
            quiet = True
        elif not a.startswith("-") and target is None:
            target = a
        i += 1
    if not target:
        c_err("usage: monitor <target> [--interval N] [--cycles M] [--quiet]")
        return None
    return run_monitor(target, interval=interval, cycles=cycles, quiet=quiet)
