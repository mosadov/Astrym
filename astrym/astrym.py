#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM 9.0.0 — main entry point (graph integrated)
# Python 3.7+ | Android | Linux | macOS | Windows

VERSION = ""

import sys
import os

try:
    _here = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _here = os.getcwd()
if _here and _here not in sys.path:
    sys.path.insert(0, _here)


# ASTRYM 9.5 — ASN + CNAME
try:
    from astrym_asn import (run_asn, run_cname,
                             render_asn, render_cname)
    RENDER_ASN_EXTRA = {'asn': render_asn,
                        'cname': render_cname}
except ImportError as _e:
    sys.stderr.write('[astrym] astrym_asn: ' + str(_e) + '\n')
    run_asn = run_cname = None
    RENDER_ASN_EXTRA = {}

# # ASTRYM ahmia patch
try:
    from astrym_ahmia import run_ahmia, render_ahmia
    RENDER_AHMIA = {'ahmia': render_ahmia}
except ImportError as _e_a:
    sys.stderr.write('[astrym] astrym_ahmia: ' + str(_e_a) + '\n')
    run_ahmia = None
    RENDER_AHMIA = {}

try:
    from astrym_recon import (run_username, render_username,
                                run_dork, render_dork)
    RENDER_RECON = {'username': render_username, 'dork': render_dork}
except ImportError:
    run_username = run_dork = None
    RENDER_RECON = {}

# # ASTRYM monitor patch
try:
    from astrym_monitor import run_monitor, run_monitor_cli
except ImportError as _e_m:
    sys.stderr.write('[astrym] astrym_monitor: ' + str(_e_m) + '\n')
    run_monitor = run_monitor_cli = None

# # ASTRYM consensus patch
try:
    from astrym_consensus import run_consensus, render_consensus
    RENDER_ASN_EXTRA['consensus'] = render_consensus
except ImportError as _e_c:
    sys.stderr.write('[astrym] consensus: ' + str(_e_c) + '\n')
    run_consensus = None

# # ASTRYM stix patch
try:
    from astrym_stix import run_stix, render_stix
    RENDER_ASN_EXTRA['stix'] = render_stix
except ImportError as _e_stix:
    sys.stderr.write('[astrym] stix: ' + str(_e_stix) + '\n')
    run_stix = None

# # ASTRYM wave5-temporal patch
try:
    from astrym_temporal import run_temporal, render_timeline
    RENDER_ASN_EXTRA['timeline'] = render_timeline
except ImportError as _e_w5:
    sys.stderr.write('[astrym] wave5-temporal: ' + str(_e_w5) + '\n')
    run_temporal = None


# ============================================================
# IMPORT CORE
# ============================================================

try:
    from astrym_core import (
        BASE_DIR, RESULTS_DIR, CONFIG_DIR, CONFIG_PATH, HISTORY_PATH,
        WATCH_DIR, GEOIP_DIR,
        HAS_DNS, HAS_REQUESTS, HAS_RICH, HAS_PDF, HAS_GEOIP2, HAS_PN,
        load_cfg, hist_all, hist_search, hist_clear,
        c_ok, c_warn, c_err, c_info, c_muted,
        header, section, kv, _clear,
        print_banner, print_deps,
        parse_cli_line, now_iso, classify,
    set_profile, get_profile,  # ASTRYM profile patch
    )
except ImportError as e:
    sys.stderr.write("FATAL: cannot import astrym_core.py: " + str(e) + "\n")
    sys.stderr.write("Make sure all modules are in the same folder.\n")
    sys.exit(1)


# ============================================================
# IMPORT MODULES
# ============================================================

try:
    from astrym_render import render_any, render_watch_diff
    from astrym_output import output_results, auto_path
    from astrym_ip import run_ip
    from astrym_domain import run_domain, run_dns, run_sub
    from astrym_email import run_email
    from astrym_check import run_check
    from astrym_advanced import (
        run_web, run_takeover, run_leak, run_origin,
        run_whois_history, run_darkweb,
    )
    from astrym_extra import (
        run_ssl, run_phone, run_scan,
        watch_load, watch_save, watch_list, watch_diff,
        batch_read,
    )
except ImportError as e:
    sys.stderr.write("FATAL: cannot import module: " + str(e) + "\n")
    sys.exit(1)


# ============================================================
# IMPORT RICH
# ============================================================

try:
    from rich.panel import Panel
    from rich.box import ROUNDED
    from rich.align import Align
    if HAS_RICH:
        from astrym_core import console
except ImportError:
    pass


# ============================================================
# IMPORT GRAPH (v9.0)
# ============================================================

try:
    import astrym_graph
    astrym_graph.init_graph()
    _HAS_GRAPH = True
except Exception as _e:
    sys.stderr.write("[astrym] graph module: " + str(_e) + "\n")
    _HAS_GRAPH = False

# === ASTRYM community patch ===
try:
    import astrym_community
    _HAS_COMMUNITY = True
except Exception as _e:
    sys.stderr.write("[astrym] community module: " + str(_e) + "\n")
    _HAS_COMMUNITY = False


# ============================================================
# DISPATCHER
# ============================================================

DISPATCH = {
    "ip":            lambda t, e, **kw: run_ip(t, extras=e),
    "domain":        lambda t, e, **kw: run_domain(t, extras=e),
    "dns":           lambda t, e, **kw: run_dns(t, extras=e),
    "sub":           lambda t, e, **kw: run_sub(
                        t, extras=e,
                        wordlist=kw.get("wordlist"),
                        workers=kw.get("workers", 40)),
    "email":         lambda t, e, **kw: run_email(t, extras=e),
    "check":         lambda t, e, **kw: run_check(t, extras=e),
    "ssl":           lambda t, e, **kw: run_ssl(t, extras=e,
                        port=kw.get("port", 443)),
    "scan":          lambda t, e, **kw: run_scan(t, extras=e),
    "web":           lambda t, e, **kw: run_web(t, extras=e),
    "darkweb":       lambda t, e, **kw: run_darkweb(t, extras=e,
                        max_pages=kw.get("pages", 3),
                        max_depth=kw.get("depth", 1)),
    "takeover":      lambda t, e, **kw: run_takeover(t, extras=e),
    "leak":          lambda t, e, **kw: run_leak(t, extras=e),
    "origin":        lambda t, e, **kw: run_origin(t, extras=e),
    "whois-history": lambda t, e, **kw: run_whois_history(t, extras=e),
    "phone":         lambda t, e, **kw: run_phone(t, extras=e),
    "asn":           lambda t, e, **kw: run_asn(t, extras=e) if run_asn else None,
    "cname":         lambda t, e, **kw: run_cname(t, extras=e) if run_cname else None,
    "ahmia":         lambda t, e, **kw: run_ahmia(t, extras=e) if run_ahmia else None,
    "clear-history": lambda t, e, **kw: _run_clear_history(),
    "clear-log":     lambda t, e, **kw: _run_clear_log(),
    "clear-watches": lambda t, e, **kw: _run_clear_watches(),
    "clear-results": lambda t, e, **kw: _run_clear_results(),
    "username":      lambda t, e, **kw: run_username(t, extras=e) if run_username else None,
    "dork":          lambda t, e, **kw: run_dork(t, extras=e) if run_dork else None,
    "timeline":      lambda t, e, **kw: run_temporal(t, extras=e, since_days=kw.get("since_days")) if run_temporal else None,
    "consensus":     lambda t, e, **kw: run_consensus(t, extras=e) if run_consensus else None,
    "stix":          lambda t, e, **kw: run_stix(t, extras=e) if run_stix else None,
    # # ASTRYM consensus-domain patch-dispatch
    "domain-consensus": lambda t, e, **kw: _run_domain_consensus(t)
        if "run_consensus_domain" in globals() or True else None,
}


# ============================================================
# RUN ONCE
# ============================================================

def run_once(args):
    cmd = args.get("command")
    targets = args.get("targets", [])
    fmt = args.get("format", "console")
    extras = args.get("extras", False)
    workers = args.get("workers", 40)
    _prof = set_profile(args.get("profile", "normal"))
    if _prof.get("name") != "normal":
        c_info("profile: " + _prof["name"])

    # --- graph commands ---
    if cmd == "related":
        return _cmd_related(targets)
    if cmd == "correlate":
        return _cmd_correlate(targets)
    if cmd == "graph":
        return _cmd_graph(targets)

    if cmd == "community":
        return _cmd_community(args)
    if cmd == "gexf":
        return _cmd_gexf(args)

    if cmd not in DISPATCH:
        c_err("unknown command: " + str(cmd))
        return

    n = len(targets)
    sub_t = targets[0] if n == 1 else str(n) + " targets"
    tag = " [+extras]" if extras else ""
    if "console" in fmt or "all" in fmt:
        header(cmd.upper() + " Analysis" + tag, sub_t)

    data = []
    for t in targets:
        try:
            r = DISPATCH[cmd](t, extras, workers=workers)
        except KeyboardInterrupt:
            c_warn("interrupted on " + t)
            continue
        except Exception as e:
            c_err(t + ": " + str(e))
            continue
        if r:
            data.append(r)

    if not data:
        c_warn("no results")
        return

    # --- write to graph ---
    if _HAS_GRAPH:
        for r in data:
            m = r.get("meta", {}) or {}
            tgt = m.get("target")
            typ = m.get("detected_kind") or m.get("type", cmd)
            if tgt and typ:
                try:
                    astrym_graph.add_scan(tgt, typ, r)
                except Exception as e:
                    sys.stderr.write("[astrym] graph add: " + str(e) + "\n")

    auto_kind = cmd
    if cmd == "scan" and data:
        auto_kind = data[0]["meta"].get("detected_kind", "scan")

    # v9.5: отдельные рендеры для asn/cname
    _v9_5_render = True
    _SPECIAL_RENDER = {**RENDER_ASN_EXTRA, **RENDER_AHMIA, **RENDER_RECON}  # ASTRYM ahmia patch
    # ASTRYM stix-formats patch
    _console_renderers = (globals().get("_SPECIAL_RENDER")
                          or globals().get("RENDER_ASN_EXTRA") or {})
    _handled_console = False
    if cmd in _console_renderers and ("console" in fmt or "all" in fmt):
        for _r in data:
            try:
                _console_renderers[cmd](_r)
            except Exception as _e2:
                sys.stderr.write("[astrym] render: " + str(_e2) + "\n")
        _handled_console = True

    if _handled_console:
        _fl = [f.strip() for f in fmt.split(",") if f.strip()]
        if "all" in _fl:
            _file_fmts = ["json", "html", "csv", "pdf", "md", "topology"]
        else:
            _file_fmts = [f for f in _fl if f != "console"]
        if _file_fmts:
            output_results(data, ",".join(_file_fmts),
                            auto_kind=auto_kind, render_fn=None)
    else:
        output_results(data, fmt, auto_kind=auto_kind, render_fn=render_any)

    # --- show hint ---
    if _HAS_GRAPH and n == 1 and cmd in ("domain", "ip", "email", "sub"):
        try:
            _show_related_hint(targets[0])
        except Exception:
            pass


# ============================================================
# GRAPH COMMANDS
# ============================================================

def _cmd_related(targets):
    if not _HAS_GRAPH:
        c_err("graph module not available")
        return
    if not targets:
        c_warn("usage: related <target> [depth]")
        return
    target = targets[0]
    depth = 2
    if len(targets) > 1:
        try:
            depth = int(targets[1])
        except Exception:
            pass

    from astrym_graph import find_related_nodes
    res = find_related_nodes(target, max_depth=depth)
    header("Related to " + target,
           str(len(res["nodes"])) + " nodes . depth " + str(depth))

    if not res["nodes"]:
        c_warn("no related nodes found")
        c_info("run more scans to build the graph")
        return

    section("Nodes by depth")
    by_depth = {}
    for n in res["nodes"]:
        d = n.get("depth", 0)
        by_depth.setdefault(d, []).append(n)

    for d in sorted(by_depth.keys()):
        nodes_at_d = by_depth[d]
        c_info("depth " + str(d) + ": " + str(len(nodes_at_d)) + " nodes")
        for n in nodes_at_d[:30]:
            kind = n.get("kind", "?")
            nid = n.get("id", "?")
            value = nid.split(":", 1)[1] if ":" in nid else nid
            c_muted("  " + kind.ljust(16) + value[:70])
        if len(nodes_at_d) > 30:
            c_muted("  ... +" + str(len(nodes_at_d) - 30) + " more")


def _cmd_correlate(targets):
    if not _HAS_GRAPH:
        c_err("graph module not available")
        return
    if not targets:
        c_warn("usage: correlate <target> [<target2>...]")
        return

    from astrym_correlate import (
        correlate_for_target, correlate_targets, format_shared,
    )

    if len(targets) == 1:
        target = targets[0]
        res = correlate_for_target(target)
        header("Correlate: " + target,
               str(res.get("total_related", 0)) + " related targets")

        if not res.get("target_id"):
            c_warn("target not in graph - run a scan first")
            return

        if not res.get("shared"):
            c_info("no shared infrastructure found")
            c_info("scan more targets to find correlations")
            return

        section("Shared infrastructure")
        print(format_shared(res["shared"], show_targets=True, limit=15))
    else:
        res = correlate_targets(targets)
        header("Cross-target correlation", str(len(targets)) + " targets")

        if not res.get("target_ids"):
            c_warn("no targets found in graph")
            return

        section("Targets in graph")
        for t, tid in res["target_ids"].items():
            c_ok(t + "  (" + tid + ")")

        if res["shared_by_all"]:
            section("Shared by ALL (" + str(len(res["shared_by_all"])) + ")")
            for item in res["shared_by_all"][:30]:
                c_ok(item["kind"].ljust(16) + item["value"][:70])

        if res["shared_pairs"]:
            section("Shared by SOME (" + str(len(res["shared_pairs"])) + ")")
            for item in res["shared_pairs"][:40]:
                c_warn(item["kind"].ljust(16) +
                       item["value"][:50].ljust(50) +
                       "  " + str(item["count"]) + "/" + str(len(targets)))

        if not res["shared_by_all"] and not res["shared_pairs"]:
            c_info("no shared properties found")


def _run_domain_consensus(target):
    try:
        from astrym_domain import run_domain
        from astrym_consensus import aggregate_domain, render_consensus_domain
    except ImportError as e:
        c_err("domain-consensus: " + str(e)); return None
    d = run_domain(target)
    if not d:
        return None
    d["consensus"] = aggregate_domain(d)
    return d


def _run_clear_history(target=None):
    from astrym_core import (HISTORY_PATH, hist_all, c_ok, c_warn, c_info)
    import json
    try:
        before = len(hist_all())
    except Exception:
        before = 0
    try:
        HISTORY_PATH.write_text('{"entries": []}', encoding="utf-8")
        c_ok(f"history cleared ({before} → 0)")
        c_info("file: " + str(HISTORY_PATH))
        return {"meta": {"type": "clear-history", "target": "-",
                          "generated_at": __import__("astrym_core").now_iso(),
                          "tool": "ASTRYM"},
                "cleared": before}
    except Exception as e:
        from astrym_core import c_err
        c_err("cannot clear history: " + str(e))
        return None


def _run_clear_log(target=None):
    from astrym_core import (CONFIG_DIR, c_ok, c_warn, c_info, c_err)
    from pathlib import Path as _P
    killed = 0
    bytes_freed = 0

    # 1. errors.log
    err_log = CONFIG_DIR / "errors.log"
    if err_log.exists():
        try:
            sz = err_log.stat().st_size
            err_log.write_text("", encoding="utf-8")
            killed += 1
            bytes_freed += sz
        except Exception:
            pass

    # 2. alerts/*.log
    alerts_dir = CONFIG_DIR / "alerts"
    if alerts_dir.is_dir():
        for f in alerts_dir.glob("*.log"):
            try:
                sz = f.stat().st_size
                f.write_text("", encoding="utf-8")
                killed += 1
                bytes_freed += sz
            except Exception:
                pass

    # 3. любые *.log в config
    for f in CONFIG_DIR.glob("*.log"):
        if f.name == "errors.log":
            continue
        try:
            sz = f.stat().st_size
            f.write_text("", encoding="utf-8")
            killed += 1
            bytes_freed += sz
        except Exception:
            pass

    if killed == 0:
        c_warn("no log files found")
    else:
        kb = round(bytes_freed / 1024, 1)
        c_ok(f"cleared {killed} log file(s), freed {kb} KB")
    c_info("config dir: " + str(CONFIG_DIR))
    return {"meta": {"type": "clear-log", "target": "-",
                      "generated_at": __import__("astrym_core").now_iso(),
                      "tool": "ASTRYM"},
            "files_cleared": killed,
            "bytes_freed": bytes_freed}


def _run_clear_watches(target=None):
    from astrym_core import WATCH_DIR, c_ok, c_warn, c_info
    if not WATCH_DIR.is_dir():
        c_warn("no watches dir")
        return None
    n = 0
    for f in WATCH_DIR.glob("*.json"):
        try:
            f.unlink()
            n += 1
        except Exception:
            pass
    c_ok(f"removed {n} watch file(s)")
    c_info("dir: " + str(WATCH_DIR))
    return {"meta": {"type": "clear-watches", "target": "-",
                      "generated_at": __import__("astrym_core").now_iso(),
                      "tool": "ASTRYM"},
            "files_removed": n}


def _run_clear_results(target=None):
    from astrym_core import RESULTS_DIR, c_ok, c_warn, c_info
    import shutil as _sh
    if not RESULTS_DIR.is_dir():
        c_warn("no results dir")
        return None
    n = 0
    for kind_dir in RESULTS_DIR.iterdir():
        if not kind_dir.is_dir():
            continue
        for f in kind_dir.iterdir():
            if f.is_file():
                try:
                    f.unlink()
                    n += 1
                except Exception:
                    pass
    c_ok(f"removed {n} file(s) from results/")
    c_info("dir: " + str(RESULTS_DIR))
    return {"meta": {"type": "clear-results", "target": "-",
                      "generated_at": __import__("astrym_core").now_iso(),
                      "tool": "ASTRYM"},
            "files_removed": n}


def _cmd_community(args):
    if not _HAS_COMMUNITY:
        c_err("astrym_community module not available")
        return
    targets = args.get("targets", [])
    resolution = 1.0
    if targets:
        try:
            resolution = float(targets[0])
        except Exception:
            pass
    data = astrym_community.detect_communities(resolution=resolution)
    astrym_community.render_communities(data)


def _cmd_gexf(args):
    if not _HAS_COMMUNITY:
        c_err("astrym_community module not available")
        return
    targets = args.get("targets", [])
    if not targets:
        c_warn("usage: gexf <output.gexf>")
        return
    out = targets[0]
    p = astrym_community.export_gexf(out)
    if p:
        c_ok("GEXF -> " + str(p))
        c_info("открой в Gephi: File -> Open -> " + str(p))
    else:
        c_err("export failed (empty graph? networkx missing?)")


def _cmd_graph(targets):
    if not _HAS_GRAPH:
        c_err("graph module not available")
        return
    sub = targets[0].lower() if targets else "stats"

    if sub == "stats" or not targets:
        s = astrym_graph.stats()
        header("Graph stats", s.get("db_path", ""))
        section("Summary")
        kv([("nodes", s.get("nodes", 0)),
            ("edges", s.get("edges", 0)),
            ("scans", s.get("scans", 0))])
        if s.get("by_kind"):
            section("Nodes by kind")
            for row in s["by_kind"]:
                c_muted("  " + str(row["kind"]).ljust(20) + str(row["c"]))
        if s.get("top_targets"):
            section("Top targets")
            for row in s["top_targets"]:
                c_muted("  " + str(row["target"]).ljust(40) + str(row["c"]))
        return

    if sub == "targets":
        header("Targets in graph")
        rows = astrym_graph.all_targets()
        if not rows:
            c_warn("empty")
            return
        for row in rows:
            c_muted("  " + str(row.get("type", "?")).ljust(15) +
                    str(row.get("target", "?")))
        return

    if sub == "clear":
        c_warn("to clear graph, run: python3 astrym_graph.py clear")
        return

    c_warn("usage: graph [stats|targets]")


def _show_related_hint(target):
    from astrym_correlate import correlate_for_target
    res = correlate_for_target(target)
    n = res.get("total_related", 0)
    if n > 0:
        c_info("graph: " + str(n) + " related targets "
               "(run 'correlate " + target + "')")


# ============================================================
# WATCH
# ============================================================

def run_watch(target):
    k = classify(target)
    cmd = "check" if k in ("ip", "domain", "url") else k
    if cmd not in DISPATCH:
        c_err("cannot watch type: " + k)
        return
    data = DISPATCH[cmd](target, False)
    if not data:
        c_err("collection failed")
        return
    new = data if isinstance(data, dict) else (data[0] if data else None)
    if not new:
        c_err("no data")
        return
    old = watch_load(target)
    if old:
        diff = watch_diff(old, new)
        render_watch_diff(diff, target)
        watch_save(target, new)
        c_ok("updated: " + str(target))
    else:
        c_ok("first snapshot saved: " + str(target))
        watch_save(target, new)
        render_any(new)
    # add to graph
    if _HAS_GRAPH:
        try:
            m = new.get("meta", {})
            astrym_graph.add_scan(target, m.get("type", cmd), new)
        except Exception:
            pass


# ============================================================
# BATCH
# ============================================================

def run_batch(path):
    lines = batch_read(path)
    if lines is None:
        c_err("cannot read: " + path)
        return
    if not lines:
        c_warn("empty file")
        return
    c_info("batch: " + str(len(lines)) + " lines")
    for ln in lines:
        parts = ln.split()
        if len(parts) < 2:
            continue
        cmd = parts[0].lower()
        if cmd not in DISPATCH:
            c_warn("skip: " + ln)
            continue
        args = parse_cli_line(ln)
        if not args:
            continue
        try:
            run_once(args)
            c_ok(ln)
        except Exception as e:
            c_err(ln + ": " + str(e))


# ============================================================
# MENU
# ============================================================

MENU_TEXT = (
    "[accent]Core[/accent]\n"
    "  [accent]ip[/accent]              [muted]<addr>[/muted]       IP analysis\n"
    "  [accent]domain[/accent]          [muted]<domain>[/muted]     domain analysis\n"
    "  [accent]dns[/accent]             [muted]<domain>[/muted]     DNS records\n"
    "  [accent]sub[/accent]             [muted]<domain>[/muted]     subdomain enum\n"
    "  [accent]email[/accent]           [muted]<email>[/muted]      email + SMTP\n"
    "  [accent]check[/accent]           [muted]<target>[/muted]     threat intel\n"
    "  [accent]ssl[/accent]             [muted]<domain>[/muted]     SSL/TLS\n"
    "  [accent]scan[/accent]            [muted]<target>[/muted]     auto-detect\n"
    "\n"
    "[accent]Advanced[/accent]\n"
    "  [accent]web[/accent]             [muted]<domain>[/muted]     CMS + leaks\n"
    "  [accent]takeover[/accent]        [muted]<domain>[/muted]     subdomain takeover\n"
    "  [accent]leak[/accent]            [muted]<domain>[/muted]     GitHub leaks\n"
    "  [accent]origin[/accent]          [muted]<domain>[/muted]     origin IP behind CF\n"
    "  [accent]whois-history[/accent]   [muted]<domain>[/muted]     WHOIS timeline\n"
    "  [accent]darkweb[/accent]         [muted]<.onion>[/muted]     Tor crawl\n"
    "  [accent]phone[/accent]           [muted]<+num>[/muted]       phone OSINT\n"
    "\n"
    "[accent]Graph[/accent]\n"
    "  [accent]related[/accent]         [muted]<target> [depth][/muted]  related nodes\n"
    "  [accent]correlate[/accent]       [muted]<t1> [<t2>...][/muted]    shared infra\n"
    "  [accent]graph[/accent]           [muted][stats|targets][/muted]   graph info\n"
    "  [accent]community[/accent]       [muted][resolution][/muted]      Louvain communities\n"
    "  [accent]gexf[/accent]            [muted]<out.gexf>[/muted]        export to Gephi\n"
    "\n"
    "[accent]Advanced+[/accent]\n"
    "  [accent]asn[/accent]         [muted]<AS15169>[/muted]  ASN discovery\n"
    "  [accent]cname[/accent]       [muted]<domain>[/muted]   CNAME chain\n"
    "  [accent]username[/accent]    [muted]<name>[/muted]     username search\n"
    "  [accent]dork[/accent]        [muted]<target>[/muted]   Google dorks\n"
    "  [accent]ahmia[/accent]       [muted]<query>[/muted]    Ahmia .onion search\n"
    "\n"
    "[accent]Utility[/accent]\n"
    "  [accent]watch[/accent]           [muted]<target>[/muted]     snapshot + diff\n"
    "  [accent]batch[/accent]           [muted]<file>[/muted]       list from file\n"
    "  [accent]monitor[/accent]         [muted]<target> [--interval N] [--cycles M][/muted]\n"
    "  [accent]clear-history[/accent]   [muted]-[/muted]              очистить историю\n"
    "  [accent]clear-log[/accent]       [muted]-[/muted]              очистить логи алертов\n"
    "  [accent]clear-watches[/accent]   [muted]-[/muted]              очистить снапшоты watch\n"
    "  [accent]clear-results[/accent]   [muted]-[/muted]              очистить results/\n"
    "  [accent]timeline[/accent]        [muted]<target> [--since N][/muted]  измен. во времени\n"
    "  [accent]consensus[/accent]       [muted]<ip>[/muted]            multi-source voting\n"
    "  [accent]stix[/accent]            [muted]<target>[/muted]        STIX 2.1 bundle\n"
    "\n"
    "[accent2]flags:[/accent2]\n"
    "  [muted]-x[/muted]     extended sources (100+ OSINT)\n"
    "  [muted]-f[/muted]     console,json,html,csv,pdf,md,all\n"
    "  [muted]-w[/muted] N   workers (default 40)\n"
    "\n"
    "[accent2]menu:[/accent2] "
    "[muted]help selfcheck results history watches deps exit[/muted]"
)


def print_menu():
    _clear()
    print_banner()
    if HAS_RICH:
        try:
            from astrym_core import console as _c
            _c.print()
            _c.print(Panel(MENU_TEXT,
                           title="[accent]ASTRYM menu[/accent]",
                           border_style="medium_purple1",
                           box=ROUNDED, padding=(1, 2)))
        except Exception:
            print(MENU_TEXT)
    else:
        print(MENU_TEXT)


def _ask(p):
    try:
        return input(p).strip()
    except (EOFError, KeyboardInterrupt):
        return None


def _pause():
    _ask("\n[Enter] back: ")


# ============================================================
# COMMANDS
# ============================================================

def cmd_selfcheck():
    _clear()
    print_banner()
    header("Self-check")
    section("Python")
    import platform
    kv([("version", sys.version.split()[0]),
        ("platform", platform.platform())])

    section("Modules")
    for name, ok, hint in [
        ("dnspython", HAS_DNS, "pip install dnspython"),
        ("requests", HAS_REQUESTS, "pip install requests"),
        ("rich", HAS_RICH, "pip install rich"),
        ("reportlab", HAS_PDF, "pip install reportlab"),
        ("geoip2", HAS_GEOIP2, "optional"),
        ("phonenumbers", HAS_PN, "optional"),
    ]:
        if ok:
            c_ok(name)
        else:
            c_warn(name + " - " + hint)

    section("Graph")
    if _HAS_GRAPH:
        s = astrym_graph.stats()
        kv([("db", s.get("db_path", "?")),
            ("nodes", s.get("nodes", 0)),
            ("edges", s.get("edges", 0)),
            ("scans", s.get("scans", 0))])
    else:
        c_warn("graph module not available")

    section("Paths")
    kv([("base", str(BASE_DIR)),
        ("results", str(RESULTS_DIR)),
        ("config", str(CONFIG_PATH)),
        ("watches", str(WATCH_DIR)),
        ("geoip", str(GEOIP_DIR))])


def cmd_history():
    _clear()
    print_banner()
    header("History", "last 50")
    entries = hist_all()
    if not entries:
        c_muted("empty")
        return
    for e in reversed(entries[-50:]):
        c_muted("  " + e.get("at", "?")[:19] + "  " +
                e.get("kind", "?").ljust(14) + "  " +
                e.get("target", "?"))


def cmd_results():
    _clear()
    print_banner()
    header("Results", str(RESULTS_DIR))
    if not RESULTS_DIR.is_dir():
        c_warn("no results dir")
        return
    any_files = False
    for root in sorted(RESULTS_DIR.rglob("*")):
        if root.is_file():
            any_files = True
            try:
                rel = root.relative_to(RESULTS_DIR)
                c_muted("  " + str(rel) + "  (" +
                        str(root.stat().st_size) + " B)")
            except Exception:
                c_muted("  " + str(root))
    if not any_files:
        c_muted("empty")


def cmd_watches():
    _clear()
    print_banner()
    header("Watches")
    ws = watch_list()
    if not ws:
        c_muted("no watches")
        return
    for w in ws:
        c_muted("  " + w["name"].ljust(30) + " -> " +
                str(w.get("target")) + " (" + str(w.get("type")) + ")")


def cmd_graph_info():
    _clear()
    print_banner()
    if not _HAS_GRAPH:
        c_err("graph module not available")
        return
    _cmd_graph(["stats"])


# ============================================================
# INTERACTIVE LOOP
# ============================================================

def interactive_loop():
    print_menu()
    while True:
        line = _ask("\033[95mastrym>\033[0m ")
        if line is None:
            print()
            return
        if not line:
            continue
        low = line.lower()

        if low in ("exit", "quit", "q"):
            print("bye.")
            return
        if low in ("help", "?", "h", "menu"):
            print_menu()
            continue
        if low in ("selfcheck", "doctor"):
            cmd_selfcheck()
            _pause(); print_menu()
            continue
        if low in ("history", "hist"):
            cmd_history()
            _pause(); print_menu()
            continue
        if low in ("results", "ls"):
            cmd_results()
            _pause(); print_menu()
            continue
        if low in ("watches",):
            cmd_watches()
            _pause(); print_menu()
            continue
        if low in ("deps",):
            print_deps()
            _pause(); print_menu()
            continue
        if low in ("graph", "graph stats"):
            cmd_graph_info()
            _pause(); print_menu()
            continue
        if low.startswith("watch "):
            try:
                run_watch(line[6:].strip())
            except Exception as e:
                c_err(str(e))
            _pause(); print_menu()
            continue
        if low.startswith("batch "):
            try:
                run_batch(line[6:].strip())
            except Exception as e:
                c_err(str(e))
            _pause(); print_menu()
            continue
        if low.startswith("monitor ") and run_monitor_cli:
            try:
                run_monitor_cli(line[8:].strip())
            except KeyboardInterrupt:
                c_info("monitor stopped")
            except Exception as e:
                c_err(str(e))
            _pause(); print_menu()
            continue

        args = parse_cli_line(line)
        if not args:
            c_warn("unknown command. Type 'help'.")
            continue

        try:
            _clear()
            print_banner()
            run_once(args)
            print()
        except KeyboardInterrupt:
            print("\ninterrupted")
        except Exception as e:
            c_err("error: " + str(e))

        ans = _ask("\n[Enter] menu  [r] repeat  [q] quit: ")
        if ans is None or ans.lower() in ("q", "quit"):
            print("bye.")
            return
        if ans.lower() not in ("r", "repeat"):
            print_menu()


# ============================================================
# MAIN
# ============================================================

def main():
    if len(sys.argv) == 1:
        _clear()
        print_banner()
        if HAS_RICH:
            try:
                from astrym_core import console as _c
                _c.print()
                _c.print("  results: " + str(RESULTS_DIR))
                _c.print("  config:  " + str(CONFIG_PATH))
                if _HAS_GRAPH:
                    s = astrym_graph.stats()
                    _c.print("  graph:   " + str(s.get("nodes", 0)) +
                             " nodes, " + str(s.get("edges", 0)) +
                             " edges, " + str(s.get("scans", 0)) + " scans")
            except Exception:
                print("  results: " + str(RESULTS_DIR))
        else:
            print("  results: " + str(RESULTS_DIR))
            print("  config:  " + str(CONFIG_PATH))
        print_deps()
        _ask("\n  Press Enter to start... ")
        interactive_loop()
        return 0

    line = " ".join(sys.argv[1:])

    if line.startswith("watch "):
        run_watch(line[6:].strip())
        return 0
    if line.startswith("batch "):
        run_batch(line[6:].strip())
        return 0

    if line.startswith("monitor ") and run_monitor_cli:
        run_monitor_cli(line[8:].strip())
        return 0

    args = parse_cli_line(line)
    if not args:
        print("Usage: astrym.py <command> <target> [-x] [-f format]")
        print("Commands: " + ", ".join(sorted(list(DISPATCH.keys()) +
                                               ["related", "correlate",
                                                "graph"])))
        print("Formats:  console, json, html, csv, md, all")
        print("Extras:   -x, --extras (100+ OSINT sources)")
        return 1

    try:
        run_once(args)
    except KeyboardInterrupt:
        print("\ninterrupted")
        return 130
    except Exception as e:
        print("error: " + str(e))
        return 1
    return 0




# ============================================================
# ASTRYM ASCII graph renderers (override)
# ============================================================
try:
    from astrym_ascii import (render_related_ascii as _asc_rel,
                                render_correlate_ascii as _asc_cor,
                                render_communities_ascii as _asc_com,
                                run_tree as _asc_tree,
                                ascii_tree as _asc_asciitree)
    _HAS_ASCII = True
except ImportError as _e_ascii:
    sys.stderr.write("[astrym] ascii: " + str(_e_ascii) + "\n")
    _HAS_ASCII = False


def _cmd_related(targets):  # noqa: F811
    if not _HAS_GRAPH:
        c_err("graph module not available")
        return
    if not targets:
        c_warn("usage: related <target> [depth]")
        return
    target = targets[0]
    depth = 2
    if len(targets) > 1:
        try:
            depth = int(targets[1])
        except Exception:
            pass
    from astrym_graph import find_related_nodes
    res = find_related_nodes(target, max_depth=depth)
    if _HAS_ASCII:
        _asc_rel(res, target)
        return
    header("Related to " + target,
           str(len(res["nodes"])) + " nodes \u00b7 depth " + str(depth))
    if not res["nodes"]:
        c_warn("no related nodes found")
        return
    section("Nodes by depth")
    by_depth = {}
    for n in res["nodes"]:
        by_depth.setdefault(n.get("depth", 0), []).append(n)
    for d in sorted(by_depth.keys()):
        nodes = by_depth[d]
        c_info(f"depth {d}: {len(nodes)} nodes")
        for n in nodes[:30]:
            kind = n.get("kind", "?")
            nid = n.get("id", "?")
            value = nid.split(":", 1)[1] if ":" in nid else nid
            c_muted("  " + kind.ljust(16) + value[:70])


def _cmd_correlate(targets):  # noqa: F811
    if not _HAS_GRAPH:
        c_err("graph module not available")
        return
    if not targets:
        c_warn("usage: correlate <target> [<target2>...]")
        return
    from astrym_correlate import correlate_for_target, correlate_targets, format_shared
    if len(targets) == 1:
        target = targets[0]
        res = correlate_for_target(target)
        header("Correlate: " + target,
               str(res.get("total_related", 0)) + " related targets")
        if not res.get("target_id"):
            c_warn("target not in graph \u2014 run a scan first")
            return
        if not res.get("shared"):
            c_info("no shared infrastructure found")
            return
        section("Shared infrastructure")
        print(format_shared(res["shared"], show_targets=True, limit=15))
        return
    res = correlate_targets(targets)
    if _HAS_ASCII:
        _asc_cor(res)
        return
    header("Cross-target correlation", f"{len(targets)} targets")
    if not res.get("target_ids"):
        c_warn("no targets found in graph")
        return
    section("Targets in graph")
    for t, tid in res["target_ids"].items():
        c_ok(t + "  (" + tid + ")")
    if res["shared_by_all"]:
        section(f"Shared by ALL ({len(res['shared_by_all'])})")
        for item in res["shared_by_all"][:30]:
            c_ok(item["kind"].ljust(16) + item["value"][:70])
    if res["shared_pairs"]:
        section(f"Shared by SOME ({len(res['shared_pairs'])})")
        for item in res["shared_pairs"][:40]:
            c_warn(item["kind"].ljust(16) +
                    item["value"][:50].ljust(50) +
                    f"  {item['count']}/{len(targets)}")


def _cmd_community(args):  # noqa: F811
    if not _HAS_COMMUNITY:
        c_err("astrym_community module not available")
        return
    targets = args.get("targets", []) if isinstance(args, dict) else []
    resolution = 1.0
    if targets:
        try:
            resolution = float(targets[0])
        except Exception:
            pass
    data = astrym_community.detect_communities(resolution=resolution)
    if _HAS_ASCII:
        _asc_com(data)
    else:
        astrym_community.render_communities(data)


def _cmd_tree(args):  # ASTRYM ascii
    if not _HAS_ASCII:
        c_err("astrym_ascii module not available")
        return None
    targets = args.get("targets", []) if isinstance(args, dict) else []
    if not targets:
        c_warn("usage: tree <target> [depth]")
        return None
    target = targets[0]
    depth = 3
    if len(targets) > 1:
        try:
            depth = int(targets[1])
        except Exception:
            pass
    _asc_tree(target, depth=depth)
    return None


if _HAS_ASCII:
    try:
        DISPATCH["tree"] = (lambda t, e, **kw:
                              _cmd_tree({"targets": [t]}))
    except Exception:
        pass




# === ASTRYM clear commands (appended) ===
def _run_clear_history(target=None):
    from astrym_core import HISTORY_PATH, hist_all, c_ok, c_info, c_err
    try:
        before = len(hist_all())
    except Exception:
        before = 0
    try:
        HISTORY_PATH.write_text('{"entries": []}', encoding="utf-8")
        c_ok("history cleared (" + str(before) + " -> 0)")
        c_info("file: " + str(HISTORY_PATH))
        return {"meta": {"type": "clear-history", "target": "-",
                         "generated_at": __import__("astrym_core").now_iso(),
                         "tool": "ASTRYM"},
                "cleared": before}
    except Exception as e:
        c_err("cannot clear history: " + str(e))
        return None


def _run_clear_log(target=None):
    from astrym_core import CONFIG_DIR, c_ok, c_warn, c_info
    killed = 0
    bytes_freed = 0

    err_log = CONFIG_DIR / "errors.log"
    if err_log.exists():
        try:
            sz = err_log.stat().st_size
            err_log.write_text("", encoding="utf-8")
            killed += 1
            bytes_freed += sz
        except Exception:
            pass

    alerts_dir = CONFIG_DIR / "alerts"
    if alerts_dir.is_dir():
        for f in alerts_dir.glob("*.log"):
            try:
                sz = f.stat().st_size
                f.write_text("", encoding="utf-8")
                killed += 1
                bytes_freed += sz
            except Exception:
                pass

    for f in CONFIG_DIR.glob("*.log"):
        if f.name == "errors.log":
            continue
        try:
            sz = f.stat().st_size
            f.write_text("", encoding="utf-8")
            killed += 1
            bytes_freed += sz
        except Exception:
            pass

    if killed == 0:
        c_warn("no log files found")
    else:
        kb = round(bytes_freed / 1024, 1)
        c_ok("cleared " + str(killed) + " log file(s), freed " + str(kb) + " KB")
    c_info("config dir: " + str(CONFIG_DIR))
    return {"meta": {"type": "clear-log", "target": "-",
                     "generated_at": __import__("astrym_core").now_iso(),
                     "tool": "ASTRYM"},
            "files_cleared": killed,
            "bytes_freed": bytes_freed}


def _run_clear_watches(target=None):
    from astrym_core import WATCH_DIR, c_ok, c_warn, c_info
    if not WATCH_DIR.is_dir():
        c_warn("no watches dir")
        return None
    n = 0
    for f in WATCH_DIR.glob("*.json"):
        try:
            f.unlink()
            n += 1
        except Exception:
            pass
    c_ok("removed " + str(n) + " watch file(s)")
    c_info("dir: " + str(WATCH_DIR))
    return {"meta": {"type": "clear-watches", "target": "-",
                     "generated_at": __import__("astrym_core").now_iso(),
                     "tool": "ASTRYM"},
            "files_removed": n}


def _run_clear_results(target=None):
    from astrym_core import RESULTS_DIR, c_ok, c_warn, c_info
    if not RESULTS_DIR.is_dir():
        c_warn("no results dir")
        return None
    n = 0
    for kind_dir in RESULTS_DIR.iterdir():
        if not kind_dir.is_dir():
            continue
        for f in kind_dir.iterdir():
            if f.is_file():
                try:
                    f.unlink()
                    n += 1
                except Exception:
                    pass
    c_ok("removed " + str(n) + " file(s) from results/")
    c_info("dir: " + str(RESULTS_DIR))
    return {"meta": {"type": "clear-results", "target": "-",
                     "generated_at": __import__("astrym_core").now_iso(),
                     "tool": "ASTRYM"},
            "files_removed": n}


DISPATCH["clear-history"] = lambda t, e, **kw: _run_clear_history()
DISPATCH["clear-log"]     = lambda t, e, **kw: _run_clear_log()
DISPATCH["clear-watches"] = lambda t, e, **kw: _run_clear_watches()
DISPATCH["clear-results"] = lambda t, e, **kw: _run_clear_results()
# === end ASTRYM clear commands ===


if __name__ == "__main__":
    sys.exit(main())