#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# astrym_topology.py — ASTRYM v8.2 Cyber Topology (report style)

import os
import sys
import json

VERSION = ""

CDN_VIS = ("https://cdn.jsdelivr.net/npm/vis-network@9.1.6/"
           "standalone/umd/vis-network.min.js")

# ============================================================
# PALETTE — совпадает с HTML-отчётом astrym_output.py
# ============================================================

COLOR_BG       = "#000000"
COLOR_SURFACE  = "#080808"
COLOR_SURFACE2 = "#0f0f0f"
COLOR_BORDER   = "#2a2a2a"
COLOR_TEXT     = "#ffffff"
COLOR_MUTED    = "#888888"
COLOR_SOFT     = "#555555"
COLOR_ACCENT   = "#a855f7"

COLOR_OK       = "#4ade80"
COLOR_WARN     = "#fbbf24"
COLOR_ERR      = "#f87171"
COLOR_INFO     = "#7ecfff"
COLOR_STRING   = "#a8e6a0"
COLOR_NUM      = "#f0c674"
COLOR_BOOL     = "#f78c6c"

# Цвета узлов
NODE_TARGET    = COLOR_ACCENT          # target = purple
NODE_TARGET_M  = COLOR_WARN            # medium risk
NODE_TARGET_H  = COLOR_ERR             # high risk
NODE_SUB       = COLOR_INFO            # subdomain = cyan
NODE_IP        = COLOR_NUM             # IP = warm
NODE_META      = "#8b7bb8"             # meta = purple-muted
NODE_HIT       = COLOR_ERR             # threat hit = red
NODE_CLEAN     = COLOR_OK              # clean = green

EDGE_DEFAULT   = COLOR_BORDER
EDGE_HIGHLIGHT = COLOR_ACCENT


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASTRYM · __TARGET__</title>
<script src="__CDN__"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
    background: __BG__;
    color: __TEXT__;
    font-family: 'SF Mono', 'Menlo', 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    overflow: hidden;
    width: 100vw; height: 100vh;
}

/* ============ HEADER ============ */
#report-header {
    position: absolute;
    top: 20px; left: 24px;
    z-index: 10;
    max-width: 50vw;
    pointer-events: none;
}
#report-header h1 {
    color: __ACCENT__;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.3px;
    margin-bottom: 6px;
}
#report-header .target {
    color: __TEXT__;
    font-size: 18px;
    word-break: break-all;
    margin-bottom: 8px;
}
#report-header .tag {
    color: __MUTED__;
    font-size: 10px;
    letter-spacing: 3px;
    text-transform: uppercase;
}

/* ============ STATS ============ */
#stats {
    position: absolute;
    top: 20px; right: 24px;
    background: __SURFACE__;
    border: 1px solid __BORDER__;
    padding: 10px 16px;
    font-size: 11px;
    color: __MUTED__;
    z-index: 10;
    letter-spacing: 1px;
}
#stats b { color: __TEXT__; }

/* ============ LEGEND ============ */
#legend {
    position: absolute;
    bottom: 20px; left: 24px;
    background: __SURFACE__;
    border: 1px solid __BORDER__;
    padding: 14px 18px;
    font-size: 11px;
    z-index: 10;
    color: __MUTED__;
}
#legend .row {
    display: flex; align-items: center;
    margin: 4px 0; letter-spacing: 1px;
}
#legend .dot {
    width: 10px; height: 10px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 10px;
    border: 1px solid __BORDER__;
}

/* ============ DETAILS PANEL ============ */
#details-panel {
    position: absolute;
    top: 20px; right: 24px;
    width: 380px;
    max-height: calc(100vh - 40px);
    background: __SURFACE__;
    border: 1px solid __BORDER__;
    padding: 20px;
    overflow-y: auto;
    display: none;
    z-index: 20;
}
#details-panel .panel-header {
    display: flex; justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid __BORDER__;
}
#panel-title {
    color: __ACCENT__;
    font-size: 13px;
    letter-spacing: 2px;
    text-transform: uppercase;
    font-weight: 700;
    word-break: break-all;
    padding-right: 20px;
}
#close-btn {
    color: __MUTED__;
    cursor: pointer;
    background: none;
    border: none;
    font-size: 20px;
    font-family: monospace;
    line-height: 1;
    padding: 0;
}
#close-btn:hover { color: __TEXT__; }

.node-info {
    font-size: 12px;
    line-height: 1.6;
    color: __TEXT__;
}
.node-info b { color: __ACCENT__; font-weight: 600; }

.kv-table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0;
}
.kv-table td {
    padding: 8px 0;
    border-bottom: 1px dashed __BORDER__;
    vertical-align: top;
    font-size: 11px;
}
.kv-table tr:last-child td { border-bottom: none; }
.kv-table td:first-child {
    color: __MUTED__;
    width: 38%;
    letter-spacing: 1px;
    text-transform: uppercase;
}
.kv-table td:last-child {
    color: __TEXT__;
    word-break: break-all;
}

pre.raw {
    background: __BG__;
    border: 1px solid __BORDER__;
    padding: 12px;
    font-family: 'SF Mono', 'Menlo', 'Consolas', monospace;
    font-size: 11px;
    color: __TEXT__;
    overflow-x: auto;
    line-height: 1.5;
    margin-top: 10px;
    max-height: 350px;
}
pre.raw .jk { color: __INFO__; }
pre.raw .js { color: __STRING__; }
pre.raw .jn { color: __NUM__; }
pre.raw .jb { color: __BOOL__; }

.raw-label {
    color: __MUTED__;
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-top: 16px;
    margin-bottom: 4px;
    display: block;
}

/* ============ GRAPH ============ */
#network-graph {
    width: 100vw;
    height: 100vh;
    background: __BG__;
}

/* ============ SCROLLBAR ============ */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: __BG__; }
::-webkit-scrollbar-thumb {
    background: __BORDER__;
    border-radius: 0;
}
::-webkit-scrollbar-thumb:hover { background: __ACCENT__; }
</style>
</head>
<body>

<div id="report-header">
    <h1>OSINT Report:</h1>
    <div class="target">__TARGET__</div>
    <div class="tag">__TYPE__ · TOPOLOGY · ASTRYM v__VERSION__</div>
</div>

<div id="stats">
    <b id="node-count">0</b> NODES &nbsp;&middot;&nbsp; <b id="edge-count">0</b> EDGES
    &nbsp;&middot;&nbsp; RISK <b id="risk-badge">-</b>
</div>

<div id="legend">
    <div class="row"><span class="dot" style="background:__ACCENT__"></span>target</div>
    <div class="row"><span class="dot" style="background:__INFO__"></span>subdomain</div>
    <div class="row"><span class="dot" style="background:__NUM__"></span>IP address</div>
    <div class="row"><span class="dot" style="background:#8b7bb8"></span>meta (WHOIS, MX, NS)</div>
    <div class="row"><span class="dot" style="background:__OK__"></span>clean</div>
    <div class="row"><span class="dot" style="background:__ERR__"></span>threat / breach</div>
</div>

<div id="details-panel">
    <div class="panel-header">
        <div id="panel-title">Node</div>
        <button id="close-btn" onclick="document.getElementById('details-panel').style.display='none'">&times;</button>
    </div>
    <div id="panel-content" class="node-info">
        Click a node on the graph to inspect.
    </div>
</div>

<div id="network-graph"></div>

<script id="data-nodes" type="application/json">__NODES__</script>
<script id="data-edges" type="application/json">__EDGES__</script>
<script>
(function () {
    var nodesData = JSON.parse(document.getElementById('data-nodes').textContent);
    var edgesData = JSON.parse(document.getElementById('data-edges').textContent);

    document.getElementById('node-count').innerText = nodesData.length;
    document.getElementById('edge-count').innerText = edgesData.length;

    var target = nodesData.find(function (n) { return n.group === 'target'; });
    if (target && target.risk_level) {
        var badge = document.getElementById('risk-badge');
        badge.innerText = (target.risk_level || '-').toUpperCase();
        if (target.risk_level === 'CRITICAL' || target.risk_level === 'HIGH') {
            badge.style.color = '__ERR__';
        } else if (target.risk_level === 'MEDIUM') {
            badge.style.color = '__WARN__';
        } else if (target.risk_level === 'LOW' || target.risk_level === 'CLEAN') {
            badge.style.color = '__OK__';
        }
    }

    if (typeof vis === 'undefined') {
        document.body.innerHTML =
            '<div style="color:__ERR__;padding:40px;font-family:monospace;font-size:14px">' +
            'ERROR: vis-network not loaded.<br>' +
            'Check internet or download CDN locally.<br><br>' +
            'CDN: __CDN__</div>';
        return;
    }

    var container = document.getElementById('network-graph');
    var data = {
        nodes: new vis.DataSet(nodesData),
        edges: new vis.DataSet(edgesData)
    };

    var options = {
        nodes: {
            shape: 'dot',
            font: {
                color: '__TEXT__',
                size: 12,
                face: 'Menlo, Consolas, monospace',
                strokeWidth: 3,
                strokeColor: '__BG__',
                vadjust: -2
            },
            borderWidth: 1,
            borderWidthSelected: 2,
            shadow: {
                enabled: true,
                color: 'rgba(168, 85, 247, 0.18)',
                size: 8,
                x: 0, y: 0
            },
            chosen: true
        },
        edges: {
            color: {
                color: '__EDGE__',
                highlight: '__ACCENT__',
                hover: '__ACCENT__',
                opacity: 1.0
            },
            width: 1,
            selectionWidth: 2,
            arrows: {
                to: { enabled: true, scaleFactor: 0.45 }
            },
            smooth: { enabled: true, type: 'continuous', roundness: 0.5 },
            font: {
                color: '__MUTED__',
                size: 9,
                face: 'Menlo, monospace',
                strokeWidth: 3,
                strokeColor: '__BG__',
                align: 'middle'
            }
        },
        physics: {
            solver: 'forceAtlas2Based',
            forceAtlas2Based: {
                gravitationalConstant: -38,
                centralGravity: 0.006,
                springLength: 110,
                springConstant: 0.14,
                damping: 0.65
            },
            stabilization: { iterations: 200, fit: true },
            minVelocity: 0.5
        },
        interaction: {
            hover: true,
            tooltipDelay: 150,
            navigationButtons: false,
            keyboard: { enabled: true, bindToWindow: true },
            multiselect: false,
            zoomView: true,
            dragView: true
        },
        layout: {
            improvedLayout: true,
            randomSeed: 42
        }
    };

    var network = new vis.Network(container, data, options);

    network.on('click', function (params) {
        if (params.nodes.length === 0) {
            document.getElementById('details-panel').style.display = 'none';
            return;
        }
        var nodeId = params.nodes[0];
        var node = nodesData.find(function (n) { return n.id === nodeId; });
        if (!node) return;

        document.getElementById('details-panel').style.display = 'block';
        document.getElementById('panel-title').innerText = node.label || nodeId;

        var content = document.getElementById('panel-content');
        var html = '';

        // Основная информация
        if (node.title) {
            html += '<div>' + node.title + '</div>';
        }

        // Мета-информация по типу
        if (node.meta && Object.keys(node.meta).length > 0) {
            html += '<table class="kv-table">';
            var keys = Object.keys(node.meta).slice(0, 15);
            keys.forEach(function (k) {
                var v = node.meta[k];
                if (v === null || v === undefined || v === '') return;
                if (typeof v === 'object') v = JSON.stringify(v);
                v = String(v).slice(0, 120);
                html += '<tr><td>' + escapeHtml(k) + '</td><td>' +
                        escapeHtml(v) + '</td></tr>';
            });
            html += '</table>';
        }

        // Raw JSON
        if (node.raw && Object.keys(node.raw).length > 0) {
            var rawStr = JSON.stringify(node.raw, null, 2);
            if (rawStr.length > 6000) rawStr = rawStr.slice(0, 6000) + '\n...';
            html += '<span class="raw-label">Raw JSON</span>';
            html += '<pre class="raw">' + highlightJson(rawStr) + '</pre>';
        }

        content.innerHTML = html || '<div class="muted">No data</div>';
    });

    network.on('hoverNode', function () {
        container.style.cursor = 'pointer';
    });
    network.on('blurNode', function () {
        container.style.cursor = 'default';
    });

    // ===== helpers =====
    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function highlightJson(txt) {
        var esc = escapeHtml(txt);
        // keys
        esc = esc.replace(/"([^"]+)"(\s*:)/g,
            '<span class="jk">"$1"</span>$2');
        // strings
        esc = esc.replace(/:\s*"([^"]*)"/g,
            ': <span class="js">"$1"</span>');
        // numbers
        esc = esc.replace(/:\s*(-?\d+\.?\d*)/g,
            ': <span class="jn">$1</span>');
        // bools
        esc = esc.replace(/:\s*(true|false|null)/g,
            ': <span class="jb">$1</span>');
        return esc;
    }

    // Auto-fit через 300 мс после старта
    setTimeout(function () { network.fit({ animation: true }); }, 400);
})();
</script>
</body>
</html>
"""


def _safe_json(obj):
    s = json.dumps(obj, ensure_ascii=False, default=str)
    # защита от `</script>` в поддоменах
    return s.replace("</", "<\\/")


# ============================================================
# GRAPH BUILDER
# ============================================================

def _build_graph(data):
    nodes = []
    edges = []
    seen = set()

    def add_node(nid, label, group, color, title, size=15,
                 raw=None, meta=None, risk_level=None):
        nid = str(nid)
        if nid in seen:
            return
        seen.add(nid)
        node = {
            "id": nid,
            "label": str(label)[:60],
            "group": group,
            "color": {
                "background": color,
                "border": "#2a2a2a",
                "highlight": {"background": color, "border": "#a855f7"}
            },
            "size": size,
            "title": title or label,
            "raw": raw if raw is not None else {},
            "meta": meta if meta is not None else {},
        }
        if risk_level:
            node["risk_level"] = risk_level
        nodes.append(node)

    def add_edge(a, b, label=None, color=None):
        a, b = str(a), str(b)
        if a not in seen or b not in seen:
            return
        e = {"from": a, "to": b}
        if label:
            e["label"] = str(label)[:20]
        if color:
            e["color"] = {
                "color": color,
                "highlight": "#a855f7",
                "hover": "#a855f7"
            }
        edges.append(e)

    # ---- meta / risk ----
    meta = data.get("meta", {}) or {}
    t_type = meta.get("type", "unknown")
    target = meta.get("target", "unknown")
    detected = meta.get("detected_kind", t_type)
    if t_type == "scan" and detected:
        t_type = detected

    risk = data.get("risk") or (data.get("security") or {}).get("risk") or {}
    if not isinstance(risk, dict):
        risk = {}
    risk_score = int(risk.get("score", 0) or 0)
    risk_level = risk.get("level", "?")

    if risk_score >= 70:
        tcolor = COLOR_ERR
    elif risk_score >= 40:
        tcolor = COLOR_ERR
    elif risk_score >= 15:
        tcolor = COLOR_WARN
    else:
        tcolor = COLOR_ACCENT

    # target
    title_t = "<b>Target:</b> " + str(target) + "<br><b>Type:</b> " + str(t_type)
    if risk_score > 0 or risk_level not in ("?", "CLEAN"):
        title_t += ("<br><b>Risk:</b> " + str(risk_score) + "/100 (" +
                    str(risk_level) + ")")

    add_node("target", target, "target", tcolor, title_t,
             size=30, raw=meta,
             meta={"target": target, "type": t_type,
                   "risk_score": risk_score, "risk_level": risk_level},
             risk_level=risk_level)

    # ---- DNS ----
    dns_rec = data.get("dns") or data.get("records") or {}
    if isinstance(dns_rec, dict):
        for rt in ("A", "AAAA"):
            for ip in dns_rec.get(rt, []) or []:
                ip_clean = str(ip).strip()
                nid = "ip:" + ip_clean
                add_node(nid, ip_clean, "ip", COLOR_NUM,
                         "<b>IP</b> (" + rt + "): " + ip_clean,
                         raw={"type": rt, "value": ip_clean},
                         meta={"ip": ip_clean, "record_type": rt})
                add_edge("target", nid, rt, COLOR_NUM)

        for mx in dns_rec.get("MX", []) or []:
            parts = str(mx).split()
            host = parts[-1].rstrip(".") if parts else str(mx)
            pref = parts[0] if len(parts) > 1 else ""
            nid = "mx:" + host
            add_node(nid, host[:40], "meta", NODE_META,
                     "<b>MX</b> priority=" + pref + " " + host,
                     raw={"priority": pref, "host": host},
                     meta={"priority": pref, "host": host})
            add_edge("target", nid, "MX", NODE_META)

        for ns in dns_rec.get("NS", []) or []:
            ns_clean = str(ns).rstrip(".")
            nid = "ns:" + ns_clean
            add_node(nid, ns_clean[:40], "meta", NODE_META,
                     "<b>NS:</b> " + ns_clean,
                     raw={"ns": ns_clean},
                     meta={"ns": ns_clean})
            add_edge("target", nid, "NS", NODE_META)

        for txt in dns_rec.get("TXT", []) or []:
            txt_str = str(txt)[:200]
            low = txt_str.lower()
            kind = "TXT"
            if low.startswith("v=spf1"):
                kind = "SPF"
            elif "v=dmarc1" in low:
                kind = "DMARC"
            elif "v=dkim1" in low:
                kind = "DKIM"
            elif "google-site-verification" in low:
                kind = "GVerify"
            nid = "txt:" + kind + ":" + str(abs(hash(txt_str)))[:8]
            add_node(nid, kind + ": " + txt_str[:28],
                     "meta", NODE_META,
                     "<b>" + kind + "</b><br>" + txt_str,
                     raw={"text": txt_str},
                     meta={"kind": kind, "value": txt_str[:120]})
            add_edge("target", nid, kind, NODE_META)

    # ---- email_security ----
    es = data.get("email_security") or {}
    if isinstance(es, dict):
        if es.get("spf"):
            add_node("spf", "SPF", "meta", NODE_META,
                     "<b>SPF:</b> " + str(es["spf"])[:150],
                     raw={"spf": es["spf"]},
                     meta={"spf": str(es["spf"])[:120]})
            add_edge("target", "spf", "SPF", NODE_META)
        if es.get("dmarc"):
            add_node("dmarc", "DMARC", "meta", NODE_META,
                     "<b>DMARC:</b> " + str(es["dmarc"])[:150],
                     raw={"dmarc": es["dmarc"]},
                     meta={"dmarc": str(es["dmarc"])[:120]})
            add_edge("target", "dmarc", "DMARC", NODE_META)
        for i, dk in enumerate((es.get("dkim") or [])[:3]):
            if isinstance(dk, dict):
                nid = "dkim:" + str(dk.get("selector", i))
                add_node(nid, "DKIM/" + str(dk.get("selector", "?")),
                         "meta", NODE_META,
                         "<b>DKIM</b> selector: " + str(dk.get("selector")),
                         raw=dk,
                         meta={"selector": dk.get("selector")})
                add_edge("target", nid, "DKIM", NODE_META)

    # ---- subdomains_ct ----
    for s in (data.get("subdomains_ct") or [])[:200]:
        s_clean = str(s).strip().lower()
        if not s_clean:
            continue
        nid = "sub:" + s_clean
        add_node(nid, s_clean[:50], "subdomain", NODE_SUB,
                 "<b>Subdomain (CT)</b><br>" + s_clean,
                 raw={"host": s_clean, "source": "ct"},
                 meta={"host": s_clean, "source": "ct"})
        add_edge("target", nid, "CT", NODE_SUB)

    # ---- subdomains (sub scan) ----
    for x in (data.get("subdomains") or [])[:300]:
        if not isinstance(x, dict):
            continue
        host = str(x.get("host", "")).strip().lower()
        if not host:
            continue
        nid = "sub:" + host
        sources = x.get("sources", [])
        add_node(nid, host[:50], "subdomain", NODE_SUB,
                 "<b>Subdomain</b><br>" + host +
                 "<br>Sources: " + ",".join(str(s) for s in sources),
                 raw=x,
                 meta={"host": host, "sources": ",".join(str(s) for s in sources)})
        add_edge("target", nid, ",".join(str(s) for s in sources[:2]), NODE_SUB)
        for ip in (x.get("ips") or [])[:5]:
            ip_clean = str(ip).strip()
            ip_nid = "ip:" + ip_clean
            add_node(ip_nid, ip_clean, "ip", COLOR_NUM,
                     "<b>IP:</b> " + ip_clean,
                     raw={"ip": ip_clean},
                     meta={"ip": ip_clean})
            add_edge(nid, ip_nid, "A", COLOR_NUM)

    # ---- extended ----
    extended = data.get("extended") or {}
    if isinstance(extended, dict):
        for src_name, subs_list in extended.items():
            if not isinstance(subs_list, list):
                continue
            for s in subs_list[:150]:
                if not isinstance(s, str):
                    continue
                s_clean = s.strip().lower()
                if not s_clean or len(s_clean) < 3:
                    continue
                nid = "sub:" + s_clean
                if nid not in seen:
                    add_node(nid, s_clean[:50], "subdomain", NODE_SUB,
                             "<b>Subdomain</b> (" + src_name + ")<br>" + s_clean,
                             raw={"host": s_clean, "source": src_name},
                             meta={"host": s_clean, "source": src_name})
                    add_edge("target", nid, src_name[:10], NODE_SUB)

    # ---- geo ----
    geo = data.get("geo") or {}
    if isinstance(geo, dict) and "country" in geo:
        cc = str(geo.get("country", "?"))
        isp = str(geo.get("isp", "?"))
        asn = str(geo.get("as", "?"))
        add_node("geo", cc, "meta", NODE_META,
                 "<b>Geo</b><br>Country: " + cc +
                 "<br>ISP: " + isp + "<br>ASN: " + asn,
                 raw=geo,
                 meta={"country": cc, "isp": isp, "asn": asn})
        add_edge("target", "geo", "geo", NODE_META)
        if isp and isp != "?":
            add_node("org:" + isp[:40], isp[:40], "meta", NODE_META,
                     "<b>ISP:</b> " + isp,
                     raw={"isp": isp},
                     meta={"isp": isp})
            add_edge("target", "org:" + isp[:40], "ISP", NODE_META)

    # ---- whois ----
    whois = data.get("whois") or {}
    if isinstance(whois, dict) and whois:
        registrar = whois.get("registrar", "?")
        created = whois.get("creation date") or whois.get("created", "?")
        expires = whois.get("expiry") or whois.get("expiration", "?")
        add_node("whois", "WHOIS", "meta", NODE_META,
                 "<b>WHOIS</b><br>Registrar: " + str(registrar)[:60] +
                 "<br>Created: " + str(created)[:20] +
                 "<br>Expires: " + str(expires)[:20],
                 raw=whois,
                 meta={"registrar": str(registrar)[:60],
                       "created": str(created)[:20],
                       "expires": str(expires)[:20]})
        add_edge("target", "whois", "WHOIS", NODE_META)

    # ---- ssl ----
    if t_type == "ssl" or data.get("protocol"):
        proto = data.get("protocol", "?")
        days = data.get("days_valid")
        add_node("ssl", "SSL", "meta", NODE_META,
                 "<b>SSL/TLS</b><br>Protocol: " + str(proto) +
                 "<br>Days valid: " + str(days),
                 raw={"protocol": proto, "days_valid": days},
                 meta={"protocol": proto, "days_valid": days})
        add_edge("target", "ssl", "SSL", NODE_META)

    # ---- email ----
    if t_type == "email":
        ov = data.get("overview") or {}
        prov = ov.get("provider") or "?"
        add_node("provider", str(prov)[:40], "meta", NODE_META,
                 "<b>Provider:</b> " + str(prov),
                 raw=ov,
                 meta={"provider": prov,
                       "disposable": ov.get("disposable")})
        add_edge("target", "provider", "provider", NODE_META)

        smtp = data.get("smtp") or {}
        if smtp:
            status = smtp.get("status", "?")
            color = {"valid": COLOR_OK,
                     "invalid": COLOR_ERR}.get(status, COLOR_WARN)
            add_node("smtp", "SMTP: " + status, "meta", color,
                     "<b>SMTP</b><br>Status: " + status +
                     "<br>Code: " + str(smtp.get("code")),
                     raw=smtp,
                     meta={"status": status,
                           "code": smtp.get("code"),
                           "mx_used": smtp.get("mx_used")})
            add_edge("target", "smtp", "SMTP", color)

        for mx in (data.get("mx") or [])[:10]:
            mx_s = str(mx)
            add_node("mx:" + mx_s, mx_s[:40], "meta", NODE_META,
                     "<b>MX:</b> " + mx_s,
                     raw={"mx": mx_s},
                     meta={"mx": mx_s})
            add_edge("target", "mx:" + mx_s, "MX", NODE_META)

        h = data.get("hibp") or {}
        if h.get("found") is True:
            n = len(h.get("breaches", []))
            add_node("hibp", "BREACHED×" + str(n), "meta", COLOR_ERR,
                     "<b>HIBP:</b> " + str(n) + " breaches",
                     raw={"count": n, "breaches": h.get("breaches", [])[:5]},
                     meta={"breaches": n})
            add_edge("target", "hibp", "HIBP", COLOR_ERR)

        g = data.get("gravatar") or {}
        if g.get("found") is True:
            add_node("gravatar", "Gravatar", "meta", COLOR_OK,
                     "<b>Gravatar</b><br>" + str(g.get("url", "")),
                     raw=g,
                     meta={"url": g.get("url")})
            add_edge("target", "gravatar", "gravatar", COLOR_OK)

    # ---- check ----
    if t_type == "check":
        results = data.get("results") or {}
        for src_name, res in results.items():
            if not isinstance(res, dict):
                continue
            found = res.get("found")
            if res.get("error"):
                color = COLOR_SOFT
                label = src_name + ": err"
            elif found is True:
                color = COLOR_ERR
                label = src_name + ": HIT"
            else:
                color = COLOR_OK
                label = src_name + ": clean"
            add_node("src:" + src_name, label, "meta", color,
                     "<b>" + src_name + "</b><br>" + str(res)[:200],
                     raw=res,
                     meta={k: res.get(k) for k in
                           ("found", "malicious", "suspicious",
                            "error", "ioc_count", "url_count")})
            add_edge("target", "src:" + src_name, "", color)

    # ---- ip: ports ----
    if t_type == "ip":
        idb = None
        ext = data.get("extended")
        if isinstance(ext, dict):
            idb = ext.get("shodan_internetdb")
        if isinstance(idb, dict) and idb.get("ports"):
            for port in idb["ports"][:10]:
                nid = "port:" + str(port)
                add_node(nid, ":" + str(port), "ip", COLOR_NUM,
                         "<b>Open port</b>: " + str(port),
                         raw={"port": port},
                         meta={"port": port})
                add_edge("target", nid, "port", COLOR_NUM)

    # ---- web: leaks ----
    if t_type == "web":
        for i, leak in enumerate((data.get("leaks") or [])[:15]):
            if not isinstance(leak, dict):
                continue
            path = leak.get("path", "?")
            status = leak.get("status", "?")
            color = COLOR_ERR if status == 200 else COLOR_WARN
            add_node("leak:" + str(i), path[:30], "ip", color,
                     "<b>Exposed:</b> " + path +
                     " (HTTP " + str(status) + ")",
                     raw=leak,
                     meta={"path": path, "status": status,
                           "what": leak.get("what")})
            add_edge("target", "leak:" + str(i), str(status), color)

    # ---- takeover ----
    if t_type == "takeover":
        for i, v in enumerate((data.get("vulnerable") or [])[:30]):
            if not isinstance(v, dict):
                continue
            sub = v.get("subdomain", "?")
            svc = v.get("service", "?")
            add_node("vuln:" + str(i), sub[:40], "ip", COLOR_ERR,
                     "<b>VULNERABLE:</b> " + sub + " → " + svc,
                     raw=v,
                     meta={"subdomain": sub, "service": svc,
                           "cname": v.get("cname")})
            add_edge("target", "vuln:" + str(i), svc[:15], COLOR_ERR)

    # ---- origin ----
    if t_type == "origin":
        for i, ip in enumerate((data.get("candidates") or [])[:30]):
            add_node("origin:" + str(i), str(ip), "ip", COLOR_NUM,
                     "<b>Origin IP:</b> " + str(ip),
                     raw={"ip": ip},
                     meta={"ip": ip})
            add_edge("target", "origin:" + str(i), "origin", COLOR_NUM)

    return nodes, edges


# ============================================================
# BUILD HTML
# ============================================================

def build_topology(results, output_path):
    if isinstance(results, dict):
        results = [results]
    if not results:
        print("[-] No results")
        return None
    # ASTRYM 9.1.2 — диагностика
    if not results:
        print("[-] build_topology: empty results")
        return None
    print("[topology] results type: " + type(results).__name__)
    if isinstance(results, list):
        print("[topology] results len: " + str(len(results)))
        if results:
            print("[topology] first item keys: " +
                  ", ".join(list(results[0].keys())[:10])
                  if isinstance(results[0], dict) else "not a dict")
    elif isinstance(results, dict):
        print("[topology] results keys: " +
              ", ".join(list(results.keys())[:10]))


    data = results[0]
    nodes, edges = _build_graph(data)
    print("[topology] graph built: nodes=" +
          str(len(nodes)) + " edges=" + str(len(edges)))

    if not nodes:
        print("[-] No nodes")
        return None

    meta = data.get("meta") or {}
    target = str(meta.get("target", "unknown"))
    t_type = str(meta.get("type", "unknown"))

    html_out = HTML_TEMPLATE
    html_out = html_out.replace("__CDN__", CDN_VIS)
    html_out = html_out.replace("__NODES__", _safe_json(nodes))
    html_out = html_out.replace("__EDGES__", _safe_json(edges))
    html_out = html_out.replace("__TARGET__", target.replace("<", "&lt;"))
    html_out = html_out.replace("__TYPE__", t_type.upper())
    html_out = html_out.replace("__VERSION__", "")

    # палитра
    html_out = html_out.replace("__BG__", COLOR_BG)
    html_out = html_out.replace("__SURFACE__", COLOR_SURFACE)
    html_out = html_out.replace("__SURFACE2__", COLOR_SURFACE2)
    html_out = html_out.replace("__BORDER__", COLOR_BORDER)
    html_out = html_out.replace("__EDGE__", EDGE_DEFAULT)
    html_out = html_out.replace("__TEXT__", COLOR_TEXT)
    html_out = html_out.replace("__MUTED__", COLOR_MUTED)
    html_out = html_out.replace("__SOFT__", COLOR_SOFT)
    html_out = html_out.replace("__ACCENT__", COLOR_ACCENT)
    html_out = html_out.replace("__OK__", COLOR_OK)
    html_out = html_out.replace("__WARN__", COLOR_WARN)
    html_out = html_out.replace("__ERR__", COLOR_ERR)
    html_out = html_out.replace("__INFO__", COLOR_INFO)
    html_out = html_out.replace("__STRING__", COLOR_STRING)
    html_out = html_out.replace("__NUM__", COLOR_NUM)
    html_out = html_out.replace("__BOOL__", COLOR_BOOL)

    try:
        d = os.path.dirname(os.path.abspath(output_path))
        if d:
            os.makedirs(d, exist_ok=True)
    except Exception:
        pass

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_out)
        print("[+] Topology: " + str(len(nodes)) + " nodes, " +
              str(len(edges)) + " edges -> " + output_path)
        return output_path
    except Exception as e:
        print("[-] Cannot write HTML: " + str(e))
        return None


# ============================================================
# CLI
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 astrym_topology.py report.json [out.html]")
        return 1
    json_path = sys.argv[1]
    if not os.path.exists(json_path):
        print("[-] Not found: " + json_path)
        return 1
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        results = data["results"]
    else:
        results = data
    out = sys.argv[2] if len(sys.argv) > 2 else \
        os.path.splitext(json_path)[0] + "_topology.html"
    build_topology(results, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())