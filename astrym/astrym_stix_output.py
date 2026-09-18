#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM STIX Output 9.9.1 — рендер STIX bundle во все форматы

STIX_OUTPUT_VERSION = ""

import csv
import json
import html as _html
from pathlib import Path

from astrym_core import (RESULTS_DIR, now_iso, HAS_PDF,
                          c_ok, c_warn, c_err, c_info, c_muted)

try:
    from astrym_output import auto_path
except Exception:
    def auto_path(kind):
        d = RESULTS_DIR / kind
        d.mkdir(parents=True, exist_ok=True)
        return d / (kind + "1")


# ============================================================
# HELPERS
# ============================================================

def _extract_bundle(result):
    if not isinstance(result, dict):
        return None, "?"
    meta = result.get("meta") or {}
    target = meta.get("target", "unknown")
    bundle = result.get("bundle")
    if not isinstance(bundle, dict):
        return None, target
    return bundle, target


def _count_by_type(objects):
    c = {}
    for o in objects or []:
        t = o.get("type", "?")
        c[t] = c.get(t, 0) + 1
    return c


def _obj_value(o):
    """Человеческое значение объекта для CSV/таблиц."""
    t = o.get("type")
    if t in ("domain-name", "ipv4-addr", "ipv6-addr", "email-addr", "url"):
        return o.get("value", "")
    if t == "autonomous-system":
        return "AS" + str(o.get("number", "?"))
    if t == "indicator":
        return o.get("pattern", "")
    if t == "identity":
        return o.get("name", "")
    if t == "relationship":
        return o.get("relationship_type", "")
    if t == "observed-data":
        return str(len(o.get("object_refs") or [])) + " refs"
    return ""


def _short_id(s):
    s = str(s or "")
    if "--" in s:
        return s.split("--", 1)[0] + "--" + s.split("--", 1)[1][:8]
    return s[:20]


def _esc(v):
    if v is None:
        return ""
    return (_html.escape(str(v))
            .replace("\n", " "))


def _md_escape(s):
    if s is None:
        return ""
    return (str(s).replace("|", "\\|").replace("\n", " "))


# ============================================================
# JSON
# ============================================================

def save_stix_json(bundle, base):
    try:
        p = Path(str(base) + ".json")
        p.write_text(json.dumps(bundle, indent=2, ensure_ascii=False),
                     encoding="utf-8")
        c_ok("STIX JSON -> " + str(p))
        return p
    except Exception as e:
        c_err("STIX JSON: " + str(e))
        return None


# ============================================================
# HTML
# ============================================================

_HTML_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:#000;color:#fff}
body{font-family:'SF Mono','Menlo','Consolas',monospace;font-size:13px;
line-height:1.55;padding:32px 16px}
.wrap{max-width:960px;margin:0 auto}
h1{font-size:24px;color:#a855f7;margin-bottom:6px}
h2{font-size:17px;color:#a855f7;margin-top:24px;padding-bottom:6px;
border-bottom:1px solid #2a2a2a}
.target{font-size:20px;color:#fff;margin-bottom:8px;word-break:break-all}
.tag{font-size:11px;color:#777;letter-spacing:3px;text-transform:uppercase}
.card{border:1px solid #2a2a2a;background:#080808;margin:14px 0;
padding:16px 20px}
.ct{font-size:11px;color:#999;letter-spacing:2px;
text-transform:uppercase;margin-bottom:12px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px dashed #1e1e1e;
vertical-align:top;word-break:break-all}
th{color:#888;font-weight:400;font-size:11px;letter-spacing:1px;
text-transform:uppercase}
.k{color:#7ecfff}.v{color:#fff}.m{color:#888}
.badge{display:inline-block;padding:1px 8px;border-radius:3px;
font-size:10px;letter-spacing:1px;text-transform:uppercase}
.b-domain-name{background:#1e3a5c;color:#7ecfff}
.b-ipv4-addr,.b-ipv6-addr{background:#4a3a1e;color:#f0c674}
.b-indicator{background:#5c1e1e;color:#f87171}
.b-identity{background:#3a1e5c;color:#c084fc}
.b-relationship{background:#1e5c3a;color:#4ade80}
.b-observed-data{background:#3a3a3a;color:#ccc}
.b-note{background:#3a3a3a;color:#ccc}
.b-autonomous-system{background:#4a2a1e;color:#f0a674}
code{background:#111;padding:1px 6px;font-size:11px}
pre{background:#000;border:1px solid #1a1a1a;padding:14px;
font-size:11px;color:#ddd;overflow-x:auto;line-height:1.5;
max-height:420px}
details summary{cursor:pointer;color:#a855f7;padding:6px 0}
footer{text-align:center;margin-top:36px;padding-top:20px;
border-top:1px solid #1a1a1a;font-size:10px;color:#555;letter-spacing:2px}
"""


def _badge(t):
    cls = "b-" + str(t).replace(".", "-")
    return ('<span class="badge ' + _esc(cls) + '">' + _esc(t) +
            '</span>')


def save_stix_html(bundle, target, base):
    try:
        p = Path(str(base) + ".html")
        objects = bundle.get("objects") or []
        by_type = _count_by_type(objects)

        rows_types = "".join(
            "<tr><td>" + _badge(t) + "</td><td>" + str(n) + "</td></tr>"
            for t, n in sorted(by_type.items(), key=lambda x: -x[1]))

        indicators = [o for o in objects if o.get("type") == "indicator"]
        rows_ind = ""
        for o in indicators:
            rows_ind += (
                "<tr><td>" + _esc(o.get("name", "")) + "</td>"
                "<td><code>" + _esc(o.get("pattern", "")) + "</code></td>"
                "<td>" + str(o.get("confidence", "")) + "</td></tr>")

        rels = [o for o in objects if o.get("type") == "relationship"]
        rel_rows = ""
        for o in rels:
            rel_rows += (
                "<tr><td>" + _esc(_short_id(o.get("source_ref"))) + "</td>"
                "<td>" + _esc(o.get("relationship_type", "")) + "</td>"
                "<td>" + _esc(_short_id(o.get("target_ref"))) + "</td>"
                "<td class='m'>" + _esc((o.get("description") or "")[:80]) +
                "</td></tr>")

        raw = json.dumps(bundle, indent=2, ensure_ascii=False, default=str)

        html_out = (
            "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>STIX Bundle — " + _esc(target) + "</title>"
            "<style>" + _HTML_CSS + "</style></head><body><div class='wrap'>"
            "<h1>STIX 2.1 Bundle</h1>"
            "<div class='target'>" + _esc(target) + "</div>"
            "<div class='tag'>stix export · astrym " +
            _esc(STIX_OUTPUT_VERSION) + "</div>"

            "<div class='card'><div class='ct'>Summary</div>"
            "<table><tr><th>Field</th><th>Value</th></tr>"
            "<tr><td>spec_version</td><td>" +
            _esc(bundle.get("spec_version", "2.1")) + "</td></tr>"
            "<tr><td>objects</td><td>" + str(len(objects)) + "</td></tr>"
            "<tr><td>produced</td><td>" + now_iso() + "</td></tr>"
            "</table></div>"

            "<div class='card'><div class='ct'>Objects by type</div>"
            "<table><tr><th>Type</th><th>Count</th></tr>" + rows_types +
            "</table></div>"
        )

        if rows_ind:
            html_out += (
                "<div class='card'><div class='ct'>Indicators (" +
                str(len(indicators)) + ")</div>"
                "<table><tr><th>Name</th><th>Pattern</th><th>Confidence</th></tr>"
                + rows_ind + "</table></div>")

        if rel_rows:
            html_out += (
                "<div class='card'><div class='ct'>Relationships (" +
                str(len(rels)) + ")</div>"
                "<table><tr><th>From</th><th>Type</th><th>To</th><th>Note</th></tr>"
                + rel_rows + "</table></div>")

        html_out += (
            "<div class='card'><details><summary>Raw STIX bundle (JSON)</summary>"
            "<pre>" + _esc(raw) + "</pre></details></div>"
            "<footer>astrym " + _esc(STIX_OUTPUT_VERSION) +
            " · STIX 2.1</footer>"
            "</div></body></html>")

        p.write_text(html_out, encoding="utf-8")
        c_ok("STIX HTML -> " + str(p))
        return p
    except Exception as e:
        c_err("STIX HTML: " + str(e))
        return None


# ============================================================
# CSV
# ============================================================

def save_stix_csv(bundle, base):
    try:
        p = Path(str(base) + ".csv")
        objects = bundle.get("objects") or []
        with open(p, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["kind", "type", "id", "value", "extra"])
            for o in objects:
                t = o.get("type", "?")
                oid = o.get("id", "")
                if t == "relationship":
                    extra = "src=" + _short_id(o.get("source_ref")) +                             " tgt=" + _short_id(o.get("target_ref"))
                    w.writerow(["relationship", t, oid,
                                 o.get("relationship_type", ""), extra])
                elif t == "indicator":
                    w.writerow(["object", t, oid,
                                 o.get("pattern", ""),
                                 "confidence=" + str(o.get("confidence", ""))])
                else:
                    w.writerow(["object", t, oid, _obj_value(o), ""])
        c_ok("STIX CSV -> " + str(p))
        return p
    except Exception as e:
        c_err("STIX CSV: " + str(e))
        return None


# ============================================================
# MD (AFFiNE-compatible)
# ============================================================

def save_stix_md(bundle, target, base):
    try:
        p = Path(str(base) + ".md")
        objects = bundle.get("objects") or []
        by_type = _count_by_type(objects)

        out = []
        out.append("---")
        out.append('title: "STIX Bundle: ' + str(target) + '"')
        out.append("date: " + now_iso())
        out.append("tool: ASTRYM " + STIX_OUTPUT_VERSION)
        out.append("type: stix")
        out.append("target: " + str(target))
        out.append("tags:")
        out.append("  - astrym")
        out.append("  - stix")
        out.append("  - threat-intel")
        out.append("---")
        out.append("")
        out.append("# STIX 2.1 Bundle: " + str(target))
        out.append("")
        out.append("> spec_version 2.1  ·  objects " + str(len(objects)) +
                   "  ·  generated " + now_iso())
        out.append("")
        out.append("## Objects by type")
        out.append("")
        out.append("| Type | Count |")
        out.append("|:-----|------:|")
        for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
            out.append("| `" + _md_escape(t) + "` | " + str(n) + " |")
        out.append("")

        indicators = [o for o in objects if o.get("type") == "indicator"]
        if indicators:
            out.append("## Indicators (" + str(len(indicators)) + ")")
            out.append("")
            out.append("| Name | Pattern | Confidence |")
            out.append("|:-----|:--------|-----------:|")
            for o in indicators:
                out.append("| " + _md_escape(o.get("name", "")) + " | `" +
                           _md_escape(o.get("pattern", "")) + "` | " +
                           str(o.get("confidence", "")) + " |")
            out.append("")

        rels = [o for o in objects if o.get("type") == "relationship"]
        if rels:
            out.append("## Relationships (" + str(len(rels)) + ")")
            out.append("")
            out.append("| From | Type | To | Note |")
            out.append("|:-----|:-----|:---|:-----|")
            for o in rels:
                out.append("| `" + _short_id(o.get("source_ref")) + "` | " +
                           _md_escape(o.get("relationship_type", "")) + " | `" +
                           _short_id(o.get("target_ref")) + "` | " +
                           _md_escape((o.get("description") or "")[:60]) + " |")
            out.append("")

        # objects list
        simple = [o for o in objects if o.get("type") in (
            "domain-name", "ipv4-addr", "ipv6-addr", "email-addr",
            "url", "autonomous-system", "identity")]
        if simple:
            out.append("## Observable Objects")
            out.append("")
            out.append("| Type | Value |")
            out.append("|:-----|:------|")
            for o in simple:
                out.append("| `" + _md_escape(o.get("type", "?")) + "` | `" +
                           _md_escape(_obj_value(o)) + "` |")
            out.append("")

        out.append("## Raw JSON")
        out.append("")
        out.append("```json")
        out.append(json.dumps(bundle, indent=2, ensure_ascii=False, default=str))
        out.append("```")

        p.write_text("\n".join(out), encoding="utf-8")
        c_ok("STIX MD -> " + str(p))
        return p
    except Exception as e:
        c_err("STIX MD: " + str(e))
        return None


# ============================================================
# PDF
# ============================================================

def save_stix_pdf(bundle, target, base):

    return None  # PDF disabled
    if not HAS_PDF:
        c_warn("install reportlab for PDF")
        return None
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors as _rl
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer)

        try:
            from astrym_output import _register_unicode_font, _sanitize_for_pdf
            font_name = _register_unicode_font()
        except Exception:
            font_name = "Helvetica"

            def _sanitize_for_pdf(s):
                return s

        p = Path(str(base) + ".pdf")
        objects = bundle.get("objects") or []
        by_type = _count_by_type(objects)

        doc = SimpleDocTemplate(
            str(p), pagesize=A4,
            leftMargin=18*mm, rightMargin=18*mm,
            topMargin=18*mm, bottomMargin=18*mm,
            title="STIX Bundle " + str(target),
            author="ASTRYM")
        st = getSampleStyleSheet()
        h1 = ParagraphStyle("h1", parent=st["Title"], fontName=font_name,
                             fontSize=18, textColor=_rl.HexColor("#a855f7"),
                             spaceAfter=4, alignment=0)
        h2 = ParagraphStyle("h2", parent=st["Heading2"], fontName=font_name,
                             fontSize=12, textColor=_rl.HexColor("#a855f7"),
                             spaceBefore=12, spaceAfter=6)
        body = ParagraphStyle("body", parent=st["Normal"], fontName=font_name,
                               fontSize=9.5, leading=13)
        mono = ParagraphStyle("mono", parent=st["Normal"], fontName=font_name,
                               fontSize=8.5, leading=11,
                               textColor=_rl.HexColor("#222222"))

        NL = chr(10)
        story = []
        story.append(Paragraph(_sanitize_for_pdf("STIX 2.1 Bundle"), h1))
        story.append(Paragraph(_sanitize_for_pdf("Target: " + str(target)),
                                body))
        story.append(Paragraph(_sanitize_for_pdf(
            "Generated: " + now_iso()), body))
        story.append(Spacer(1, 10))

        def add_lines(title, lines):
            story.append(Paragraph(_sanitize_for_pdf(title), h2))
            for ln in lines:
                ln = (ln.replace("&", "&amp;").replace("<", "&lt;")
                        .replace(">", "&gt;"))
                story.append(Paragraph(_sanitize_for_pdf(ln), mono))

        add_lines("Summary", [
            "  spec_version  " + str(bundle.get("spec_version", "2.1")),
            "  objects       " + str(len(objects)),
            "  producer      ASTRYM " + STIX_OUTPUT_VERSION,
        ])
        add_lines("Objects by type",
                   ["  " + str(t).ljust(24) + str(n)
                    for t, n in sorted(by_type.items(), key=lambda x: -x[1])])

        inds = [o for o in objects if o.get("type") == "indicator"]
        if inds:
            lines = []
            for o in inds:
                lines.append("  - " + str(o.get("name", ""))[:70])
                lines.append("    " + str(o.get("pattern", ""))[:100])
                if o.get("confidence") is not None:
                    lines.append("    confidence: " + str(o.get("confidence")))
            add_lines("Indicators (" + str(len(inds)) + ")", lines)

        rels = [o for o in objects if o.get("type") == "relationship"]
        if rels:
            lines = []
            for o in rels[:80]:
                lines.append("  " + _short_id(o.get("source_ref")) + "  --" +
                             str(o.get("relationship_type", "")) + "-->  " +
                             _short_id(o.get("target_ref")))
            if len(rels) > 80:
                lines.append("  ... +" + str(len(rels) - 80))
            add_lines("Relationships (" + str(len(rels)) + ")", lines)

        doc.build(story)
        c_ok("STIX PDF -> " + str(p))
        return p
    except Exception as e:
        c_err("STIX PDF: " + str(e))
        return None


# ============================================================
# TOPOLOGY (vis.js)
# ============================================================

_VIS_CDN = ("https://cdn.jsdelivr.net/npm/vis-network@9.1.6/"
            "standalone/umd/vis-network.min.js")

_TOPO_COLORS = {
    "domain-name":       "#7ecfff",
    "ipv4-addr":         "#f0c674",
    "ipv6-addr":         "#f0c674",
    "autonomous-system": "#f0a674",
    "email-addr":        "#a8e6a0",
    "url":               "#7ecfff",
    "indicator":         "#f87171",
    "identity":          "#c084fc",
    "observed-data":     "#888888",
    "note":              "#888888",
}


def _topo_build(bundle):
    objects = bundle.get("objects") or []
    id_to_obj = {o.get("id"): o for o in objects if o.get("id")}
    nodes = []
    edges = []

    for o in objects:
        t = o.get("type", "?")
        if t == "relationship":
            continue
        oid = o.get("id")
        if not oid:
            continue
        label = _obj_value(o) or t
        nodes.append({
            "id": oid,
            "label": str(label)[:32],
            "title": "<b>" + str(t) + "</b><br>" + str(label)[:200],
            "color": {
                "background": _TOPO_COLORS.get(t, "#888888"),
                "border": "#2a2a2a",
                "highlight": {"background": _TOPO_COLORS.get(t, "#888888"),
                               "border": "#a855f7"},
            },
            "shape": "dot",
            "size": 22 if t == "indicator" else 14,
            "group": t,
        })

    for o in objects:
        if o.get("type") != "relationship":
            continue
        s = o.get("source_ref")
        d = o.get("target_ref")
        if s in id_to_obj and d in id_to_obj:
            edges.append({
                "from": s,
                "to": d,
                "label": str(o.get("relationship_type", ""))[:18],
                "arrows": "to",
                "color": {"color": "#2a2a2a", "highlight": "#a855f7"},
                "font": {"color": "#888", "size": 9,
                          "face": "monospace"},
            })

    return nodes, edges


def save_stix_topology(bundle, target, base):
    try:
        p = Path(str(base) + "_topology.html")
        nodes, edges = _topo_build(bundle)
        if not nodes:
            c_warn("STIX topology: no nodes")
            return None

        nodes_json = json.dumps(nodes, ensure_ascii=False).replace("</", "<\\/")
        edges_json = json.dumps(edges, ensure_ascii=False).replace("</", "<\\/")

        html_out = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>STIX topology - __T__</title>
<script src="__CDN__"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:#000;color:#fff;font-family:'SF Mono',Menlo,monospace;
font-size:13px;overflow:hidden;width:100vw;height:100vh}
#hdr{position:absolute;top:20px;left:24px;z-index:10;pointer-events:none}
#hdr h1{color:#a855f7;font-size:20px;margin-bottom:4px}
#hdr .tgt{color:#fff;font-size:16px;word-break:break-all}
#hdr .tag{color:#777;font-size:10px;letter-spacing:3px;
text-transform:uppercase;margin-top:6px}
#stats{position:absolute;top:20px;right:24px;background:#080808;
border:1px solid #2a2a2a;padding:10px 16px;font-size:11px;color:#888;
letter-spacing:1px;z-index:10}
#stats b{color:#fff}
#net{width:100vw;height:100vh;background:#000}
</style></head><body>
<div id="hdr"><h1>STIX 2.1 Topology</h1>
<div class="tgt">__T__</div>
<div class="tag">astrym &middot; stix</div></div>
<div id="stats"><b>__NC__</b> NODES &middot; <b>__EC__</b> REL</div>
<div id="net"></div>
<script>
(function(){
  var N = __N__, E = __E__;
  document.getElementById('stats').innerHTML =
    '<b>'+N.length+'</b> NODES &middot; <b>'+E.length+'</b> REL';
  var c = document.getElementById('net');
  var data = {nodes: new vis.DataSet(N), edges: new vis.DataSet(E)};
  var opts = {
    nodes:{font:{color:'#fff',size:11,face:'Menlo,monospace',
      strokeWidth:3,strokeColor:'#000'},borderWidth:1,shadow:true},
    edges:{smooth:{type:'continuous',roundness:0.5},width:1,
      color:{color:'#2a2a2a',highlight:'#a855f7'}},
    physics:{solver:'forceAtlas2Based',
      forceAtlas2Based:{gravitationalConstant:-40,centralGravity:0.01,
        springLength:120,springConstant:0.15,damping:0.65},
      stabilization:{iterations:200,fit:true}},
    interaction:{hover:true,tooltipDelay:100,zoomView:true,dragView:true},
    layout:{randomSeed:42}
  };
  var n = new vis.Network(c, data, opts);
  n.on('click', function(p){
    if(!p.nodes.length) return;
    var o = N.find(function(x){return x.id===p.nodes[0];});
    if(o) alert(o.title.replace(/<br>/g, '\n').replace(/<[^>]+>/g, ''));
  });
  setTimeout(function(){n.fit({animation:true});}, 400);
})();
</script></body></html>"""
        html_out = (html_out
                     .replace("__CDN__", _VIS_CDN)
                     .replace("__T__", _esc(target))
                     .replace("__N__", nodes_json)
                     .replace("__E__", edges_json))

        p.write_text(html_out, encoding="utf-8")
        c_ok("STIX TOPOLOGY -> " + str(p))
        return p
    except Exception as e:
        c_err("STIX topology: " + str(e))
        return None


# ============================================================
# DISPATCHER
# ============================================================

def output_stix_results(results, fmt, base=None):
    """Единая точка входа для STIX-выходов во все форматы."""
    if not results:
        c_warn("stix: no results")
        return
    result = results[0]
    bundle, target = _extract_bundle(result)
    if not bundle:
        c_err("stix: bundle missing in result")
        return

    fmts = [f.strip().lower() for f in (fmt or "console").split(",") if f.strip()]
    if "all" in fmts:
        fmts = ["json", "html", "csv", "pdf", "md", "topology"]
    # console handled outside — skip here
    fmts = [f for f in fmts if f != "console"]
    if not fmts:
        return

    if base is None:
        base = auto_path("stix")
        c_info("auto-output: " + str(base) + ".*")

    for f in fmts:
        if f == "json":
            save_stix_json(bundle, base)
        elif f == "html":
            save_stix_html(bundle, target, base)
        elif f == "csv":
            save_stix_csv(bundle, base)
        elif f == "pdf":
            save_stix_pdf(bundle, target, base)
        elif f == "md":
            save_stix_md(bundle, target, base)
        elif f == "topology":
            save_stix_topology(bundle, target, base)
        else:
            c_warn("stix: unknown format " + str(f))
