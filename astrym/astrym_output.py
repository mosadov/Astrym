#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Output 8.1.0 — экспорт в json/html/csv/pdf

import os, re, json, csv
from pathlib import Path
from datetime import datetime

from astrym_core import RESULTS_DIR

from astrym_core import c_ok, c_err, c_warn, c_info, c_muted, HAS_PDF

try:
    from astrym_core import now_iso
except ImportError:
    def now_iso():
        from datetime import timezone
        return datetime.now(timezone.utc).isoformat()

VERSION = ""

# ============================================================
# AUTO PATH
# ============================================================

def auto_path(kind):
    """Следующий номер: results/<kind>/<kind>N"""
    folder = RESULTS_DIR / kind
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except Exception:
        folder = RESULTS_DIR
    n = 1
    existing = set()
    if folder.is_dir():
        for f in folder.iterdir():
            m = re.match(r"^" + re.escape(kind) + r"(\d+)$", f.stem)
            if m:
                existing.add(int(m.group(1)))
    while n in existing:
        n += 1
    return folder / (kind + str(n))

# ============================================================
# JSON
# ============================================================

def save_json(results, base):
    try:
        payload = results[0] if len(results) == 1 else {
            "meta": {"type": "multi", "count": len(results),
                     "generated_at": now_iso(),
                     "tool": "ASTRYM"},
            "results": results,
        }
        path = Path(str(base) + ".json")
        path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        c_ok("JSON -> " + str(path))
        return path
    except Exception as e:
        c_err("JSON: " + str(e))
        return None

# ============================================================
# CSV
# ============================================================

def save_csv(results, base):
    try:
        path = Path(str(base) + ".csv")
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["type", "target", "key", "value"])
            for r in results:
                t = r.get("meta", {}).get("type", "?")
                tgt = r.get("meta", {}).get("target", "?")
                for k, v in r.items():
                    if k == "meta":
                        continue
                    if isinstance(v, (str, int, float, bool)):
                        w.writerow([t, tgt, k, v])
                    elif isinstance(v, list) and v and isinstance(v[0], str):
                        w.writerow([t, tgt, k, ";".join(v[:50])])
        c_ok("CSV -> " + str(path))
        return path
    except Exception as e:
        c_err("CSV: " + str(e))
        return None

# ============================================================
# HTML
# ============================================================

HTML_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:#000;color:#fff}
body{font-family:'SF Mono','Menlo','Consolas',monospace;font-size:14px;
line-height:1.6;padding:32px 16px}
.wrap{max-width:900px;margin:0 auto}
h1{font-size:26px;color:#a855f7;margin-bottom:6px}
h2{font-size:18px;color:#a855f7;margin-top:24px;padding-bottom:6px;
border-bottom:1px solid #2a2a2a}
h3{font-size:14px;color:#c084fc;margin-top:14px}
.email{font-size:22px;color:#fff;margin-bottom:8px;word-break:break-all}
.tag{font-size:11px;color:#777;letter-spacing:3px;text-transform:uppercase}
.card{border:1px solid #2a2a2a;background:#080808;margin:14px 0;padding:16px 20px}
.ct{font-size:11px;color:#999;letter-spacing:2px;text-transform:uppercase;
margin-bottom:12px}
pre{background:#000;border:1px solid #1a1a1a;padding:14px;font-size:12px;
color:#ddd;overflow-x:auto;line-height:1.5}
.k{color:#7ecfff}.s{color:#a8e6a0}.n{color:#f0c674}.b{color:#f78c6c}
.kv{width:100%;border-collapse:collapse}
.kv td{padding:10px 0;border-bottom:1px dashed #1e1e1e;vertical-align:top}
.kv td:first-child{color:#888;width:40%;font-size:11px;letter-spacing:1px;
text-transform:uppercase}
.kv td:last-child{color:#fff;word-break:break-all}
.ok{color:#4ade80}.err{color:#f87171}.warn{color:#fbbf24}
.status{margin:14px 0;padding:10px 14px;font-size:12px}
.status.ok{border-left:3px solid #4ade80;color:#4ade80}
.status.err{border-left:3px solid #f87171;color:#f87171}
.status.warn{border-left:3px solid #fbbf24;color:#fbbf24}
a{color:#7ecfff;text-decoration:none}
a:hover{text-decoration:underline}
footer{text-align:center;margin-top:36px;padding-top:20px;
border-top:1px solid #1a1a1a;font-size:10px;color:#555;letter-spacing:2px}
"""

def _esc(v):
    if v is None: return ""
    return (str(v).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))

def _json_hl(obj):
    txt = json.dumps(obj, indent=2, ensure_ascii=False, default=str)
    txt = _esc(txt)
    txt = re.sub(r'"([^"]+)"(\s*:)', r'<span class="k">"\1"</span>\2', txt)
    txt = re.sub(r':\s*"([^"]*)"', r': <span class="s">"\1"</span>', txt)
    txt = re.sub(r':\s*(-?\d+\.?\d*)', r': <span class="n">\1</span>', txt)
    txt = re.sub(r':\s*(true|false|null)', r': <span class="b">\1</span>', txt)
    return txt

def _kv_block(pairs):
    s = "<table class='kv'>"
    for k, v in pairs:
        if v is None or v == "":
            continue
        s += ("<tr><td>" + _esc(k) + "</td><td>" + _esc(v) + "</td></tr>")
    s += "</table>"
    return s

def _html_ip(r):
    out = []
    ov = r.get("overview", {})
    g = r.get("geo", {})
    pairs = [("Address", ov.get("address")), ("Version", ov.get("version")),
             ("PTR", ov.get("ptr")),
             ("Private", "yes" if ov.get("private") else "no")]
    if "error" not in g:
        pairs += [("Country", g.get("country")), ("City", g.get("city")),
                  ("ISP", g.get("isp")), ("ASN", g.get("as")),
                  ("Source", g.get("source"))]
    out.append("<div class='card'><div class='ct'>Overview</div>" +
               _kv_block(pairs) + "</div>")
    dnsbl = r.get("dnsbl", [])
    if dnsbl:
        rows = []
        for x in dnsbl:
            cls = {"listed": "err", "clean": "ok"}.get(x["status"], "warn")
            rows.append((x["zone"], "<span class='" + cls + "'>" +
                         x["status"] + "</span>"))
        out.append("<div class='card'><div class='ct'>DNSBL</div>" +
                   "<table class='kv'>" +
                   "".join("<tr><td>" + _esc(k) + "</td><td>" + v +
                           "</td></tr>" for k, v in rows) + "</table></div>")
    w = r.get("whois", {})
    if w:
        out.append("<div class='card'><div class='ct'>WHOIS</div>" +
                   _kv_block(list(w.items())) + "</div>")
    return "".join(out)

def _html_domain(r):
    out = []
    rec = r.get("dns", {})
    for rt, vs in rec.items():
        if vs:
            out.append("<h3>" + _esc(rt) + "</h3><pre>" +
                       _esc("\n".join(vs)) + "</pre>")
    if out:
        out = ["<div class='card'><div class='ct'>DNS Records</div>" +
               "".join(out) + "</div>"]
    subs = r.get("subdomains_ct", [])
    if subs:
        out.append("<div class='card'><div class='ct'>Subdomains CT (" +
                   str(len(subs)) + ")</div><pre>" +
                   _esc("\n".join(subs[:200])) + "</pre></div>")
    w = r.get("whois", {})
    if w:
        out.append("<div class='card'><div class='ct'>WHOIS</div>" +
                   _kv_block(list(w.items())) + "</div>")
    # # ASTRYM consensus-domain patch-html
    _cons = r.get("consensus") or {}
    if _cons.get("fields"):
        rows = ""
        try:
            from astrym_consensus import _html_badge as _hb
        except Exception:
            _hb = lambda c, v, t: c + " (" + str(v) + "/" + str(t) + ")"
        for fld, c in _cons["fields"].items():
            rows += ("<tr><td>" + _esc(fld) + "</td><td>" +
                     _esc(c.get("value")) + "</td><td>" +
                     _hb(c.get("confidence"),
                          c.get("votes", 0),
                          c.get("total_votes", 0)) + "</td></tr>")
        if rows:
            out.append("<div class='card'><div class='ct'>Consensus</div>"
                       "<table class='kv'><tr><td>Field</td><td>Value</td>"
                       "<td>Confidence</td></tr>" + rows + "</table></div>")
    return "".join(out)

def _html_dns(r):
    out = []
    rec = r.get("records", {})
    for rt, vs in rec.items():
        if vs:
            out.append("<h3>" + _esc(rt) + "</h3><pre>" +
                       _esc("\n".join(vs)) + "</pre>")
    if out:
        out = ["<div class='card'><div class='ct'>DNS Records</div>" +
               "".join(out) + "</div>"]
    ds = r.get("dnssec", {})
    status = "enabled" if ds.get("enabled") else "not enabled"
    cls = "ok" if ds.get("enabled") else "warn"
    out.append("<div class='card'><div class='ct'>DNSSEC</div>"
               "<div class='status " + cls + "'>" + status + "</div></div>")
    return "".join(out)

def _html_sub(r):
    subs = r.get("subdomains", [])
    s = r.get("stats", {})
    out = ["<div class='card'><div class='ct'>Stats</div>" +
           _kv_block([("CT", s.get("ct_count")), ("Brute", s.get("brute_count")),
                      ("Unique", s.get("total_unique")),
                      ("Wordlist", s.get("wordlist"))]) + "</div>"]
    if subs:
        body = "<table class='kv'>"
        for x in subs[:300]:
            body += ("<tr><td>" + _esc(x.get("host")) +
                     "</td><td>" + _esc(",".join(x.get("sources", []))) +
                     "</td></tr>")
        body += "</table>"
        out.append("<div class='card'><div class='ct'>Subdomains (" +
                   str(len(subs)) + ")</div>" + body + "</div>")
    return "".join(out)

def _html_email(r):
    out = []
    ov = r.get("overview", {})
    out.append("<div class='card'><div class='ct'>Overview</div>" +
               _kv_block([("Email", ov.get("email")), ("Local", ov.get("local")),
                          ("Domain", ov.get("domain")),
                          ("Provider", ov.get("provider")),
                          ("Disposable", "yes" if ov.get("disposable") else "no")])
               + "</div>")
    smtp = r.get("smtp")
    if smtp:
        st = smtp.get("status", "?")
        cls = {"valid": "ok", "invalid": "err"}.get(st, "warn")
        out.append("<div class='card'><div class='ct'>SMTP</div>"
                   "<div class='status " + cls + "'>" + _esc(st) +
                   "</div><pre>" + _json_hl(smtp) + "</pre></div>")
    g = r.get("gravatar", {})
    if g.get("found"):
        out.append("<div class='card'><div class='ct'>Gravatar</div>"
                   "<img src='" + _esc(g.get("url")) +
                   "' style='width:96px;border:1px solid #333'></div>")
    h = r.get("hibp", {})
    if h.get("found") is True:
        bl = h.get("breaches", [])
        rows = "".join("<tr><td>" + _esc(b.get("Name")) +
                       "</td><td>" + _esc(b.get("BreachDate")) +
                       "</td></tr>" for b in bl[:30])
        out.append("<div class='card'><div class='ct'>HIBP (" + str(len(bl)) +
                   ")</div><div class='status err'>BREACHED</div><table class='kv'>"
                   + rows + "</table></div>")
    elif h.get("found") is False:
        out.append("<div class='card'><div class='ct'>HIBP</div>"
                   "<div class='status ok'>no breaches</div></div>")
    return "".join(out)

def _html_check(r):
    out = []
    rk = r.get("risk", {})
    lvl = rk.get("level", "?"); sc = rk.get("score", 0)
    cls = {"CLEAN":"ok","LOW":"ok","MEDIUM":"warn",
           "HIGH":"err","CRITICAL":"err"}.get(lvl, "warn")
    reasons = "".join("<p style='color:#aaa'>· " + _esc(x) + "</p>"
                      for x in rk.get("reasons", []))
    out.append("<div class='card'><div class='ct'>Risk</div>"
               "<div class='status " + cls + "'>" + _esc(lvl) + " · " +
               str(sc) + "/100</div>" + reasons + "</div>")
    for src, res in r.get("results", {}).items():
        if not res: continue
        if res.get("error"):
            out.append("<div class='card'><div class='ct'>" + _esc(src) +
                       "</div><p class='err'>" + _esc(res["error"]) + "</p></div>")
            continue
        if res.get("found") is False:
            out.append("<div class='card'><div class='ct'>" + _esc(src) +
                       "</div><p class='ok'>not found</p></div>")
            continue
        rows = [(k.replace("_"," "), str(v)) for k, v in res.items()
                if k not in ("source","found","target","kind")
                and not isinstance(v, (list, dict))]
        if rows:
            out.append("<div class='card'><div class='ct'>" + _esc(src) +
                       "</div>" + _kv_block(rows) + "</div>")
    return "".join(out)

def _html_ssl(r):
    if r.get("error"):
        return ("<div class='card'><div class='ct'>SSL</div>"
                "<p class='err'>" + _esc(r["error"]) + "</p></div>")
    pairs = [("Protocol", r.get("protocol")), ("Cipher", r.get("cipher")),
             ("Subject CN", r.get("subject", {}).get("commonName")),
             ("Issuer CN", r.get("issuer", {}).get("commonName")),
             ("Not before", r.get("not_before")),
             ("Not after", r.get("not_after")),
             ("Days valid", r.get("days_valid"))]
    out = ["<div class='card'><div class='ct'>Certificate</div>" +
           _kv_block(pairs) + "</div>"]
    san = r.get("san", [])
    if san:
        out.append("<div class='card'><div class='ct'>SAN (" + str(len(san)) +
                   ")</div><pre>" + _esc("\n".join(san)) + "</pre></div>")
    return "".join(out)

def _html_web(r):
    out = ["<div class='card'><div class='ct'>Overview</div>" +
           _kv_block([("Final URL", r.get("final_url")),
                      ("Status", r.get("status_code")),
                      ("Title", r["titles"][0] if r.get("titles") else "-")])
           + "</div>"]
    if r.get("cms_detected"):
        out.append("<div class='card'><div class='ct'>Technologies</div><pre>" +
                   _esc("\n".join(r["cms_detected"])) + "</pre></div>")
    if r.get("headers"):
        out.append("<div class='card'><div class='ct'>Headers</div>" +
                   _kv_block(list(r["headers"].items())) + "</div>")
    if r.get("leaks"):
        rows = ""
        for x in r["leaks"]:
            cls = "err" if x["status"] == 200 else "warn"
            rows += ("<tr><td>" + _esc(x["path"]) + "</td><td class='" + cls +
                     "'>" + str(x["status"]) + " (" + _esc(x["what"]) +
                     ")</td></tr>")
        out.append("<div class='card'><div class='ct'>Exposed Paths</div>"
                   "<table class='kv'>" + rows + "</table></div>")
    return "".join(out)

def _html_generic(r):
    out = ["<div class='card'><div class='ct'>Full JSON</div><pre>" +
           _json_hl(r) + "</pre></div>"]
    return "".join(out)

_HTML_BY_TYPE = {
    "ip": _html_ip, "domain": _html_domain, "dns": _html_dns,
    "sub": _html_sub, "email": _html_email, "check": _html_check,
    "ssl": _html_ssl, "web": _html_web,
}

def save_html(results, base):
    try:
        p = Path(str(base) + ".html")
        r = results[0]
        t = r.get("meta", {}).get("type", "?")
        tgt = r.get("meta", {}).get("target", "?")
        body_fn = _HTML_BY_TYPE.get(t, _html_generic)
        body = body_fn(r)
        # extended блок
        if r.get("extended") or r.get("extended_links"):
            ext_html = "<div class='card'><div class='ct'>Extended sources</div><pre>"
            ext_html += _json_hl(r.get("extended", {}))
            ext_html += "</pre></div>"
            if r.get("extended_links"):
                links = "".join("<p>· <a href='" + _esc(u) + "' target='_blank'>" +
                                _esc(n) + "</a></p>" for n, u in r["extended_links"])
                ext_html += ("<div class='card'><div class='ct'>External services</div>" +
                             links + "</div>")
            body += ext_html
        body += ("<div class='card'><div class='ct'>Raw JSON</div><pre>" +
                 _json_hl(r) + "</pre></div>")
        html = ("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                "<title>ASTRYM · " + _esc(tgt) + "</title>"
                "<style>" + HTML_CSS + "</style></head><body><div class='wrap'>"
                "<h1>OSINT Report:</h1>"
                "<div class='email'>" + _esc(tgt) + "</div>"
                "<div class='tag'>" + _esc(t) + " · ASTRYM" + "</div>"
                + body +
                "<footer>© " + str(datetime.now().year) + " ASTRYM" +
                "</footer></div></body></html>")
        p.write_text(html, encoding="utf-8")
        c_ok("HTML -> " + str(p))
        return p
    except Exception as e:
        c_err("HTML: " + str(e))
        return None

# ============================================================
# PDF
# ============================================================

# ============================================================
# ASTRYM 9.1.5 — PDF Unicode font
# ============================================================

_PDF_FONT_NAME = "Helvetica"


def _register_unicode_font():
    global _PDF_FONT_NAME
    if _PDF_FONT_NAME != 'Helvetica':
        return _PDF_FONT_NAME
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
    except ImportError:
        return 'Helvetica'
    candidates = [
        '/data/data/com.termux/files/usr/share/fonts/TTF/DejaVuSans.ttf',
        '/data/data/com.termux/files/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        '/system/fonts/DejaVuSans.ttf',
        '/system/fonts/Roboto-Regular.ttf',
        '/system/fonts/NotoSans-Regular.ttf',
        '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
        '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
        '/usr/share/fonts/TTF/DejaVuSans.ttf',
        '/Library/Fonts/Arial Unicode.ttf',
        '/System/Library/Fonts/Supplemental/Arial Unicode.ttf',
        'C:/Windows/Fonts/arial.ttf',
        '/data/user/0/ru.iiec.pydroid3/files/usr/share/fonts/TTF/DejaVuSans.ttf',
    ]
    for path in candidates:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont('AstrymUni', path))
                _PDF_FONT_NAME = 'AstrymUni'
                return 'AstrymUni'
            except Exception:
                continue
    return 'Helvetica'


_TRANSLIT = {
    0x430:'a',0x431:'b',0x432:'v',0x433:'g',0x434:'d',0x435:'e',
    0x436:'zh',0x437:'z',0x438:'i',0x439:'y',0x43a:'k',0x43b:'l',
    0x43c:'m',0x43d:'n',0x43e:'o',0x43f:'p',0x440:'r',0x441:'s',
    0x442:'t',0x443:'u',0x444:'f',0x445:'h',0x446:'ts',0x447:'ch',
    0x448:'sh',0x449:'sch',0x44a:'',0x44b:'y',0x44c:'',0x44d:'e',
    0x44e:'yu',0x44f:'ya',
    0x410:'A',0x411:'B',0x412:'V',0x413:'G',0x414:'D',0x415:'E',
    0x416:'Zh',0x417:'Z',0x418:'I',0x419:'Y',0x41a:'K',0x41b:'L',
    0x41c:'M',0x41d:'N',0x41e:'O',0x41f:'P',0x420:'R',0x421:'S',
    0x422:'T',0x423:'U',0x424:'F',0x425:'H',0x426:'Ts',0x427:'Ch',
    0x428:'Sh',0x429:'Sch',0x42a:'',0x42b:'Y',0x42c:'',0x42d:'E',
    0x42e:'Yu',0x42f:'Ya',
    0x2014:'-',0x2013:'-',0x00ab:'"',0x00bb:'"',0x00b7:'.',
}


def _sanitize_for_pdf(s):
    if _PDF_FONT_NAME != 'Helvetica':
        return s
    try:
        return s.translate(_TRANSLIT)
    except Exception:
        return s


def save_pdf(results, base):

    return None  # PDF disabled
    if not HAS_PDF:
        c_warn('install reportlab for PDF')
        return None
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors as _rl
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

        font_name = _register_unicode_font()
        p = Path(str(base) + '.pdf')
        r = results[0] if results else {}
        meta = r.get('meta', {}) or {}

        doc = SimpleDocTemplate(
            str(p), pagesize=A4,
            leftMargin=18*mm, rightMargin=18*mm,
            topMargin=18*mm, bottomMargin=18*mm,
            title='ASTRYM ' + str(meta.get('target', '')),
            author='ASTRYM')

        st = getSampleStyleSheet()
        h1_style = ParagraphStyle('h1', parent=st['Title'],
            fontName=font_name, fontSize=20,
            textColor=_rl.HexColor('#a855f7'), spaceAfter=4, alignment=0)
        h2_style = ParagraphStyle('h2', parent=st['Heading2'],
            fontName=font_name, fontSize=13,
            textColor=_rl.HexColor('#a855f7'),
            spaceBefore=12, spaceAfter=6)
        body_style = ParagraphStyle('body', parent=st['Normal'],
            fontName=font_name, fontSize=9.5, leading=13,
            textColor=_rl.HexColor('#000000'))
        mono_style = ParagraphStyle('mono', parent=st['Normal'],
            fontName=font_name, fontSize=8.5, leading=11,
            textColor=_rl.HexColor('#222222'))

        NL = chr(10)
        story = []
        story.append(Paragraph(
            _sanitize_for_pdf('ASTRYM - OSINT Report'), h1_style))
        story.append(Paragraph(
            _sanitize_for_pdf('Target: ' + str(meta.get('target', '?'))),
            body_style))
        story.append(Paragraph(
            _sanitize_for_pdf('Type: ' + str(meta.get('type', '?')) +
                              ' - ' + str(meta.get('generated_at', ''))[:19] + ' UTC'),
            body_style))
        story.append(Spacer(1, 10))

        def add_section(title, body):
            story.append(Paragraph(_sanitize_for_pdf(title), h2_style))
            for line in body.split(NL):
                line = line.rstrip()
                if not line:
                    story.append(Spacer(1, 3))
                    continue
                line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                line = _sanitize_for_pdf(line)
                story.append(Paragraph(line, mono_style))

        ov = r.get('overview')
        if ov:
            lines = []
            for k, v in ov.items():
                if isinstance(v, (str, int, float, bool)) and v not in (None, ''):
                    lines.append('  ' + str(k).ljust(18) + str(v))
            add_section('Overview', NL.join(lines) or '  нет данных')

        geo = r.get('geo')
        if geo and 'error' not in geo:
            lines = []
            for k, v in geo.items():
                if k in ('query', 'status'):
                    continue
                if isinstance(v, (str, int, float, bool)) and v not in (None, ''):
                    lines.append('  ' + str(k).ljust(18) + str(v))
            add_section('Geolocation', NL.join(lines) or '  нет данных')

        dns = r.get('dns') or r.get('records')
        if isinstance(dns, dict):
            lines = []
            any_rec = False
            for rt in ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'CAA', 'SRV'):
                vs = dns.get(rt) or []
                for i, v in enumerate(vs[:8]):
                    any_rec = True
                    lines.append('  ' + (rt if i == 0 else '').ljust(8) + str(v)[:90])
            add_section('DNS Records', NL.join(lines) if any_rec else '  нет данных')

        subs = r.get('subdomains') or []
        if subs:
            lines = []
            for i, x in enumerate(subs[:100], 1):
                if isinstance(x, dict):
                    host = x.get('host', '?')
                    srcs = ','.join(x.get('sources', []))
                else:
                    host = str(x)
                    srcs = ''
                lines.append('  ' + str(i).rjust(3) + '. ' + host[:50] + '  [' + srcs + ']')
            if len(subs) > 100:
                lines.append('  ... +' + str(len(subs) - 100) + ' еще')
            add_section('Subdomains (' + str(len(subs)) + ')', NL.join(lines))

        subs_ct = r.get('subdomains_ct') or []
        if subs_ct:
            lines = ['  ' + str(s)[:90] for s in subs_ct[:80]]
            add_section('Subdomains (CT)', NL.join(lines))

        w = r.get('whois') or {}
        if w:
            lines = ['  ' + str(k).ljust(22) + str(v)[:100] for k, v in w.items()]
            add_section('WHOIS', NL.join(lines))

        smtp = r.get('smtp')
        if smtp:
            lines = []
            for k, v in smtp.items():
                if k == 'steps':
                    continue
                lines.append('  ' + str(k).ljust(18) + str(v)[:100])
            add_section('SMTP', NL.join(lines))

        es = r.get('email_security')
        if es:
            lines = []
            if es.get('spf'):
                lines.append('  SPF:    ' + str(es['spf'])[:100])
            if es.get('dmarc'):
                lines.append('  DMARC:  ' + str(es['dmarc'])[:100])
            for dk in (es.get('dkim') or []):
                if isinstance(dk, dict):
                    lines.append('  DKIM/' + str(dk.get('selector', '?')) + ': ' + str(dk.get('value', ''))[:80])
            add_section('Email Security', NL.join(lines) or '  нет данных')

        h = r.get('hibp')
        if h:
            if h.get('found') is True:
                lines = ['  НАЙДЕНО в ' + str(len(h.get('breaches', []))) + ' утечках']
                for b in h.get('breaches', [])[:30]:
                    lines.append('  - ' + str(b.get('Name', '?')) + ' (' + str(b.get('BreachDate', '?')) + ')')
                add_section('HaveIBeenPwned', NL.join(lines))
            elif h.get('found') is False:
                add_section('HaveIBeenPwned', '  утечек не найдено')
            else:
                msg = h.get('message') or h.get('error') or 'нет данных'
                add_section('HaveIBeenPwned', '  ' + str(msg)[:150])

        risk = r.get('risk')
        if risk:
            lines = ['  Level:  ' + str(risk.get('level', '?')),
                     '  Score:  ' + str(risk.get('score', 0)) + '/100']
            for reason in risk.get('reasons', []):
                lines.append('  - ' + str(reason)[:150])
            add_section('Risk Assessment', NL.join(lines))

        results_block = r.get('results')
        if isinstance(results_block, dict):
            for src_name, res in results_block.items():
                if not isinstance(res, dict):
                    continue
                lines = []
                if res.get('error'):
                    lines.append('  ошибка: ' + str(res['error'])[:150])
                elif res.get('found') is False:
                    lines.append('  чисто')
                else:
                    for k, v in res.items():
                        if k in ('source', 'found', 'target', 'kind'):
                            continue
                        if isinstance(v, (str, int, float, bool)):
                            lines.append('  ' + str(k).ljust(20) + str(v)[:100])
                if lines:
                    add_section(src_name.upper(), NL.join(lines))

        if r.get('protocol') or r.get('meta', {}).get('type') == 'ssl':
            lines = []
            for k in ('protocol', 'cipher', 'not_before', 'not_after', 'days_valid', 'expired', 'hsts'):
                v = r.get(k)
                if v not in (None, ''):
                    lines.append('  ' + str(k).ljust(16) + str(v)[:100])
            if r.get('subject'):
                lines.append('  subject:   ' + str(r['subject'].get('commonName', '?')))
            if r.get('issuer'):
                lines.append('  issuer:    ' + str(r['issuer'].get('commonName', '?')))
            if r.get('san'):
                lines.append('  SAN (' + str(len(r['san'])) + '):')
                for s in r['san'][:20]:
                    lines.append('    ' + str(s))
            if lines:
                add_section('SSL/TLS', NL.join(lines))

        if r.get('leaks'):
            lines = []
            for x in r['leaks'][:30]:
                if isinstance(x, dict):
                    lines.append('  [' + str(x.get('status', '?')) + '] ' + str(x.get('path', '?')) + ' - ' + str(x.get('what', '')))
            add_section('Exposed Paths', NL.join(lines) or '  нет данных')

        if r.get('false_positives'):
            add_section('Filtered false positives',
                        '  ' + str(len(r['false_positives'])) + ' путей отфильтровано')

        src_meta = (r.get('meta') or {}).get('sources')
        if src_meta:
            lines = []
            lines.append('  FREE: ' + str(len(src_meta.get('free', []))))
            for x in src_meta.get('free', [])[:50]:
                lines.append('    + ' + str(x.get('name', '?')))
            if src_meta.get('api_available'):
                lines.append('  API ACTIVE: ' + str(len(src_meta['api_available'])))
                for x in src_meta['api_available']:
                    lines.append('    + ' + str(x.get('name', '?')))
            if src_meta.get('api_missing'):
                lines.append('  API MISSING: ' + str(len(src_meta['api_missing'])))
                for x in src_meta['api_missing']:
                    lines.append('    - ' + str(x.get('name', '?')) + ' (требуется ' + str(x.get('env', '?')) + ')')
            add_section('Sources', NL.join(lines))

        story.append(Spacer(1, 20))
        story.append(Paragraph(
            _sanitize_for_pdf('ASTRYM 9.1.5 - OSINT Report'),
            body_style))

        doc.build(story)
        c_ok('PDF -> ' + str(p))
        return p
    except Exception as e:
        import traceback as _tb
        err('PDF: ' + str(e))
        try:
            err('  ' + _tb.format_exc().split(chr(10))[-3])
        except Exception:
            pass
        return None


def save_topology(results, base):
    """Генерирует HTML-граф инфраструктуры через astrym_topology."""
    try:
        from astrym_topology import build_topology
    except ImportError as e:
        c_err("astrym_topology.py not found: " + str(e))
        return None
    try:
        p = Path(str(base) + "_topology.html")
        out = build_topology(results, str(p))
        if out:
            c_ok("TOPOLOGY -> " + str(out))
        return out
    except Exception as e:
        c_err("topology: " + str(e))
        return None


# ASTRYM markdown export (AFFiNE-compatible)


def _md_escape(s):
    if s is None:
        return ""
    return (str(s).replace("|", "\\|")
                  .replace("\n", " ")
                  .replace("\r", " "))


def _md_kv(rows):
    lines = ["| Key | Value |", "|:----|:------|"]
    for k, v in rows:
        if v is None or v == "":
            continue
        lines.append("| " + _md_escape(k) + " | " + _md_escape(v) + " |")
    if len(lines) == 2:
        return ""
    return "\n".join(lines) + "\n\n"


def _md_list(items, ordered=False):
    if not items:
        return ""
    out = []
    for i, x in enumerate(items, 1):
        if ordered:
            out.append(str(i) + ". " + _md_escape(x))
        else:
            out.append("- " + _md_escape(x))
    return "\n".join(out) + "\n\n"


def _md_frontmatter(r):
    meta = r.get("meta") or {}
    t = meta.get("type", "?")
    tgt = meta.get("target", "?")
    gen = meta.get("generated_at", "")
    tool = meta.get("tool", "ASTRYM")
    risk = ((r.get("risk") or {}).get("level")
            or ((r.get("security") or {}).get("risk") or {}).get("level")
            or "")
    tags = ["astrym", "osint", t]
    if risk:
        tags.append(str(risk).lower())
    lines = ["---"]
    lines.append('title: "ASTRYM Report: ' + str(tgt) + '"')
    lines.append("date: " + str(gen))
    lines.append("tool: " + str(tool))
    lines.append("type: " + str(t))
    lines.append("target: " + str(tgt))
    if risk:
        lines.append("risk: " + str(risk))
    lines.append("tags:")
    for tag in tags:
        lines.append("  - " + str(tag))
    lines.append("---")
    lines.append("")
    return "\n".join(lines) + "\n"


def _md_ip(r):
    out = ["## Overview\n\n"]
    ov = r.get("overview", {})
    g = r.get("geo", {})
    rows = [("Address", ov.get("address")), ("Version", ov.get("version")),
            ("PTR", ov.get("ptr")),
            ("Private", "yes" if ov.get("private") else "no")]
    if "error" not in g:
        rows += [("Country", g.get("country")), ("City", g.get("city")),
                 ("ISP", g.get("isp")), ("ASN", g.get("as")),
                 ("Source", g.get("source"))]
    out.append(_md_kv(rows))

    dnsbl = r.get("dnsbl") or []
    if dnsbl:
        out.append("## DNSBL\n\n")
        out.append("| Zone | Status |\n|:-----|:-------|\n")
        for x in dnsbl:
            out.append("| " + _md_escape(x.get("zone")) + " | " +
                       _md_escape(x.get("status")) + " |\n")
        out.append("\n")

    w = r.get("whois") or {}
    if w:
        out.append("## WHOIS\n\n")
        out.append(_md_kv(list(w.items())))
    return "".join(out)


def _md_domain(r):
    out = []
    rec = r.get("dns") or {}
    if rec:
        out.append("## DNS Records\n\n")
        for rt, vs in rec.items():
            if not vs:
                continue
            out.append("### " + str(rt) + "\n\n")
            for v in vs:
                out.append("- `" + _md_escape(v) + "`\n")
            out.append("\n")
    subs = r.get("subdomains_ct") or []
    if subs:
        out.append("## Subdomains (CT) — " + str(len(subs)) + "\n\n")
        for s in subs[:100]:
            out.append("- `" + _md_escape(s) + "`\n")
        if len(subs) > 100:
            out.append("\n_... +" + str(len(subs) - 100) + " more_\n")
        out.append("\n")
    w = r.get("whois") or {}
    if w:
        out.append("## WHOIS\n\n")
        out.append(_md_kv(list(w.items())))
    # # ASTRYM consensus-domain patch-md
    _cons = r.get("consensus") or {}
    if _cons.get("fields"):
        try:
            from astrym_consensus import _md_badge as _bdg
        except Exception:
            _bdg = lambda c, v, t: c + " (" + str(v) + "/" + str(t) + ")"
        out.append("## Consensus\n\n")
        out.append("| Field | Value | Confidence |\n")
        out.append("|:------|:------|:-----------|\n")
        for fld, c in _cons["fields"].items():
            out.append("| " + _md_escape(fld) + " | " +
                       _md_escape(c.get("value")) + " | " +
                       _bdg(c.get("confidence"),
                             c.get("votes", 0),
                             c.get("total_votes", 0)) + " |\n")
        out.append("\n")
    return "".join(out)


def _md_dns(r):
    out = []
    rec = r.get("records") or {}
    for rt, vs in rec.items():
        if not vs:
            continue
        out.append("## " + str(rt) + "\n\n")
        for v in vs:
            out.append("- `" + _md_escape(v) + "`\n")
        out.append("\n")
    ds = r.get("dnssec") or {}
    out.append("## DNSSEC\n\n")
    if ds.get("enabled"):
        out.append("**enabled** · " + str(len(ds.get("keys", []))) + " DNSKEY\n")
    else:
        out.append("_not enabled_\n")
    return "".join(out)


def _md_sub(r):
    s = r.get("stats") or {}
    out = ["## Stats\n\n"]
    out.append(_md_kv([("CT", s.get("ct_count")),
                       ("Brute", s.get("brute_count")),
                       ("Unique", s.get("total_unique")),
                       ("Wordlist", s.get("wordlist"))]))
    subs = r.get("subdomains") or []
    if subs:
        out.append("## Subdomains — " + str(len(subs)) + "\n\n")
        out.append("| Host | Sources | IPs | HTTP |\n")
        out.append("|:-----|:--------|:----|:-----|\n")
        for x in subs[:300]:
            http = ""
            if x.get("http") and x["http"].get("status"):
                http = str(x["http"]["status"])
            out.append("| `" + _md_escape(x.get("host")) + "` | " +
                       _md_escape(",".join(x.get("sources") or [])) + " | " +
                       _md_escape(",".join((x.get("ips") or [])[:3])) + " | " +
                       http + " |\n")
        out.append("\n")
    return "".join(out)


def _md_email(r):
    out = []
    ov = r.get("overview") or {}
    out.append("## Overview\n\n")
    out.append(_md_kv([("Email", ov.get("email")),
                       ("Local", ov.get("local")),
                       ("Domain", ov.get("domain")),
                       ("Provider", ov.get("provider")),
                       ("Disposable", "yes" if ov.get("disposable") else "no")]))
    mx = r.get("mx") or []
    if mx:
        out.append("## MX\n\n")
        out.append(_md_list(mx))

    smtp = r.get("smtp")
    if smtp:
        out.append("## SMTP\n\n")
        out.append("**status:** " + _md_escape(smtp.get("status")) +
                   " (code " + str(smtp.get("code")) + ")\n\n")
        out.append(_md_kv([("MX used", smtp.get("mx_used")),
                            ("Timing", str(smtp.get("timing_ms", 0)) + " ms"),
                            ("Port blocked", "yes" if smtp.get("port_blocked")
                             else "no")]))

    h = r.get("hibp") or {}
    out.append("## Have I Been Pwned\n\n")
    if h.get("found") is True:
        breaches = h.get("breaches") or []
        out.append("**BREACHED** — " + str(len(breaches)) + " breaches\n\n")
        for b in breaches[:30]:
            out.append("- " + _md_escape(b.get("Name")) + " (" +
                       _md_escape(b.get("BreachDate")) + ")\n")
    elif h.get("found") is False:
        out.append("_not found_\n")
    else:
        out.append("_unavailable_\n")
    return "".join(out)


def _md_check(r):
    out = []
    rk = r.get("risk") or {}
    lvl = rk.get("level", "?"); sc = rk.get("score", 0)
    out.append("## Risk: **" + str(lvl) + "** — " + str(sc) + "/100\n\n")
    reasons = rk.get("reasons") or []
    if reasons:
        out.append("**Reasons:**\n\n")
        for x in reasons:
            out.append("- " + _md_escape(x) + "\n")
        out.append("\n")
    errs = rk.get("api_errors") or []
    if errs:
        out.append("**API errors:**\n\n")
        for x in errs:
            out.append("- " + _md_escape(x) + "\n")
        out.append("\n")

    for src, res in (r.get("results") or {}).items():
        out.append("### " + src.upper() + "\n\n")
        if not res:
            out.append("_no data_\n\n")
            continue
        if res.get("error"):
            out.append("_Error:_ " + _md_escape(res["error"]) + "\n\n")
            continue
        if res.get("found") is False:
            out.append("_not found_\n\n")
            continue
        rows = [(k.replace("_", " "), str(v)) for k, v in res.items()
                if k not in ("source", "found", "target", "kind")
                and not isinstance(v, (list, dict))]
        if rows:
            out.append(_md_kv(rows))
    return "".join(out)


def _md_ssl(r):
    if r.get("error"):
        return "## SSL\n\n_Error: " + _md_escape(r["error"]) + "_\n"
    out = ["## Certificate\n\n"]
    out.append(_md_kv([
        ("Protocol", r.get("protocol")), ("Cipher", r.get("cipher")),
        ("Subject CN", (r.get("subject") or {}).get("commonName")),
        ("Issuer CN", (r.get("issuer") or {}).get("commonName")),
        ("Not before", r.get("not_before")),
        ("Not after", r.get("not_after")),
        ("Days valid", r.get("days_valid"))]))
    san = r.get("san") or []
    if san:
        out.append("## SAN (" + str(len(san)) + ")\n\n")
        out.append(_md_list(san[:60]))
    return "".join(out)


def _md_web(r):
    out = ["## Overview\n\n"]
    out.append(_md_kv([("Final URL", r.get("final_url")),
                       ("Status", r.get("status_code")),
                       ("Title", r["titles"][0] if r.get("titles") else "-")]))
    cms = r.get("cms_detected") or []
    if cms:
        out.append("## Technologies\n\n")
        out.append(_md_list(cms))
    hdrs = r.get("headers") or {}
    if hdrs:
        out.append("## Headers\n\n")
        out.append(_md_kv(list(hdrs.items())))
    leaks = r.get("leaks") or []
    if leaks:
        out.append("## Exposed paths\n\n")
        out.append("| Path | Status | What |\n")
        out.append("|:-----|:-------|:-----|\n")
        for x in leaks:
            out.append("| `" + _md_escape(x.get("path")) + "` | " +
                       str(x.get("status")) + " | " +
                       _md_escape(x.get("what")) + " |\n")
        out.append("\n")
    fh = r.get("favicon_hash")
    if fh is not None:
        out.append("## Favicon MMH3\n\n`" + str(fh) + "`\n\n")
        out.append("[Shodan search](https://www.shodan.io/search?"
                    "query=http.favicon.hash:" + str(fh) + ")\n\n")
    an = r.get("analytics") or {}
    if an:
        out.append("## Shared analytics\n\n")
        for k, ids in an.items():
            out.append("- **" + _md_escape(k) + "**: " +
                       ", ".join("`" + _md_escape(i) + "`" for i in ids[:5]) +
                       "\n")
        out.append("\n")
    return "".join(out)


def _md_takeover(r):
    vuln = r.get("vulnerable") or []
    out = ["## Summary\n\n"]
    out.append(_md_kv([("Checked", r.get("checked", 0)),
                       ("Vulnerable", len(vuln))]))
    if vuln:
        out.append("## Vulnerable subdomains\n\n")
        out.append("| Subdomain | Service | CNAME | Status |\n")
        out.append("|:----------|:--------|:------|:-------|\n")
        for x in vuln:
            out.append("| `" + _md_escape(x.get("subdomain")) + "` | " +
                       _md_escape(x.get("service")) + " | `" +
                       _md_escape(x.get("cname")) + "` | " +
                       str(x.get("status_code")) + " |\n")
        out.append("\n")
    return "".join(out)


def _md_origin(r):
    out = ["## Summary\n\n"]
    out.append(_md_kv([("Cloudflare",
                        "yes" if r.get("is_cloudflare") else "no"),
                       ("Current IPs",
                        ", ".join(r.get("current_ips") or []))]))
    cand = r.get("candidates") or []
    if cand:
        out.append("## Candidate origin IPs\n\n")
        out.append(_md_list(cand))
    src = r.get("sources") or {}
    if src:
        out.append("## Sources\n\n")
        for k, v in src.items():
            out.append("### " + str(k) + "\n\n")
            if isinstance(v, dict):
                out.append(_md_kv(list(v.items())))
            elif isinstance(v, list):
                out.append(_md_list(v))
    return "".join(out)


def _md_whois_history(r):
    out = ["## Timeline\n\n"]
    for row in (r.get("timeline") or [])[:60]:
        if isinstance(row, (list, tuple)) and len(row) >= 2:
            out.append("- `" + _md_escape(row[0]) + "` — " +
                       _md_escape(row[1]) + "\n")
    out.append("\n")
    used = r.get("sources_used") or []
    if used:
        out.append("## Sources used\n\n")
        out.append(_md_list(used))
    return "".join(out)


def _md_phone(r):
    p = r.get("parsed") or {}
    out = ["## Parsed\n\n"]
    out.append(_md_kv([("E.164", p.get("e164")),
                       ("International", p.get("international")),
                       ("Country", p.get("region")),
                       ("Carrier", p.get("carrier")),
                       ("Line type", p.get("line_type")),
                       ("Timezones", ", ".join(p.get("timezones") or []))]))
    msgr = r.get("messengers") or {}
    if msgr:
        out.append("## Messengers\n\n")
        out.append(_md_kv(list(msgr.items())))
    rep = r.get("reputation") or {}
    if rep:
        out.append("## Reputation links\n\n")
        out.append(_md_kv(list(rep.items())))
    return "".join(out)


def _md_darkweb(r):
    if r.get("error"):
        return "## Darkweb\n\n_Error: " + _md_escape(r["error"]) + "_\n"
    out = ["## Overview\n\n"]
    out.append(_md_kv([("Pages crawled", r.get("pages_crawled", 0))]))
    for k, vals in (r.get("entities") or {}).items():
        if vals:
            out.append("## " + str(k).upper() + "\n\n")
            out.append(_md_list(vals[:50]))
    return "".join(out)


def _md_generic(r):
    out = ["## Data\n\n"]
    for k, v in r.items():
        if k == "meta":
            continue
        if isinstance(v, (str, int, float, bool)):
            out.append("- **" + _md_escape(k) + "**: " + _md_escape(v) + "\n")
        elif isinstance(v, list) and v and isinstance(v[0], str):
            out.append("- **" + _md_escape(k) + "**: " +
                       ", ".join(_md_escape(x) for x in v[:20]) + "\n")
    out.append("\n")
    return "".join(out)


_MD_BY_TYPE = {
    "ip": _md_ip, "domain": _md_domain, "dns": _md_dns,
    "sub": _md_sub, "email": _md_email, "check": _md_check,
    "ssl": _md_ssl, "web": _md_web,
    "takeover": _md_takeover, "origin": _md_origin,
    "whois-history": _md_whois_history,
    "phone": _md_phone, "darkweb": _md_darkweb,
}


def _md_extended(r):
    out = []
    ext = r.get("extended")
    if ext:
        out.append("## Extended sources\n\n")
        for src, vals in ext.items():
            out.append("### " + str(src) + "\n\n")
            if isinstance(vals, dict):
                rows = [(k, v) for k, v in vals.items()
                        if isinstance(v, (str, int, float, bool))]
                if rows:
                    out.append(_md_kv(rows))
                else:
                    out.append("_data present (see JSON)_\n\n")
            elif isinstance(vals, list):
                for v in vals[:30]:
                    out.append("- " + _md_escape(v) + "\n")
                out.append("\n")
    links = r.get("extended_links")
    if links:
        out.append("## External services\n\n")
        for name, url in links:
            out.append("- [" + _md_escape(name) + "](" + str(url) + ")\n")
        out.append("\n")
    return "".join(out)


def _md_raw_block(r):
    import json as _json
    try:
        txt = _json.dumps(r, indent=2, ensure_ascii=False, default=str)
    except Exception:
        return ""
    if len(txt) > 20000:
        txt = txt[:20000] + "\n... [truncated]"
    return ("\n## Raw JSON\n\n```json\n" + txt + "\n```\n")


def save_md(results, base):
    try:
        p = Path(str(base) + ".md")
        r = results[0]
        t = r.get("meta", {}).get("type", "?")
        tgt = r.get("meta", {}).get("target", "?")
        body_fn = _MD_BY_TYPE.get(t, _md_generic)

        parts = []
        parts.append(_md_frontmatter(r))
        parts.append("# ASTRYM Report: " + str(tgt) + "\n\n")
        parts.append("> **Type:** " + str(t) +
                     "  ·  **Tool:** ASTRYM  \n")
        parts.append("> _Generated by ASTRYM — "
                     "import into AFFiNE via File → Import → Markdown_\n\n")
        parts.append("---\n\n")
        parts.append(body_fn(r))
        parts.append(_md_extended(r))
        parts.append(_md_raw_block(r))

        text = "".join(parts)
        p.write_text(text, encoding="utf-8")
        c_ok("MD -> " + str(p))
        return p
    except Exception as e:
        c_err("MD: " + str(e))
        return None


# end ASTRYM markdown export


def output_results(results, fmt="console", base=None, auto_kind=None,
                   render_fn=None):
    if not results:
        c_warn("no results")
        return
    fmts = [x.strip().lower() for x in fmt.split(",") if x.strip()]
    if "all" in fmts:
        fmts = ["console", "json", "html", "csv", "md", "topology"]
    if not base and auto_kind:
        base = auto_path(auto_kind)
        c_info("auto-output: " + str(base) + ".*")
    if base is None:
        base = RESULTS_DIR / "out"

    for f in fmts:
        if f == "console":
            if render_fn:
                for r in results:
                    try: render_fn(r)
                    except Exception as e:
                        c_err("render: " + str(e))
        elif f == "json":
            save_json(results, base)
        elif f == "html":
            save_html(results, base)
        elif f == "csv":
            save_csv(results, base)
        elif f == "pdf":
            save_pdf(results, base)
        elif f == "topology":
            save_topology(results, base)
        elif f == "md":
            save_md(results, base)
        else:
            c_warn("unknown format: " + f)


# ============================================================
# ASTRYM stix-formats patch
# Оборачиваем output_results: для auto_kind == "stix" делегируем
# в astrym_stix_output.output_stix_results.
# ============================================================

_output_results_orig = output_results


def output_results(results, fmt="console", base=None, auto_kind=None,
                    render_fn=None):
    if auto_kind == "stix":
        try:
            from astrym_stix_output import output_stix_results
            output_stix_results(results, fmt, base)
            return
        except Exception as _e:
            c_err("stix output: " + str(_e))
    return _output_results_orig(results, fmt, base, auto_kind, render_fn)
# end ASTRYM stix-formats patch


# ═══════════════════════════════════════════════
# ASTRYM Recon HTML renderers
# ═══════════════════════════════════════════════

def _html_username(r):
    out = []
    found = r.get("found") or []
    errs = r.get("errors") or []
    out.append("<div class='card'><div class='ct'>Summary</div>" +
               _kv_block([
                   ("username", r.get("username")),
                   ("checked", r.get("total_checked")),
                   ("found", len(found)),
                   ("not found", r.get("not_found")),
                   ("errors", len(errs)),
               ]) + "</div>")
    if found:
        rows = "".join(
            "<tr><td>" + _esc(x.get("site")) + "</td>"
            "<td><a href='" + _esc(x.get("url")) + "' target='_blank'>" +
            _esc(x.get("url")) + "</a></td></tr>"
            for x in found)
        out.append("<div class='card'><div class='ct'>Found (" +
                   str(len(found)) + ")</div>"
                   "<table class='kv'>" + rows + "</table></div>")
    else:
        out.append("<div class='card'><div class='ct'>Found</div>"
                   "<p class='warn'>нигде не найдено</p></div>")
    if errs:
        rows = "".join(
            "<tr><td>" + _esc(e.get("site")) + "</td><td>" +
            _esc(e.get("error") or e.get("status")) + "</td></tr>"
            for e in errs)
        out.append("<div class='card'><div class='ct'>Errors (" +
                   str(len(errs)) + ")</div>"
                   "<table class='kv'>" + rows + "</table></div>")
    return "".join(out)


def _html_dork(r):
    out = []
    dorks = r.get("dorks") or []
    out.append("<div class='card'><div class='ct'>Summary</div>" +
               _kv_block([
                   ("target", r.get("target")),
                   ("category", "domain" if r.get("is_domain") else "string"),
                   ("dorks", r.get("count")),
               ]) + "</div>")
    by_cat = {}
    for x in dorks:
        by_cat.setdefault(x.get("category", "other"), []).append(x)
    for cat in sorted(by_cat.keys()):
        items = by_cat[cat]
        rows = "".join(
            "<tr><td><code>" + _esc(x.get("query")) + "</code></td>"
            "<td><a href='" + _esc(x.get("url")) +
            "' target='_blank'>open</a></td></tr>"
            for x in items)
        out.append("<div class='card'><div class='ct'>" + _esc(cat) +
                   " (" + str(len(items)) + ")</div>"
                   "<table class='kv'>" + rows + "</table></div>")
    return "".join(out)


_HTML_BY_TYPE["username"] = _html_username
_HTML_BY_TYPE["dork"] = _html_dork
