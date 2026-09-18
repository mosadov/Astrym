#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Consensus 9.9.0 — multi-source field voting + confidence

CONSENSUS_VERSION = "9.9.0"

import re
from collections import defaultdict

try:
    import pycountry
    _HAS_PYCOUNTRY = True
except ImportError:
    _HAS_PYCOUNTRY = False


# ============================================================
# NORMALIZERS
# ============================================================

_COUNTRY_ALIASES = {
    "united states": "US", "united states of america": "US", "usa": "US",
    "u.s.a": "US", "u.s": "US", "us": "US",
    "united kingdom": "GB", "great britain": "GB", "uk": "GB",
    "russia": "RU", "russian federation": "RU",
    "china": "CN", "peoples republic of china": "CN",
    "germany": "DE", "deutschland": "DE",
    "france": "FR", "netherlands": "NL", "holland": "NL",
    "japan": "JP", "south korea": "KR", "korea": "KR",
    "canada": "CA", "australia": "AU", "brazil": "BR",
    "india": "IN", "italy": "IT", "spain": "ES", "poland": "PL",
    "ukraine": "UA", "sweden": "SE", "norway": "NO", "finland": "FI",
    "switzerland": "CH", "austria": "AT", "belgium": "BE",
    "ireland": "IE", "denmark": "DK", "czechia": "CZ",
    "czech republic": "CZ", "turkey": "TR", "singapore": "SG",
    "hong kong": "HK", "taiwan": "TW", "israel": "IL",
    "mexico": "MX", "argentina": "AR", "south africa": "ZA",
}

_ISP_STOP = {
    "inc", "llc", "ltd", "corp", "corporation", "co", "company",
    "gmbh", "bv", "ab", "sa", "srl", "plc", "pte", "pvt",
    "limited", "holdings", "group", "as", "asn", "block",
    "network", "networks", "net", "internet", "service", "services",
    "systems", "technologies", "solutions", "communications",
}


def _norm_country(v):
    if not v:
        return None
    s = str(v).strip()
    if not s:
        return None
    if len(s) == 2 and s.isalpha():
        return s.upper()
    low = s.lower()
    if low in _COUNTRY_ALIASES:
        return _COUNTRY_ALIASES[low]
    if _HAS_PYCOUNTRY:
        try:
            return pycountry.countries.lookup(s).alpha_2
        except LookupError:
            pass
    return None


def _norm_asn(v):
    if v is None:
        return None
    m = re.search(r"(\d{1,10})", str(v))
    if not m:
        return None
    return "AS" + m.group(1)


def _norm_isp(v):
    if not v:
        return None
    s = str(v).lower()
    s = re.sub(r"[^\w\s]", " ", s)
    words = [w for w in s.split() if w and w not in _ISP_STOP]
    if not words:
        return None
    return " ".join(sorted(words))


def _norm_city(v):
    if not v:
        return None
    s = str(v).lower().strip()
    s = re.sub(r"\s+", " ", s)
    return s or None


def _norm_tz(v):
    if not v:
        return None
    return str(v).strip().lower()


def _norm_generic(v):
    if v is None:
        return None
    s = str(v).strip()
    return s.lower() if s else None


NORMALIZERS = {
    "country": _norm_country,
    "city": _norm_city,
    "region": _norm_city,
    "isp": _norm_isp,
    "org": _norm_isp,
    "asn": _norm_asn,
    "timezone": _norm_tz,
}


# ============================================================
# SOURCE → FIELD MAPPING
# ============================================================

SOURCE_FIELD_MAP = {
    "ip-api": {
        "country": "country",
        "city": "city",
        "region": "regionName",
        "isp": "isp",
        "org": "org",
        "asn": "as",
        "timezone": "timezone",
    },
    "ipwho": {
        "country": "country",
        "city": "city",
        "region": "region",
        "isp": "isp",
        "org": "org",
        "asn": "asn",
    },
    "ipapi": {
        "country": "country",
        "city": "city",
        "region": "region",
        "org": "org",
        "asn": "asn",
    },
    "ipinfo": {
        "city": "city",
        "region": "region",
        "org": "org",
        "timezone": "timezone",
    },
    "bgpview": {
        "asn": "asn",
    },
    "team_cymru": {
        "country": "country",
        "asn": "asn",
    },
}


def _get(d, path):
    cur = d
    for p in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
        if cur is None:
            return None
    return cur


# ============================================================
# FIELD CONSENSUS
# ============================================================

class FieldConsensus:
    def __init__(self, field, normalizer=None):
        self.field = field
        self.normalizer = normalizer or _norm_generic
        self.votes = defaultdict(list)   # norm_value → [(source, raw)]
        self.raws = {}                   # source → raw value

    def add(self, source, raw_value):
        if raw_value is None or raw_value == "":
            return
        norm = self.normalizer(raw_value)
        if norm is None:
            return
        self.votes[norm].append(source)
        self.raws[source] = raw_value

    def result(self):
        total = sum(len(v) for v in self.votes.values())
        if total == 0:
            return None

        sorted_v = sorted(self.votes.items(), key=lambda x: -len(x[1]))
        winner, winners = sorted_v[0]
        win_count = len(winners)
        ratio = win_count / total

        if win_count >= 3 and ratio >= 0.6:
            conf = "confirmed"
        elif win_count >= 2 and ratio >= 0.5:
            conf = "likely"
        elif win_count == 1 and total == 1:
            conf = "single"
        elif ratio < 0.5 and len(sorted_v) > 1:
            conf = "conflict"
        else:
            conf = "weak"

        alternatives = []
        for val, srcs in sorted_v[1:4]:
            alternatives.append({
                "value": val,
                "count": len(srcs),
                "sources": list(srcs),
                "raw": [self.raws.get(s) for s in srcs],
            })

        return {
            "field": self.field,
            "value": winner,
            "confidence": conf,
            "votes": win_count,
            "total_votes": total,
            "ratio": round(ratio, 2),
            "sources": list(winners),
            "raw_values": {s: self.raws[s] for s in winners},
            "alternatives": alternatives,
        }


# ============================================================
# PUBLIC API
# ============================================================

def collect_consensus(sources_dict, field_map=None, min_sources=1):
    if not isinstance(sources_dict, dict):
        return {}
    field_map = field_map or SOURCE_FIELD_MAP

    fields = set()
    for src_cfg in field_map.values():
        fields.update(src_cfg.keys())

    out = {}
    for field in fields:
        fc = FieldConsensus(field, NORMALIZERS.get(field))
        srcs_with_field = 0
        for src_name, src_cfg in field_map.items():
            if field not in src_cfg:
                continue
            data = sources_dict.get(src_name)
            if not isinstance(data, dict):
                continue
            raw = _get(data, src_cfg[field])
            if raw is None or raw == "":
                continue
            srcs_with_field += 1
            fc.add(src_name, raw)
        if srcs_with_field < min_sources:
            continue
        r = fc.result()
        if r:
            out[field] = r
    return out


def consensus_for_ip(ip_result):
    """Высокоуровневая обёртка: берёт dict результата collect_ip,
    подмешивает extended, возвращает consensus-словарь."""
    sources = {}
    geo = ip_result.get("geo") or {}
    if isinstance(geo, dict) and "error" not in geo:
        sources["ip-api"] = geo
    ext = ip_result.get("extended") or {}
    if isinstance(ext, dict):
        for k, v in ext.items():
            if isinstance(v, dict) and v:
                sources[k] = v
    return collect_consensus(sources)


def aggregate(ip_result):
    """Собирает consensus + summary."""
    cons = consensus_for_ip(ip_result)
    summary = {"confirmed": 0, "likely": 0, "single": 0,
               "weak": 0, "conflict": 0}
    for f in cons.values():
        summary[f["confidence"]] = summary.get(f["confidence"], 0) + 1
    return {"fields": cons, "summary": summary}


def render_consensus_block(cons, section_fn=None, kv_fn=None,
                            c_ok_fn=None, c_warn_fn=None,
                            c_err_fn=None, c_muted_fn=None):
    """Рендер для встраивания в другие render-функции.

    # ASTRYM two-bugs fix
    Порядок полей: известные — в фиксированном порядке, остальные —
    по алфавиту. Работает и для IP, и для domain.
    """
    if not cons:
        return
    fields = cons.get("fields") or cons
    if not fields:
        return
    if section_fn:
        section_fn("Consensus (multi-source)")

    PREFERRED = (
        "country", "city", "region", "isp", "org", "asn", "timezone",
        "registrar", "creation_date", "updated_date",
        "expiry_date", "name_server", "dnssec",
    )
    seen = set()
    ordered = []
    for f in PREFERRED:
        if f in fields:
            ordered.append(f)
            seen.add(f)
    for f in sorted(fields.keys()):
        if f not in seen:
            ordered.append(f)

    for field in ordered:
        c = fields.get(field)
        if not c:
            continue
        val = c.get("value") or "?"
        conf = c.get("confidence", "?")
        votes = c.get("votes", 0)
        total = c.get("total_votes", 0)

        line = ("  " + str(field).ljust(14) + " " +
                str(val)[:38].ljust(38) + "  " +
                str(conf) + " (" + str(votes) + "/" + str(total) + ")")

        if c_ok_fn and conf in ("confirmed", "likely"):
            c_ok_fn(line)
        elif c_err_fn and conf == "conflict":
            c_err_fn(line)
        elif c_warn_fn and conf == "weak":
            c_warn_fn(line)
        elif c_muted_fn:
            c_muted_fn(line)

        for a in (c.get("alternatives") or [])[:2]:
            if c_muted_fn:
                c_muted_fn("               ↳ alt: " +
                           str(a.get("value"))[:30] +
                           " (" + str(a.get("count")) + " src)")


def render_consensus(ip_result_or_dict):
    """Полный рендер — для standalone команды consensus."""
    from astrym_core import header, section, kv, c_ok, c_warn, c_err, c_muted
    if isinstance(ip_result_or_dict, dict) and "fields" in ip_result_or_dict:
        agg = ip_result_or_dict
    else:
        agg = aggregate(ip_result_or_dict)
    header("Consensus", "multi-source field voting")
    cons = agg.get("fields") or {}
    if not cons:
        c_muted("no sources with comparable data")
        return
    s = agg.get("summary") or {}
    kv([("confirmed", s.get("confirmed", 0)),
        ("likely", s.get("likely", 0)),
        ("single", s.get("single", 0)),
        ("weak", s.get("weak", 0)),
        ("conflict", s.get("conflict", 0))])
    render_consensus_block(cons, section, kv, c_ok, c_warn, c_err, c_muted)


def run_consensus(target, extras=False):
    from astrym_core import is_ip, c_err
    if not is_ip(target):
        c_err("consensus currently supports IP addresses only")
        return None
    from astrym_ip import collect_ip, _x_ip
    d = collect_ip(target)
    d["extended"] = _x_ip(target)
    agg = aggregate(d)
    if not agg.get("fields"):
        c_err("no consensus available (all sources empty)")
        return None
    agg["meta"] = {
        "type": "consensus",
        "target": target,
        "generated_at": __import__("astrym_core").now_iso(),
        "tool": "ASTRYM " + CONSENSUS_VERSION,
    }
    return agg


# ASTRYM consensus-domain patch
# Расширение astrym_consensus.py: голосование по domain-полям.
# Не трогает IP-часть, дописывается в конец модуля.

try:
    import requests as _cd_requests
    _CD_HAS_REQUESTS = True
except ImportError:
    _CD_HAS_REQUESTS = False


def _norm_registrar(v):
    if not v:
        return None
    s = str(v).lower()
    s = re.sub(r"[^\w\s]", " ", s)
    for w in ("inc", "llc", "ltd", "corp", "co", "gmbh", "bv",
              "sa", "srl", "plc", "pte", "pvt", "limited",
              "company", "corporation", "group", "holdings",
              "domains", "domain"):
        s = re.sub(r"\b" + w + r"\b", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s or None


def _norm_date(v):
    if not v:
        return None
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", str(v))
    if m:
        return m.group(0)
    m = re.search(r"(\d{1,2})-([A-Za-z]{3})-(\d{4})", str(v))
    if m:
        months = {"jan": "01", "feb": "02", "mar": "03", "apr": "04",
                  "may": "05", "jun": "06", "jul": "07", "aug": "08",
                  "sep": "09", "oct": "10", "nov": "11", "dec": "12"}
        mon = months.get(m.group(2).lower())
        if mon:
            return m.group(3) + "-" + mon + "-" + m.group(1).zfill(2)
    return None


def _norm_ns(v):
    if not v:
        return None
    parts = [p.strip().lower().rstrip(".") for p in str(v).split(",")]
    parts = [p for p in parts if p]
    if not parts:
        return None
    return ",".join(sorted(set(parts)))


def _norm_dnssec(v):
    # ASTRYM ip-consensus+dnssec fix
    # Порядок важен: "unsigned" содержит "signed" — проверяем отрицание раньше.
    if not v:
        return None
    s = str(v).lower().strip()
    if s in ("unsigned", "no", "disabled", "not signed", "off"):
        return "no"
    if s in ("signed", "yes", "enabled", "on"):
        return "yes"
    if "unsigned" in s or "not signed" in s or "disabled" in s:
        return "no"
    if "signed" in s or "enabled" in s:
        return "yes"
    return None


def _get_first(d, keys):
    if isinstance(keys, str):
        keys = [keys]
    if not isinstance(d, dict):
        return None
    for k in keys:
        v = d.get(k)
        if v is not None and v != "":
            return v
    return None


def _fetch_rdap_domain(domain, timeout=8):
    if not _CD_HAS_REQUESTS:
        return None
    try:
        r = _cd_requests.get("https://rdap.org/domain/" + domain,
                              timeout=timeout)
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None

    out = {}

    for e in (d.get("entities") or []):
        roles = e.get("roles") or []
        if "registrar" in roles:
            vcard = e.get("vcardArray") or []
            if len(vcard) >= 2 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if (isinstance(item, list) and len(item) >= 4
                            and item[0] == "fn"):
                        out["registrar"] = item[3]
                        break
            break

    for ev in (d.get("events") or []):
        action = (ev.get("eventAction") or "").lower()
        date = ev.get("eventDate") or ""
        if action in ("registration", "registered"):
            out["creation_date"] = date[:10]
        elif action in ("expiration", "expiry"):
            out["expiry_date"] = date[:10]
        elif action == "last changed":
            out["updated_date"] = date[:10]

    nss = []
    for ns in (d.get("nameservers") or []):
        name = ns.get("ldhName")
        if name:
            nss.append(str(name).lower().rstrip("."))
    if nss:
        out["name_server"] = ",".join(sorted(set(nss)))

    return out or None


def _build_domain_sources(result):
    """Собирает источники для domain-голосования."""
    sources = {}

    w = result.get("whois") or {}
    if isinstance(w, dict) and w:
        sources["whois"] = w

    meta = result.get("meta") or {}
    domain = meta.get("target", "")
    if domain and "." in domain:
        rdap = _fetch_rdap_domain(domain)
        if rdap:
            sources["rdap"] = rdap

    dns = result.get("dns") or {}
    ns_list = dns.get("NS") or []
    if ns_list:
        sources["dns"] = {
            "name_server": ",".join(
                sorted(str(x).rstrip(".").lower() for x in ns_list))
        }

    return sources


SOURCE_FIELD_MAP_DOMAIN = {
    "whois": {
        "registrar":     ["registrar", "registrant", "registrant organization",
                          "registrant org", "org", "organization"],
        "creation_date": ["creation date", "created", "created on",
                          "registered on", "domain registration date"],
        "expiry_date":   ["expiry", "expiration", "registry expiry date",
                          "expiration date", "expires", "paid-till"],
        "updated_date":  ["updated date", "last updated", "changed",
                          "last modified"],
        "name_server":   ["name server", "nserver", "nameserver"],
        "dnssec":        ["dnssec"],
    },
    "rdap": {
        "registrar":     "registrar",
        "creation_date": "creation_date",
        "expiry_date":   "expiry_date",
        "updated_date":  "updated_date",
        "name_server":   "name_server",
    },
    "dns": {
        "name_server":   "name_server",
    },
}


def consensus_for_domain(result):
    sources = _build_domain_sources(result)
    if not sources:
        return {}

    fields = set()
    for cfg in SOURCE_FIELD_MAP_DOMAIN.values():
        fields.update(cfg.keys())

    out = {}
    for field in fields:
        fc = FieldConsensus(field, NORMALIZERS.get(field))
        srcs_with_field = 0
        for src_name, src_cfg in SOURCE_FIELD_MAP_DOMAIN.items():
            if field not in src_cfg:
                continue
            data = sources.get(src_name)
            if not isinstance(data, dict):
                continue
            raw = _get_first(data, src_cfg[field])
            if raw is None or raw == "":
                continue
            srcs_with_field += 1
            fc.add(src_name, raw)
        if srcs_with_field < 1:
            continue
        r = fc.result()
        if r:
            out[field] = r
    return out


def aggregate_domain(result):
    cons = consensus_for_domain(result)
    summary = {"confirmed": 0, "likely": 0, "single": 0,
               "weak": 0, "conflict": 0}
    for f in cons.values():
        summary[f["confidence"]] = summary.get(f["confidence"], 0) + 1
    return {"fields": cons, "summary": summary}


def render_consensus_domain(result):
    from astrym_core import header, section, kv, c_ok, c_warn, c_err, c_muted
    agg = aggregate_domain(result)
    header("Domain Consensus", "multi-source field voting")
    cons = agg.get("fields") or {}
    if not cons:
        c_muted("no sources with comparable data")
        return
    s = agg.get("summary") or {}
    kv([("confirmed", s.get("confirmed", 0)),
        ("likely", s.get("likely", 0)),
        ("single", s.get("single", 0)),
        ("weak", s.get("weak", 0)),
        ("conflict", s.get("conflict", 0))])
    render_consensus_block(cons, section, kv, c_ok, c_warn, c_err, c_muted)


def _md_badge(conf, votes, total):
    label = conf.upper() if conf == "conflict" else conf
    return label + " (" + str(votes) + "/" + str(total) + ")"


def _html_badge(conf, votes, total):
    colors = {"confirmed": "#4ade80", "likely": "#a3e635",
              "single": "#888888", "weak": "#fbbf24",
              "conflict": "#f87171"}
    c = colors.get(conf, "#888888")
    label = conf.upper() if conf == "conflict" else conf
    return ('<span style="color:' + c + ';font-weight:600">' +
            label + ' (' + str(votes) + '/' + str(total) + ')</span>')
# end ASTRYM consensus-domain patch


# ============================================================
# ASTRYM v4 consensus polish (appended overrides)
# Python выполняет top-to-bottom; эти определения перекрывают
# старые версии из верхней части файла.
# ============================================================


# --- 1. _ISP_STOP: дополняем стоп-словами (in-place, не переопределяем) ---

_ISP_STOP = _ISP_STOP | {
    "dns", "public", "anycast", "resolver", "resolvers", "ns",
    "hosting", "cloud", "transit", "peer", "peering", "backbone",
    "data", "center", "centers", "colocation", "colo",
    "saas", "iaas", "paas", "cdn", "edge", "core",
    "isp", "provider", "operator", "telecom", "telecommunications",
}


# --- 2. Новый _norm_isp с вырезанием AS-префиксов ---

def _norm_isp(v):
    if not v:
        return None
    s = str(v).lower()
    s = re.sub(r"[^\w\s]", " ", s)
    s = re.sub(r"\b(?:as|asn)\d+\b", " ", s)
    words = [w for w in s.split() if w and w not in _ISP_STOP]
    if not words:
        return None
    return " ".join(sorted(words))


# перепривязываем NORMALIZERS к новой функции
NORMALIZERS["isp"] = _norm_isp
NORMALIZERS["org"] = _norm_isp


# --- 3. Anycast detection ---

_ANYCAST_V4 = [
    "8.8.8.0/24",      "8.8.4.0/24",
    "1.1.1.0/24",      "1.0.0.0/24",
    "9.9.9.0/24",      "149.112.112.0/24",
    "208.67.222.0/24", "208.67.220.0/24",
    "77.88.8.0/24",
    "64.6.64.0/24",    "64.6.65.0/24",
    "156.154.70.0/24", "156.154.71.0/24",
    "185.228.168.0/24","185.228.169.0/24",
    "76.76.2.0/24",    "76.76.19.0/24",
    "94.140.14.0/24",  "94.140.15.0/24",
    "198.101.242.0/24",
]


def is_anycast(ip):
    """True если IP в известной public-DNS anycast-сети."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(str(ip).strip())
    except Exception:
        return False
    for net in _ANYCAST_V4:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return True
        except Exception:
            continue
    return False


# --- 4. Новый aggregate с anycast-флагом ---

def aggregate(ip_result):
    cons = consensus_for_ip(ip_result)
    meta = ip_result.get("meta") or {}
    target = meta.get("target", "")
    if target and is_anycast(target):
        cons["_anycast"] = {"value": True, "confidence": "note",
                            "votes": 0, "total_votes": 0, "sources": []}
    summary = {"confirmed": 0, "likely": 0, "single": 0,
               "weak": 0, "conflict": 0}
    for k, f in cons.items():
        if k.startswith("_"):
            continue
        conf = f.get("confidence", "single")
        summary[conf] = summary.get(conf, 0) + 1
    return {"fields": cons, "summary": summary}


# --- 5. Новый render_consensus_block (anycast-aware) ---

def render_consensus_block(cons, section_fn=None, kv_fn=None,
                            c_ok_fn=None, c_warn_fn=None,
                            c_err_fn=None, c_muted_fn=None):
    if not cons:
        return
    fields = cons.get("fields") or cons
    if not fields:
        return
    if section_fn:
        section_fn("Consensus (multi-source)")

    anycast = bool(fields.get("_anycast"))
    if anycast and c_muted_fn:
        c_muted_fn("  i  anycast IP - один адрес физически живёт "
                   "в нескольких дата-центрах")
        c_muted_fn("     city / region / timezone неоднозначны, "
                   "показаны как anycast (не conflict)")
        c_muted_fn("")

    PREFERRED = (
        "country", "city", "region", "isp", "org", "asn", "timezone",
        "registrar", "creation_date", "updated_date",
        "expiry_date", "name_server", "dnssec",
    )
    seen = set()
    ordered = []
    for f in PREFERRED:
        if f in fields:
            ordered.append(f); seen.add(f)
    for f in sorted(fields.keys()):
        if f not in seen and not f.startswith("_"):
            ordered.append(f)

    ANYCAST_GEO = {"city", "region", "timezone"}

    for field in ordered:
        c = fields.get(field)
        if not c:
            continue
        val = c.get("value") or "?"
        conf = c.get("confidence", "?")
        votes = c.get("votes", 0)
        total = c.get("total_votes", 0)

        if anycast and field in ANYCAST_GEO and conf == "conflict":
            conf = "anycast"

        line = ("  " + str(field).ljust(14) + " " +
                str(val)[:38].ljust(38) + "  " +
                str(conf) + " (" + str(votes) + "/" + str(total) + ")")

        if c_ok_fn and conf in ("confirmed", "likely"):
            c_ok_fn(line)
        elif conf == "anycast":
            if c_muted_fn: c_muted_fn(line)
        elif c_err_fn and conf == "conflict":
            c_err_fn(line)
        elif c_warn_fn and conf == "weak":
            c_warn_fn(line)
        elif c_muted_fn:
            c_muted_fn(line)

        if anycast and field in ANYCAST_GEO:
            continue
        for a in (c.get("alternatives") or [])[:2]:
            if c_muted_fn:
                c_muted_fn("               -> alt: " +
                           str(a.get("value"))[:30] +
                           " (" + str(a.get("count")) + " src)")
# end ASTRYM v4 consensus polish
