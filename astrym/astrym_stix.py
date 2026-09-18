#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM STIX 9.9.0 — STIX 2.1 bundle export (no external deps)

STIX_VERSION = ""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from astrym_core import (RESULTS_DIR, now_iso, classify,
                          hist_record, c_ok, c_err, c_info, c_muted)


# ============================================================
# ID HELPERS (STIX требует "type--uuid4")
# ============================================================

def _sid(kind):
    return f"{kind}--{uuid.uuid4()}"


def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ============================================================
# SCO BUILDERS
# ============================================================

def _sco_identity_astrym():
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _sid("identity"),
        "created": _ts(),
        "modified": _ts(),
        "name": "ASTRYM",
        "description": "OSINT analysis tool (open source)",
        "identity_class": "system",
        "sectors": ["technology"],
        "x_astrym_version": STIX_VERSION,
    }


def _sco_domain(name):
    return {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": _sid("domain-name"),
        "value": str(name).lower().strip("."),
    }


def _sco_ipv4(ip):
    return {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": _sid("ipv4-addr"),
        "value": str(ip).strip(),
    }


def _sco_ipv6(ip):
    return {
        "type": "ipv6-addr",
        "spec_version": "2.1",
        "id": _sid("ipv6-addr"),
        "value": str(ip).strip(),
    }


def _sco_asn(number, name=None):
    obj = {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": _sid("autonomous-system"),
        "number": int(number),
    }
    if name:
        obj["name"] = str(name)[:200]
    return obj


def _sco_email(addr):
    return {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": _sid("email-addr"),
        "value": str(addr).strip().lower(),
    }


def _sco_url(url):
    return {
        "type": "url",
        "spec_version": "2.1",
        "id": _sid("url"),
        "value": str(url).strip(),
    }


# ============================================================
# SDO BUILDERS
# ============================================================

def _sdo_observed_data(refs, first_seen=None):
    return {
        "type": "observed-data",
        "spec_version": "2.1",
        "id": _sid("observed-data"),
        "created": _ts(),
        "modified": _ts(),
        "first_observed": first_seen or _ts(),
        "last_observed": _ts(),
        "number_observed": 1,
        "object_refs": list(refs),
        "x_astrym_source": "astrym-scan",
    }


def _sdo_indicator(pattern, name=None, description=None,
                    labels=None, confidence=None):
    obj = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _sid("indicator"),
        "created": _ts(),
        "modified": _ts(),
        "valid_from": _ts(),
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": labels or ["anomalous-activity"],
    }
    if name:
        obj["name"] = name[:200]
    if description:
        obj["description"] = description[:1000]
    if confidence is not None:
        obj["confidence"] = int(confidence)
    return obj


def _sro_relationship(src_ref, tgt_ref, rel_type, description=None):
    obj = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _sid("relationship"),
        "created": _ts(),
        "modified": _ts(),
        "relationship_type": rel_type,
        "source_ref": src_ref,
        "target_ref": tgt_ref,
    }
    if description:
        obj["description"] = description[:500]
    return obj


def _sro_note(refs, content):
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": _sid("note"),
        "created": _ts(),
        "modified": _ts(),
        "abstract": "ASTRYM analysis note",
        "content": content[:2000],
        "object_refs": list(refs),
    }


# ============================================================
# BUNDLE BUILDER
# ============================================================

def build_bundle(result):
    """Принимает dict ASTRYM-результата, отдаёт STIX bundle dict."""
    if not isinstance(result, dict):
        return None
    meta = result.get("meta") or {}
    target = meta.get("target")
    kind = meta.get("detected_kind") or meta.get("type", "?")
    if not target:
        return None

    bundle = {
        "type": "bundle",
        "id": _sid("bundle"),
        "spec_version": "2.1",
        "objects": [],
    }
    objects = bundle["objects"]

    # 1) producer
    producer = _sco_identity_astrym()
    objects.append(producer)

    # 2) target SCO
    target_ref = None
    if kind == "ip":
        if ":" in target:
            target_obj = _sco_ipv6(target)
        else:
            target_obj = _sco_ipv4(target)
        target_ref = target_obj["id"]
        objects.append(target_obj)
    elif kind == "domain":
        target_obj = _sco_domain(target)
        target_ref = target_obj["id"]
        objects.append(target_obj)
    elif kind == "email":
        target_obj = _sco_email(target)
        target_ref = target_obj["id"]
        objects.append(target_obj)
    elif kind == "url":
        target_obj = _sco_url(target)
        target_ref = target_obj["id"]
        objects.append(target_obj)
    else:
        # fallback — domain name
        target_obj = _sco_domain(target)
        target_ref = target_obj["id"]
        objects.append(target_obj)

    observed_refs = [target_ref]

    # 3) DNS — A / AAAA
    dns = result.get("dns") or result.get("records") or {}
    if isinstance(dns, dict):
        for ip in (dns.get("A") or []):
            o = _sco_ipv4(ip)
            objects.append(o)
            observed_refs.append(o["id"])
            objects.append(_sro_relationship(
                target_ref, o["id"], "resolves-to",
                "A record from ASTRYM scan"))
        for ip in (dns.get("AAAA") or []):
            o = _sco_ipv6(ip)
            objects.append(o)
            observed_refs.append(o["id"])
            objects.append(_sro_relationship(
                target_ref, o["id"], "resolves-to",
                "AAAA record from ASTRYM scan"))
        for mx in (dns.get("MX") or []):
            parts = str(mx).split()
            host = parts[-1].rstrip(".") if parts else str(mx)
            o = _sco_domain(host)
            objects.append(o)
            observed_refs.append(o["id"])
            objects.append(_sro_relationship(
                target_ref, o["id"], "related-to", "MX host"))
        for ns in (dns.get("NS") or []):
            host = str(ns).rstrip(".").lower()
            o = _sco_domain(host)
            objects.append(o)
            observed_refs.append(o["id"])
            objects.append(_sro_relationship(
                target_ref, o["id"], "related-to", "NS host"))

    # 4) subdomains (CT + sub)
    subs_ct = result.get("subdomains_ct") or []
    subs = result.get("subdomains") or []
    sub_hosts = set()
    for s in subs_ct[:300]:
        if isinstance(s, str):
            sub_hosts.add(s.lower())
    for s in subs[:300]:
        if isinstance(s, dict) and s.get("host"):
            sub_hosts.add(str(s["host"]).lower())
    for host in list(sub_hosts)[:500]:
        if not host or host == target:
            continue
        o = _sco_domain(host)
        objects.append(o)
        observed_refs.append(o["id"])
        objects.append(_sro_relationship(
            o["id"], target_ref, "related-to", "subdomain"))

    # 5) geo / ASN (ip scan)
    geo = result.get("geo") or {}
    if isinstance(geo, dict) and "error" not in geo:
        asn_raw = geo.get("as") or ""
        if asn_raw:
            import re as _re
            m = _re.search(r"(\d{1,10})", str(asn_raw))
            if m:
                asn_obj = _sco_asn(int(m.group(1)),
                                    geo.get("isp") or geo.get("org"))
                objects.append(asn_obj)
                observed_refs.append(asn_obj["id"])
                objects.append(_sro_relationship(
                    target_ref, asn_obj["id"], "belongs-to",
                    "ASN from GeoIP"))

    # 6) consensus ASN (ip scan)
    cons = result.get("consensus") or {}
    cf = (cons.get("fields") or {}) if isinstance(cons, dict) else {}
    asn_field = cf.get("asn") if isinstance(cf, dict) else None
    if isinstance(asn_field, dict) and asn_field.get("value"):
        import re as _re2
        m = _re2.search(r"(\d{1,10})", str(asn_field["value"]))
        if m:
            asn_obj = _sco_asn(int(m.group(1)))
            objects.append(asn_obj)
            observed_refs.append(asn_obj["id"])
            objects.append(_sro_relationship(
                target_ref, asn_obj["id"], "belongs-to",
                "ASN from consensus (multi-source)"))

    # 7) risk score → indicator
    risk = result.get("risk") or {}
    if not risk and isinstance(result.get("security"), dict):
        risk = result["security"].get("risk") or {}
    score = int(risk.get("score", 0) or 0)
    level = str(risk.get("level") or "").upper()
    if score >= 15:
        if kind == "ip":
            pattern = f"[ipv4-addr:value = '{target}']"
        elif kind == "domain":
            pattern = f"[domain-name:value = '{target}']"
        else:
            pattern = f"[domain-name:value = '{target}']"
        reasons = risk.get("reasons") or []
        ind = _sdo_indicator(
            pattern=pattern,
            name="ASTRYM risk indicator: " + str(level),
            description="; ".join(str(r)[:200] for r in reasons[:10]),
            labels=["anomalous-activity"],
            confidence=min(100, score),
        )
        objects.append(ind)
        objects.append(_sro_relationship(
            ind["id"], target_ref, "indicates",
            "Risk indicator from ASTRYM"))

    # 8) threat intel hits → indicators
    results_block = result.get("results") or {}
    if isinstance(results_block, dict):
        for src_name, res in results_block.items():
            if not isinstance(res, dict):
                continue
            if res.get("error") or res.get("found") is not True:
                continue
            if kind == "ip":
                pattern = f"[ipv4-addr:value = '{target}']"
            else:
                pattern = f"[domain-name:value = '{target}']"
            ind = _sdo_indicator(
                pattern=pattern,
                name="Threat intel hit: " + str(src_name),
                description=json.dumps(
                    {k: v for k, v in res.items()
                     if isinstance(v, (str, int, float, bool))},
                    ensure_ascii=False)[:800],
                labels=["malicious-activity"],
            )
            objects.append(ind)
            objects.append(_sro_relationship(
                ind["id"], target_ref, "indicates",
                "Threat intel hit from " + str(src_name)))

    # 9) observed-data контейнер
    if len(observed_refs) > 1:
        od = _sdo_observed_data(observed_refs)
        objects.append(od)
        objects.append(_sro_relationship(
            producer["id"], od["id"], "produces",
            "ASTRYM produced this observation"))

    # 10) note с общим резюме
    if len(observed_refs) > 1:
        note_body = []
        note_body.append("Target: " + str(target))
        note_body.append("Kind: " + str(kind))
        if score > 0:
            note_body.append(f"Risk: {score}/100 ({level})")
        if cf:
            confirmed = sum(1 for f in cf.values()
                            if isinstance(f, dict)
                            and f.get("confidence") == "confirmed")
            note_body.append(f"Consensus fields confirmed: {confirmed}")
        note_body.append("Producer: ASTRYM " + STIX_VERSION)
        note = _sro_note([target_ref], "\n".join(note_body))
        objects.append(note)

    return bundle


# ============================================================
# EXPORT
# ============================================================

def _stix_dir():
    d = RESULTS_DIR / "stix"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return d


def export_stix(result, out_path=None):
    """Собирает bundle и пишет в файл. Возвращает путь."""
    bundle = build_bundle(result)
    if not bundle:
        return None
    if out_path is None:
        target = (result.get("meta") or {}).get("target", "unknown")
        safe = "".join(c if c.isalnum() or c in "._-" else "_"
                       for c in str(target))[:60]
        out_path = _stix_dir() / (safe + "_bundle.json")
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return p


# ============================================================
# RUN (для CLI)
# ============================================================

def run_stix(target, extras=False):
    """Собирает скан + генерирует bundle."""
    kind = classify(target)
    if kind == "ip":
        from astrym_ip import collect_ip, _x_ip
        result = collect_ip(target)
        if extras:
            result["extended"] = _x_ip(target)
        try:
            from astrym_consensus import aggregate
            result["consensus"] = aggregate(result)
        except Exception:
            pass
    elif kind == "domain":
        from astrym_domain import collect_domain, _x_domain
        result = collect_domain(target)
        if extras:
            result["extended"] = _x_domain(target)
        try:
            from astrym_consensus import aggregate_domain
            result["consensus"] = aggregate_domain(result)
        except Exception:
            pass
    elif kind in ("email", "url"):
        from astrym_check import collect_check
        result = collect_check(target, extras=extras)
    else:
        c_err("stix: unsupported kind: " + str(kind))
        return None

    if not result:
        return None

    p = export_stix(result)
    if not p:
        c_err("stix: bundle build failed")
        return None

    c_ok("STIX -> " + str(p))
    hist_record("stix", target, {"file": str(p)})
    return {"meta": {"type": "stix", "target": target,
                     "generated_at": now_iso(),
                     "tool": "ASTRYM " + STIX_VERSION},
            "bundle_path": str(p),
            "bundle": json.loads(Path(p).read_text(encoding="utf-8"))}


def render_stix(d):
    from astrym_core import header, kv, section
    if not d:
        return
    header("STIX 2.1 export", d["meta"]["target"])
    bundle = d.get("bundle") or {}
    objects = bundle.get("objects") or []
    by_type = {}
    for o in objects:
        t = o.get("type", "?")
        by_type[t] = by_type.get(t, 0) + 1

    section("Bundle")
    kv([
        ("ID", bundle.get("id", "")[:60]),
        ("Spec", bundle.get("spec_version", "2.1")),
        ("Objects", len(objects)),
        ("File", d.get("bundle_path")),
    ])

    section("Objects by type")
    for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
        c_muted("  " + str(t).ljust(22) + str(n))

    section("Import")
    c_muted("  MISP:       Administration -> Feeds -> Import (STIX 2.1)")
    c_muted("  OpenCTI:    Data -> Import -> STIX 2.1 bundle")
    c_muted("  TheHive:    Templates -> STIX -> Upload")
    c_muted("  PyMISP:     misp.upload_stix('" + str(d.get("bundle_path")) + "')")
