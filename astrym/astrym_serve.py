#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ASTRYM Serve 2.0.0 — REST API (этап 2: форматы, batch, kinds).
#
# Запуск:        python3 astrym_serve.py
# Генерация ключа: python3 astrym_serve.py --genkey
# Список ключей:   python3 astrym_serve.py --list-keys
#
# Эндпоинты:
#   GET  /health
#   GET  /info
#   GET  /kinds
#   GET  /scan/<kind>/<target>[?extras=1&profile=...&format=json|md|html|stix]
#   POST /batch          body: {"targets": [{"kind":"domain","target":"x"}]}
#                        или: {"lines": ["domain github.com", "ip 8.8.8.8"]}
#
# Примеры:
#   curl 'http://127.0.0.1:8080/health'
#   curl -H 'X-API-Key: ak_...' 'http://127.0.0.1:8080/scan/domain/github.com'
#   curl -H 'X-API-Key: ak_...' 'http://127.0.0.1:8080/scan/ip/8.8.8.8?format=md'
#   curl -H 'X-API-Key: ak_...' 'http://127.0.0.1:8080/scan/ip/8.8.8.8?format=stix'
#   curl -X POST -H 'X-API-Key: ak_...' -H 'Content-Type: application/json' \
#        -d '{"lines":["domain github.com","ip 8.8.8.8"]}' \
#        http://127.0.0.1:8080/batch

SERVE_VERSION = "2.0.0"
START_TS = __import__("time").time()

import argparse
import json
import os
import secrets
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

_HERE = Path(__file__).parent.resolve()
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

try:
    import astrym
    from astrym_core import load_cfg, save_cfg, CONFIG_PATH
except Exception as _e:
    sys.stderr.write("[astrym_serve] FATAL: cannot import astrym: " + str(_e) + "\n")
    sys.exit(1)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
MAX_BATCH = 20


# ============================================================
# API KEYS
# ============================================================

def get_keys():
    cfg = load_cfg()
    return [str(k) for k in (cfg.get("server_api_keys") or []) if k]


def add_key(key=None):
    cfg = load_cfg()
    keys = list(cfg.get("server_api_keys") or [])
    if not key:
        key = "ak_" + secrets.token_urlsafe(24)
    if key in keys:
        return None, "already exists"
    keys.append(key)
    cfg["server_api_keys"] = keys
    save_cfg(cfg)
    return key, None


def remove_key(key):
    cfg = load_cfg()
    keys = list(cfg.get("server_api_keys") or [])
    if key not in keys:
        return False
    keys.remove(key)
    cfg["server_api_keys"] = keys
    save_cfg(cfg)
    return True


# ============================================================
# FORMAT CONVERTERS (in-memory, temp files)
# ============================================================

def _render_md(result):
    from astrym_output import save_md
    tmpdir = Path(tempfile.mkdtemp(prefix="astrym_md_"))
    base = tmpdir / "out"
    try:
        p = save_md([result], base)
        if not p:
            return None
        return Path(str(p)).read_text(encoding="utf-8")
    finally:
        try:
            for f in tmpdir.iterdir():
                f.unlink()
            tmpdir.rmdir()
        except Exception:
            pass


def _render_html(result):
    from astrym_output import save_html
    tmpdir = Path(tempfile.mkdtemp(prefix="astrym_html_"))
    base = tmpdir / "out"
    try:
        p = save_html([result], base)
        if not p:
            return None
        return Path(str(p)).read_text(encoding="utf-8")
    finally:
        try:
            for f in tmpdir.iterdir():
                f.unlink()
            tmpdir.rmdir()
        except Exception:
            pass


def _render_stix(result):
    try:
        from astrym_stix import build_bundle
    except ImportError:
        return None
    bundle = build_bundle(result)
    if not bundle:
        return None
    return json.dumps(bundle, indent=2, ensure_ascii=False, default=str)


def _render(result, fmt):
    """Вернуть (body_bytes, content_type). fmt — json|md|html|stix."""
    fmt = (fmt or "json").lower()
    if fmt in ("json", ""):
        body = json.dumps(result, ensure_ascii=False, default=str)
        return body.encode("utf-8"), "application/json; charset=utf-8"
    if fmt == "md" or fmt == "markdown":
        txt = _render_md(result)
        if txt is None:
            return (json.dumps({"error": "md render failed"},
                                ensure_ascii=False).encode("utf-8"),
                    "application/json")
        return txt.encode("utf-8"), "text/markdown; charset=utf-8"
    if fmt == "html":
        txt = _render_html(result)
        if txt is None:
            return (json.dumps({"error": "html render failed"},
                                ensure_ascii=False).encode("utf-8"),
                    "application/json")
        return txt.encode("utf-8"), "text/html; charset=utf-8"
    if fmt == "stix":
        txt = _render_stix(result)
        if txt is None:
            return (json.dumps({"error": "stix render failed"},
                                ensure_ascii=False).encode("utf-8"),
                    "application/json")
        return txt.encode("utf-8"), "application/json; charset=utf-8"
    # неизвестный формат
    return (json.dumps({"error": "unknown format: " + fmt,
                        "available": ["json", "md", "html", "stix"]},
                        ensure_ascii=False).encode("utf-8"),
            "application/json")


# ============================================================
# HANDLER
# ============================================================

class Handler(BaseHTTPRequestHandler):
    server_version = "ASTRYM/" + SERVE_VERSION

    def log_message(self, fmt, *args):
        ts = time.strftime("%H:%M:%S")
        sys.stderr.write("[" + ts + "] " + (fmt % args) + "\n")

    # --- helpers ---

    def _send(self, code, body, ctype="application/json; charset=utf-8",
               extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers",
                          "X-API-Key, Content-Type")
        self.send_header("Access-Control-Allow-Methods",
                          "GET, POST, OPTIONS")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str))

    def _check_auth(self, qs):
        keys = get_keys()
        if not keys:
            return True
        supplied = (self.headers.get("X-API-Key") or "").strip()
        if not supplied:
            supplied = (qs.get("key") or "").strip()
        return supplied in keys

    def _read_body(self, max_bytes=1_000_000):
        try:
            n = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            n = 0
        if n <= 0 or n > max_bytes:
            return None
        try:
            raw = self.rfile.read(n)
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None

    # --- OPTIONS ---

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods",
                          "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                          "X-API-Key, Content-Type")
        self.end_headers()

    # --- GET ---

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        qs = {k: v[0] for k, v in parse_qs(u.query).items()}

        if path in ("/health", "/"):
            self._send_json(200, {
                "status": "ok",
                "service": "astrym",
                "version": SERVE_VERSION,
                "uptime_sec": round(time.time() - START_TS, 1),
                "now": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "auth_required": len(get_keys()) > 0,
            })
            return

        if not self._check_auth(qs):
            self._send_json(401, {
                "error": "unauthorized",
                "hint": "add header X-API-Key: <key> or ?key=<key>",
            })
            return

        if path == "/info":
            self._handle_info()
            return

        if path == "/kinds":
            self._handle_kinds()
            return

        if path.startswith("/scan/"):
            parts = path.split("/", 3)
            if len(parts) < 4 or not parts[2] or not parts[3]:
                self._send_json(400, {
                    "error": "usage: /scan/<kind>/<target>",
                    "example": "/scan/domain/github.com",
                })
                return
            self._handle_scan(parts[2].lower(), unquote(parts[3]), qs)
            return

        self._send_json(404, {
            "error": "not found",
            "path": path,
            "available": ["/health", "/info", "/kinds",
                          "/scan/<kind>/<target>", "POST /batch"],
        })

    # --- POST ---

    def do_POST(self):
        u = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(u.query).items()}

        if not self._check_auth(qs):
            self._send_json(401, {"error": "unauthorized"})
            return

        if u.path == "/batch":
            self._handle_batch(qs)
            return

        self._send_json(404, {
            "error": "not found",
            "path": u.path,
            "available_post": ["/batch"],
        })

    # --- info ---

    def _handle_info(self):
        info = {
            "service": "astrym",
            "version": SERVE_VERSION,
            "uptime_sec": round(time.time() - START_TS, 1),
            "config_path": str(CONFIG_PATH),
            "auth_enabled": len(get_keys()) > 0,
            "keys_count": len(get_keys()),
            "kinds_count": len(getattr(astrym, "DISPATCH", {})),
        }
        # граф
        try:
            if getattr(astrym, "_HAS_GRAPH", False):
                s = astrym.astrym_graph.stats()
                info["graph"] = {
                    "nodes": s.get("nodes", 0),
                    "edges": s.get("edges", 0),
                    "scans": s.get("scans", 0),
                    "db": s.get("db_path"),
                }
        except Exception:
            pass
        # кэш RIPE
        try:
            from astrym_asn import cache_stats
            info["ripe_cache"] = cache_stats()
        except Exception:
            pass
        self._send_json(200, info)

    # --- kinds ---

    def _handle_kinds(self):
        dispatch = getattr(astrym, "DISPATCH", {})
        kinds = sorted(dispatch.keys())
        self._send_json(200, {
            "count": len(kinds),
            "kinds": kinds,
            "usage": "/scan/<kind>/<target>",
        })

    # --- scan ---

    def _handle_scan(self, kind, target, qs):
        dispatch = getattr(astrym, "DISPATCH", {})
        if kind not in dispatch:
            self._send_json(404, {
                "error": "unknown kind: " + kind,
                "available": sorted(dispatch.keys()),
            })
            return

        extras = (qs.get("extras", "0").lower() in ("1", "true", "yes", "on"))
        profile = (qs.get("profile") or "normal").lower()
        fmt = (qs.get("format") or "json").lower()

        try:
            from astrym_core import set_profile
            set_profile(profile)
        except Exception:
            pass

        t0 = time.time()
        try:
            result = dispatch[kind](target, extras)
        except Exception as e:
            self._send_json(500, {
                "error": "collect failed",
                "kind": kind, "target": target,
                "detail": str(e)[:300],
            })
            return

        if not result:
            self._send_json(404, {
                "error": "no result",
                "kind": kind, "target": target,
            })
            return

        try:
            if getattr(astrym, "_HAS_GRAPH", False):
                astrym.astrym_graph.add_scan(target, kind, result)
        except Exception:
            pass

        duration = round(time.time() - t0, 2)
        result.setdefault("meta", {})
        result["meta"]["api_duration_sec"] = duration
        result["meta"]["api_kind"] = kind
        result["meta"]["api_profile"] = profile

        body, ctype = _render(result, fmt)
        extra = {"X-AST RYM-Duration": str(duration),
                  "X-AST RYM-Kind": kind,
                  "X-AST RYM-Format": fmt}
        self._send(200, body, ctype, extra)

    # --- batch ---

    def _handle_batch(self, qs):
        raw = self._read_body()
        if not raw:
            self._send_json(400, {"error": "empty body"})
            return
        try:
            data = json.loads(raw)
        except Exception as e:
            self._send_json(400, {"error": "invalid JSON: " + str(e)[:120]})
            return
        if not isinstance(data, dict):
            self._send_json(400, {"error": "body must be object"})
            return

        fmt = (data.get("format") or qs.get("format") or "json").lower()
        extras = bool(data.get("extras"))
        profile = (data.get("profile") or qs.get("profile")
                    or "normal").lower()

        items = []
        if isinstance(data.get("lines"), list):
            for ln in data["lines"]:
                parts = str(ln).strip().split(None, 1)
                if len(parts) == 2:
                    items.append((parts[0].lower(), parts[1].strip()))
        elif isinstance(data.get("targets"), list):
            for t in data["targets"]:
                if isinstance(t, dict) and t.get("kind") and t.get("target"):
                    items.append((str(t["kind"]).lower(), str(t["target"])))
                elif isinstance(t, str):
                    parts = t.split(None, 1)
                    if len(parts) == 2:
                        items.append((parts[0].lower(), parts[1]))

        if not items:
            self._send_json(400, {
                "error": "no items",
                "expected": {
                    "lines": ["domain github.com", "ip 8.8.8.8"],
                }
            })
            return
        if len(items) > MAX_BATCH:
            self._send_json(413, {
                "error": "too many items",
                "max": MAX_BATCH,
                "got": len(items),
            })
            return

        try:
            from astrym_core import set_profile
            set_profile(profile)
        except Exception:
            pass

        dispatch = getattr(astrym, "DISPATCH", {})
        t0 = time.time()
        results = []
        for kind, target in items:
            if kind not in dispatch:
                results.append({"kind": kind, "target": target,
                                 "error": "unknown kind"})
                continue
            try:
                r = dispatch[kind](target, extras)
            except Exception as e:
                results.append({"kind": kind, "target": target,
                                 "error": str(e)[:200]})
                continue
            if not r:
                results.append({"kind": kind, "target": target,
                                 "error": "no result"})
                continue
            try:
                if getattr(astrym, "_HAS_GRAPH", False):
                    astrym.astrym_graph.add_scan(target, kind, r)
            except Exception:
                pass
            r.setdefault("meta", {})
            r["meta"]["api_kind"] = kind
            r["meta"]["api_profile"] = profile
            results.append(r)

        # формат md/html/stix для batch не имеет смысла — оставляем JSON
        # но каждый item содержит полноценный result
        duration = round(time.time() - t0, 2)
        payload = {
            "meta": {
                "type": "batch",
                "count": len(results),
                "duration_sec": duration,
                "profile": profile,
                "extras": extras,
                "format": fmt,
            },
            "results": results,
        }
        self._send_json(200, payload)


# ============================================================
# SERVER
# ============================================================

def run_server(host, port):
    keys = get_keys()
    try:
        srv = ThreadingHTTPServer((host, port), Handler)
    except OSError as e:
        sys.stderr.write("[astrym_serve] cannot bind " + host + ":" +
                         str(port) + " — " + str(e) + "\n")
        sys.exit(1)

    print("ASTRYM API server v" + SERVE_VERSION)
    print("  listening:  http://" + host + ":" + str(port))
    print("  config:     " + str(CONFIG_PATH))
    if keys:
        print("  keys:       " + str(len(keys)))
    else:
        print("  keys:       NONE (DEV MODE)")
    print("  endpoints:")
    print("    GET  /health")
    print("    GET  /info")
    print("    GET  /kinds")
    print("    GET  /scan/<kind>/<target>?format=json|md|html|stix")
    print("    POST /batch")
    print("  Ctrl+C to stop")
    print()

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[astrym_serve] stopping...")
        srv.shutdown()


# ============================================================
# CLI
# ============================================================

def main():
    ap = argparse.ArgumentParser(prog="astrym_serve",
                                  description="ASTRYM REST API server")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--genkey", action="store_true")
    ap.add_argument("--list-keys", action="store_true")
    ap.add_argument("--revoke-key", metavar="KEY")
    args = ap.parse_args()

    if args.genkey:
        key, err = add_key()
        if err:
            print("error: " + err)
            sys.exit(1)
        print("new key: " + key)
        print("saved:   " + str(CONFIG_PATH))
        return

    if args.list_keys:
        keys = get_keys()
        if not keys:
            print("(no keys)")
        else:
            for k in keys:
                print(k)
        return

    if args.revoke_key:
        ok = remove_key(args.revoke_key)
        print("revoked" if ok else "not found")
        return

    run_server(args.host, args.port)


if __name__ == "__main__":
    main()
# end ASTRYM serve stage 2
