"""MULTI-OSINT-TOOL :: hardened local HTTP server (stdlib only, loopback only).

Threat model: the server is reachable by every process and every web page on this machine, so it
defends itself like an internet-facing service:
  * binds 127.0.0.1 only; refuses non-loopback peers; Host allow-list (stops DNS rebinding)
  * no cookie, no API: a single-use, 120-second launch token is exchanged for an HttpOnly,
    SameSite=Strict, HMAC-signed session cookie; every state change also needs a CSRF header
  * Origin / Sec-Fetch-Site checks, JSON-only bodies (forces a CORS preflight that is never granted)
  * strict schema per route (unknown fields rejected), 1 MiB body cap, socket timeouts, thread cap
  * per-session rate limits; vault re-authentication for anything that reveals a secret
  * strict CSP (no inline script/style, same-origin only), nosniff, no-store, frame-ancestors 'none'
  * errors are generic + correlation id; details only in the redacted server log
"""
from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import logging
import re
import secrets
import socket
import socketserver
import threading
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import mot_config as C
from mot_app import App, AppError
from mot_netguard import NetworkUnsafe
from mot_orchestrator import TYPES, InputError
from mot_vault import Redactor, VaultLocked

log = logging.getLogger("mot.server")

MAX_BODY = 1_048_576
SESSION_TTL = 12 * 3600
LAUNCH_TTL = 120
COOKIE = "mot_sid"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; "
       "form-action 'self'; frame-ancestors 'none'; object-src 'none'; manifest-src 'none'; worker-src 'none'")
SEC_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=(), interest-cohort=()",
    "Cache-Control": "no-store",
}
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".woff2": "font/woff2", ".svg": "image/svg+xml",
        ".txt": "text/plain; charset=utf-8", ".png": "image/png", ".ico": "image/x-icon"}
STATIC_NAME = re.compile(r"^[A-Za-z0-9_./-]{1,80}$")
LIMITS = {"light": (300, 60.0), "default": (200, 10.0), "sensitive": (8, 60.0), "search": (15, 60.0), "install": (6, 60.0), "launch": (30, 60.0), "anon_api": (60, 60.0), "keys": (40, 60.0), "export": (20, 60.0)}


# ====================================================================================== sessions
class Sessions:
    """Stateless HMAC tokens. The same secret lets the supervisor mint launch links and lets a restarted server keep honouring browser sessions."""

    def __init__(self, secret: bytes):
        if len(secret) < 32:
            raise ValueError("session secret too short")
        self.secret = secret
        self._used: dict[str, int] = {}
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    def _sig(self, msg: str) -> str:
        return hmac.new(self.secret, msg.encode(), hashlib.sha256).hexdigest()

    def _make(self, kind: str, ttl: int, ident: str) -> str:
        body = f"{kind}.{int(time.time()) + ttl}.{ident}"
        return f"{body}.{self._sig(body)}"

    def _parse(self, token: str, kind: str) -> Optional[str]:
        if not isinstance(token, str) or len(token) > 200:
            return None
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != kind or not parts[1].isdigit() or not re.fullmatch(r"[0-9a-f]{16,64}", parts[2]):
            return None
        if not hmac.compare_digest(parts[3], self._sig(".".join(parts[:3]))):
            return None
        if int(parts[1]) < time.time():
            return None
        return parts[2]

    def mint_launch(self) -> str:
        return self._make("L", LAUNCH_TTL, secrets.token_hex(12))

    def redeem_launch(self, token: str) -> Optional[str]:
        nonce = self._parse(token, "L")
        if not nonce:
            return None
        with self._lock:
            now = int(time.time())
            self._used = {k: v for k, v in self._used.items() if v > now}
            if nonce in self._used:
                return None  # single use
            self._used[nonce] = now + LAUNCH_TTL + 5
        return self._make("S", SESSION_TTL, secrets.token_hex(16))

    def session_id(self, cookie_value: str) -> Optional[str]:
        sid = self._parse(cookie_value, "S")
        if not sid or sid in self._revoked:
            return None
        return sid

    def revoke(self, sid: str) -> None:
        with self._lock:
            self._revoked.add(sid)

    def csrf_for(self, sid: str) -> str:
        return self._sig("csrf|" + sid)[:32]


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[tuple, deque] = {}
        self._lock = threading.Lock()

    def allow(self, who: str, bucket: str) -> Optional[int]:
        """None = allowed; otherwise seconds to wait."""
        limit, window = LIMITS[bucket]
        now = time.monotonic()
        with self._lock:
            q = self._hits.setdefault((who, bucket), deque())
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return max(1, int(window - (now - q[0])) + 1)
            q.append(now)
            if len(self._hits) > 5000:  # bounded memory
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < 120}
        return None


# ====================================================================================== validation
@dataclass
class F:
    kind: str = "str"
    required: bool = False
    max_len: int = 200
    min_len: int = 0
    choices: Optional[tuple] = None
    lo: int = 0
    hi: int = 0
    pattern: Optional[str] = None
    multiline: bool = False
    max_items: int = 40
    item_pattern: Optional[str] = None


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CTRL_ML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CTRL_SL = re.compile(r"[\x00-\x1f\x7f]")


class ValidationError(Exception):
    pass


def _check(name: str, v: Any, f: F) -> Any:
    if f.kind == "str":
        if not isinstance(v, str):
            raise ValidationError(f"'{name}' must be text.")
        if not f.min_len <= len(v) <= f.max_len:
            raise ValidationError(f"'{name}' must be {f.min_len} to {f.max_len} characters.")
        if (_CTRL_ML if f.multiline else _CTRL_SL).search(v):
            raise ValidationError(f"'{name}' contains control characters.")
        if f.choices is not None and v not in f.choices:
            raise ValidationError(f"'{name}' is not an allowed value.")
        if f.pattern and not re.fullmatch(f.pattern, v):
            raise ValidationError(f"'{name}' has an invalid format.")
        return v
    if f.kind == "int":
        if isinstance(v, bool) or not isinstance(v, int) or not f.lo <= v <= f.hi:
            raise ValidationError(f"'{name}' must be a whole number from {f.lo} to {f.hi}.")
        return v
    if f.kind == "bool":
        if not isinstance(v, bool):
            raise ValidationError(f"'{name}' must be true or false.")
        return v
    if f.kind == "list":
        if not isinstance(v, list) or len(v) > f.max_items:
            raise ValidationError(f"'{name}' must be a list of at most {f.max_items} items.")
        for x in v:
            if not isinstance(x, str) or (f.item_pattern and not re.fullmatch(f.item_pattern, x)):
                raise ValidationError(f"'{name}' contains an invalid item.")
        return v
    if f.kind == "dict":  # str -> str, used for key fields
        if not isinstance(v, dict) or len(v) > f.max_items:
            raise ValidationError(f"'{name}' must be an object.")
        for k, x in v.items():
            if not re.fullmatch(r"[a-z0-9_]{1,32}", str(k)) or not isinstance(x, str) or len(x) > 4096 or _CTRL_SL.search(x):
                raise ValidationError(f"'{name}' contains an invalid entry.")
        return v
    raise ValidationError("bad schema")


def validate(data: dict, spec: dict[str, F], what: str = "body") -> dict:
    unknown = set(data) - set(spec)
    if unknown:  # mass-assignment defence: nothing unexpected reaches business logic
        raise ValidationError("Unexpected field(s): " + ", ".join(sorted(str(u)[:30] for u in unknown)))
    out = {}
    for name, f in spec.items():
        if name not in data or data[name] is None:
            if f.required:
                raise ValidationError(f"'{name}' is required.")
            continue
        out[name] = _check(name, data[name], f)
    return out


# ====================================================================================== routing
@dataclass
class Req:
    method: str
    path: str
    sid: str
    body: dict = field(default_factory=dict)
    query: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)


@dataclass
class Download:
    data: bytes
    mime: str
    filename: str


@dataclass
class Route:
    method: str
    rx: re.Pattern
    fn: Callable[[Req], Any]
    body: dict
    query: dict
    limit: str
    csrf: bool
    touch: bool


ID_RX = r"(?P<id>[a-z0-9_]{2,32})"
JOB_RX = r"(?P<id>[0-9a-f]{12,24})"
CASE_RX = r"(?P<id>[0-9a-f]{16})"
PASSWORD = F("str", True, 256, 1)
KEYFILE = F("str", False, 800_000, 1)


def build_routes(app: App, sess: Sessions, stop: threading.Event) -> list[Route]:
    R: list[Route] = []

    def add(method: str, pattern: str, fn, body: Optional[dict] = None, query: Optional[dict] = None, limit: str = "default", touch: bool = True) -> None:
        R.append(Route(method, re.compile(pattern + r"\Z"), fn, body or {}, query or {}, limit, method != "GET", touch))

    # ---- session / vault
    add("GET", r"/api/session", lambda r: {"csrf": sess.csrf_for(r.sid), "status": app.status()}, limit="light", touch=False)
    add("GET", r"/api/ping", lambda r: app.status(), limit="light", touch=False)
    add("POST", r"/api/touch", lambda r: {"ok": True}, limit="light")
    add("POST", r"/api/logout", lambda r: (sess.revoke(r.sid), app.lock("logout"), {"ok": True})[2], limit="sensitive")
    add("POST", r"/api/quit", lambda r: (stop.set(), {"ok": True})[1], limit="sensitive")
    add("POST", r"/api/panic", lambda r: app.panic(), limit="light")
    add("POST", r"/api/vault/create", lambda r: app.create_vault(r.body["password"], r.body["confirm"], r.body.get("keyfile")),
        body={"password": PASSWORD, "confirm": PASSWORD, "keyfile": KEYFILE}, limit="sensitive")
    add("POST", r"/api/vault/unlock", lambda r: app.unlock(r.body["password"], r.body.get("keyfile")), body={"password": PASSWORD, "keyfile": KEYFILE}, limit="sensitive")
    add("POST", r"/api/vault/lock", lambda r: app.lock("user"), limit="light")
    add("POST", r"/api/vault/password", lambda r: app.change_password(r.body["old"], r.body["new"], r.body["confirm"]),
        body={"old": PASSWORD, "new": PASSWORD, "confirm": PASSWORD}, limit="sensitive")
    add("POST", r"/api/vault/backup", lambda r: Download(*_swap(app.vault_backup(r.body["password"]))), body={"password": PASSWORD}, limit="sensitive")

    # ---- dashboard / search
    add("GET", r"/api/overview", lambda r: app.overview())
    add("POST", r"/api/ack", lambda r: app.accept_ack(), limit="light")
    add("POST", r"/api/detect", lambda r: app.detect(r.body["target"]), body={"target": F("str", True, 500, 1)}, limit="light")
    add("GET", r"/api/plan", lambda r: app.plan(r.query["ttype"]), query={"ttype": F("str", True, 20, 1, choices=tuple(TYPES))}, limit="light")
    add("GET", r"/api/types", lambda r: app.types(), limit="light")
    add("POST", r"/api/search", lambda r: app.search(r.body["target"], r.body.get("ttype"), r.body.get("tools"), r.body.get("save", True), r.body.get("face_consent", False), r.body.get("purpose", "")),
        body={"target": F("str", True, 500, 1), "ttype": F("str", False, 20, choices=tuple(TYPES)), "tools": F("list", False, max_items=40, item_pattern=r"[a-z0-9_]{2,32}"),
              "save": F("bool"), "face_consent": F("bool"), "purpose": F("str", False, 200)}, limit="search")
    add("GET", r"/api/jobs", lambda r: app.jobs(), limit="light")
    add("GET", r"/api/jobs/" + JOB_RX, lambda r: app.job(r.params["id"], [x for x in r.query.get("have", "").split(",") if x]),
        query={"have": F("str", False, 700, pattern=r"[a-z0-9_,]*")}, limit="light", touch=False)
    add("POST", r"/api/jobs/" + JOB_RX + r"/cancel", lambda r: app.cancel(r.params["id"]), limit="light")
    add("POST", r"/api/reveal", lambda r: app.reveal(r.body["job"], r.body["finding"], r.body["password"]),
        body={"job": F("str", True, 24, 12, pattern=r"[0-9a-f]{12,24}"), "finding": F("str", True, 12, 4, pattern=r"[0-9a-f]{4,12}"), "password": PASSWORD}, limit="sensitive")

    # ---- cases
    add("GET", r"/api/cases", lambda r: app.cases())
    add("GET", r"/api/cases/" + CASE_RX, lambda r: app.case(r.params["id"]))
    add("POST", r"/api/cases/" + CASE_RX + r"/update", lambda r: app.case_update(r.params["id"], r.body.get("title"), r.body.get("notes")),
        body={"title": F("str", False, 120), "notes": F("str", False, 20000, multiline=True)})
    add("POST", r"/api/cases/" + CASE_RX + r"/delete", lambda r: app.case_delete(r.params["id"]), limit="sensitive")
    add("GET", r"/api/cases/" + CASE_RX + r"/export", lambda r: Download(*app.case_export(r.params["id"], r.query["fmt"])),
        query={"fmt": F("str", True, 10, 1, choices=("json", "csv", "md", "maltego"))}, limit="export")

    # ---- connections / keys
    add("GET", r"/api/connections", lambda r: app.connections())
    add("POST", r"/api/connections/" + ID_RX + r"/key", lambda r: app.set_key(r.params["id"], r.body["fields"]), body={"fields": F("dict", True, max_items=8)}, limit="keys")
    add("POST", r"/api/connections/" + ID_RX + r"/delete_key", lambda r: app.delete_key(r.params["id"]), limit="keys")
    add("POST", r"/api/connections/" + ID_RX + r"/test", lambda r: app.test_connection(r.params["id"], r.body.get("confirm_cost", False)), body={"confirm_cost": F("bool")}, limit="keys")
    add("POST", r"/api/connections/" + ID_RX + r"/config", lambda r: app.set_connector(r.params["id"], r.body.get("enabled"), r.body.get("route")),
        body={"enabled": F("bool"), "route": F("str", False, 10, choices=("auto", "tor", "vpn"))})
    add("POST", r"/api/connections/" + ID_RX + r"/reveal", lambda r: app.reveal_key(r.params["id"], r.body["field"], r.body["password"]),
        body={"field": F("str", True, 32, 1, pattern=r"[a-z0-9_]{1,32}"), "password": PASSWORD}, limit="sensitive")

    # ---- shield
    add("GET", r"/api/shield", lambda r: app.shield())
    add("POST", r"/api/shield/verify", lambda r: app.shield_verify(), limit="search")
    add("POST", r"/api/shield/config", lambda r: app.shield_config(r.body.get("mode"), r.body.get("tor_socks"), r.body.get("custom_proxy"), r.body.get("vpn_iface_pattern"), r.body.get("allow_direct")),
        body={"mode": F("str", False, 20, choices=("tor_over_vpn", "tor", "vpn", "proxy", "direct")), "tor_socks": F("str", False, 120), "custom_proxy": F("str", False, 300),
              "vpn_iface_pattern": F("str", False, 80), "allow_direct": F("bool")}, limit="sensitive")
    add("POST", r"/api/shield/baseline", lambda r: app.shield_baseline(r.body.get("ip"), r.body.get("force", False)), body={"ip": F("str", False, 45), "force": F("bool")}, limit="sensitive")
    add("POST", r"/api/shield/tor/start", lambda r: app.tor_start(), limit="sensitive")

    # ---- links that leave the shield (URLs are resolved server-side from an allow-list; the page never supplies one)
    ext = {"kind": F("str", True, 10, 1, choices=("vendor", "guide")), "id": F("str", True, 32, 2, pattern=r"[a-z0-9_]{2,32}"),
           "which": F("str", True, 8, 1, pattern=r"site|key|docs|[0-9]")}
    add("POST", r"/api/external/link", lambda r: app.external_link(r.body["kind"], r.body["id"], r.body["which"]), body=ext, limit="light")
    add("POST", r"/api/external/open", lambda r: app.open_external(r.body["kind"], r.body["id"], r.body["which"], r.body.get("confirm", False)),
        body={**ext, "confirm": F("bool")}, limit="sensitive")

    # ---- health, tools, recovery, audit, settings
    add("GET", r"/api/health", lambda r: app.health(), limit="search")
    add("POST", r"/api/health/fix", lambda r: app.health_fix(r.body["id"]), body={"id": F("str", True, 40, 2, pattern=r"[a-z0-9_]{2,40}")}, limit="sensitive")
    add("GET", r"/api/tools", lambda r: app.tools(), limit="light")
    add("POST", r"/api/tools/" + ID_RX + r"/install", lambda r: app.tool_install(r.params["id"]), limit="install")
    add("GET", r"/api/recovery", lambda r: app.recovery(), limit="light")
    add("POST", r"/api/recovery/(?P<id>[a-z0-9]{6,24})", lambda r: app.recover(r.params["id"], r.body["action"]), body={"action": F("str", True, 10, choices=("resume", "case", "discard"))}, limit="search")
    add("GET", r"/api/audit", lambda r: app.audit_view(int(r.query.get("limit", "50"))), query={"limit": F("str", False, 3, pattern=r"[0-9]{1,3}")}, limit="light")
    add("GET", r"/api/settings", lambda r: app.settings())
    add("POST", r"/api/settings", lambda r: app.settings_set(r.body), body={
        "idle_lock_minutes": F("int", lo=1, hi=240), "max_workers": F("int", lo=0, hi=32), "connector_timeout": F("int", lo=10, hi=900), "job_timeout": F("int", lo=30, hi=3600),
        "theharvester_sources": F("str", False, 300), "persist_secrets": F("bool"), "mask_sensitive": F("bool"), "secure_window": F("bool"),
        "toolenv_python": F("str", False, 400), "theme": F("str", False, 8, choices=("dark", "light"))}, limit="sensitive")
    return R


def _swap(t: tuple) -> tuple:
    """vault_backup returns (bytes, filename); Download wants (bytes, mime, filename)."""
    return t[0], "application/octet-stream", t[1]


# ====================================================================================== http
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "MOT"
    sys_version = ""
    timeout = 20  # per-socket-operation timeout: blunts slow-loris

    # ---- plumbing
    def log_message(self, fmt, *args) -> None:  # never log query strings, cookies or bodies
        log.debug("%s %s", self.command, self.path.split("?", 1)[0][:120])

    @property
    def srv(self) -> "MotServer":
        return self.server  # type: ignore[return-value]

    def _send(self, status: int, body: bytes = b"", ctype: str = "application/json; charset=utf-8", extra: Optional[dict] = None) -> None:
        try:
            self.send_response(status)
            for k, v in SEC_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass

    def _json(self, status: int, payload: dict, extra: Optional[dict] = None) -> None:
        self._send(status, json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"), extra=extra)

    def _err(self, status: int, message: str, code: str = "error", extra: Optional[dict] = None, **more) -> None:
        self._json(status, {"ok": False, "error": message, "code": code, **more}, extra)

    # ---- guards
    def _host_ok(self) -> bool:
        h = (self.headers.get("Host") or "").lower()
        return h in self.srv.allowed_hosts

    def _fetch_site_ok(self) -> bool:
        site = self.headers.get("Sec-Fetch-Site")
        return site in (None, "same-origin", "none")

    def _origin_ok(self) -> bool:
        o = self.headers.get("Origin")
        return o is None or o in self.srv.allowed_origins

    def _cookie_sid(self) -> Optional[str]:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE:
                return self.srv.sessions.session_id(v)
        return None

    # ---- entry points
    def do_GET(self) -> None:
        self._dispatch()

    def do_POST(self) -> None:
        self._dispatch()

    def _not_allowed(self) -> None:
        self._err(405, "Method not allowed.", "method", extra={"Allow": "GET, POST"})

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = do_TRACE = do_CONNECT = _not_allowed  # type: ignore[assignment]

    def _dispatch(self) -> None:
        cid = secrets.token_hex(4)
        try:
            self._handle(cid)
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass
        except Exception:  # last line of defence: nothing internal reaches the client
            log.exception("unhandled error cid=%s", cid)
            self._err(500, "Something went wrong inside MULTI-OSINT-TOOL. Open Health to run diagnostics.", "internal", cid=cid)

    def _handle(self, cid: str) -> None:
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            return self._err(403, "Forbidden.", "forbidden")
        if not self._host_ok():
            return self._err(421, "Unexpected Host header.", "bad_host")
        if len(self.path) > 2048 or "\x00" in self.path:
            return self._err(414, "Request target too long.", "bad_request")
        u = urllib.parse.urlsplit(self.path)
        path = u.path
        if path == "/mot-health":
            return self._send(200, b'{"ok":true}')
        if path == "/mot-launch" and self.command == "POST":
            return self._launch()
        if not path.startswith("/api/"):
            if self.command != "GET":
                return self._not_allowed()
            if not self._fetch_site_ok():
                return self._err(403, "Cross-site request refused.", "forbidden")
            return self._static(path)
        # ---------------- API
        if not self._fetch_site_ok():
            return self._err(403, "Cross-site request refused.", "forbidden")
        sid = self._cookie_sid()
        if not sid:
            wait = self.srv.limiter.allow("anon", "anon_api")
            return self._err(429 if wait else 401, "Rate limited." if wait else "No session. Open MULTI-OSINT-TOOL from the launch link printed in the terminal.", "rate" if wait else "no_session")
        route, params = self._match(path)
        if route is None:
            return self._err(404, "Not found.", "not_found")
        if route is False:
            return self._not_allowed()
        if route.csrf:
            if not self._origin_ok():
                return self._err(403, "Origin not allowed.", "forbidden")
            tok = self.headers.get("X-MOT-CSRF", "")
            if not hmac.compare_digest(tok.encode(), self.srv.sessions.csrf_for(sid).encode()):
                return self._err(403, "Missing or invalid CSRF token.", "csrf")
        wait = self.srv.limiter.allow(sid, route.limit)
        if wait:
            return self._err(429, f"Too many requests. Try again in {wait}s.", "rate", wait=wait, extra={"Retry-After": str(wait)})
        req = Req(self.command, path, sid, params=params)
        try:
            req.query = validate({k: v[0] for k, v in urllib.parse.parse_qs(u.query, max_num_fields=10).items()}, route.query, "query")
            if route.method == "POST":
                req.body = validate(self._read_json(), route.body)
        except ValidationError as exc:
            return self._err(400, str(exc), "invalid")
        except _HttpErr as exc:
            return self._err(exc.status, exc.msg, exc.code)
        if route.touch:
            self.srv.app.touch()
        try:
            data = route.fn(req)
        except AppError as exc:
            hdr = {"Retry-After": str(exc.extra["wait"])} if exc.status == 429 and "wait" in exc.extra else None
            return self._err(exc.status, str(exc), exc.code, extra=hdr, **exc.extra)
        except InputError as exc:
            return self._err(400, str(exc), "invalid")
        except VaultLocked:
            return self._err(423, "The vault is locked.", "locked")
        except NetworkUnsafe as exc:
            return self._err(409, "The network shield is not verified: " + str(exc), "shield_down")
        if isinstance(data, Download):
            name = re.sub(r"[^A-Za-z0-9._-]", "_", data.filename)[:80]
            return self._send(200, data.data, data.mime, {"Content-Disposition": f'attachment; filename="{name}"'})
        self._json(200, {"ok": True, "data": data})

    def _match(self, path: str):
        seen_path = False
        for r in self.srv.routes:
            m = r.rx.match(path)
            if m:
                if r.method == self.command:
                    return r, m.groupdict()
                seen_path = True
        return (False, {}) if seen_path else (None, {})

    def _read_json(self) -> dict:
        if (self.headers.get("Transfer-Encoding") or "").lower() not in ("", "identity"):
            raise _HttpErr(411, "Chunked bodies are not accepted.", "length")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise _HttpErr(415, "Content-Type must be application/json.", "type")
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise _HttpErr(411, "Content-Length is required.", "length") from None
        if n < 0 or n > MAX_BODY:
            raise _HttpErr(413, "Request body too large.", "too_large")
        raw = self.rfile.read(n) if n else b"{}"
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise _HttpErr(400, "Body is not valid JSON.", "invalid") from None
        if not isinstance(obj, dict):
            raise _HttpErr(400, "Body must be a JSON object.", "invalid")
        return obj

    # ---- launch token exchange (the only route reachable without a session)
    def _launch(self) -> None:
        wait = self.srv.limiter.allow("anon", "launch")
        if wait:
            return self._err(429, "Too many attempts.", "rate")
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if not 0 < n <= 512:
                raise ValueError
            form = urllib.parse.parse_qs(self.rfile.read(n).decode("ascii"), strict_parsing=True, max_num_fields=2)
            token = form["t"][0]
        except (ValueError, KeyError, UnicodeDecodeError):
            return self._err(400, "Bad launch request.", "invalid")
        cookie = self.srv.sessions.redeem_launch(token)
        if not cookie:
            return self._send(403, b"This launch link is invalid, expired or already used. Start MULTI-OSINT-TOOL again, or type 'link' in its terminal.", "text/plain; charset=utf-8")
        page = b'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=/"><title>MULTI-OSINT-TOOL</title><p>Opening ...</p>'
        self._send(200, page, "text/html; charset=utf-8", {"Set-Cookie": f"{COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}"})

    # ---- static UI
    def _static(self, path: str) -> None:
        rel = path.lstrip("/") or "mot_index.html"
        if not STATIC_NAME.match(rel) or ".." in rel or rel.startswith((".", "/")) or "//" in rel or "/." in rel:
            return self._err(404, "Not found.", "not_found")
        base = C.UI_DIR.resolve()
        f = (base / rel).resolve()
        ext = f.suffix.lower()
        if ext not in MIME or not f.is_file() or not f.is_relative_to(base):
            return self._err(404, "Not found.", "not_found")
        self._send(200, f.read_bytes(), MIME[ext])


class _HttpErr(Exception):
    def __init__(self, status: int, msg: str, code: str):
        super().__init__(msg)
        self.status, self.msg, self.code = status, msg, code


class MotServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32
    allow_reuse_address = (C.os.name != "nt")  # POSIX: restart right after a crash; Windows: reuse would allow port hijack
    address_family = socket.AF_INET

    def __init__(self, app: App, port: int, secret: bytes, max_threads: int = 48):
        self.app = app
        self.sessions = Sessions(secret)
        self.limiter = RateLimiter()
        self.stop_event = threading.Event()
        self.routes = build_routes(app, self.sessions, self.stop_event)
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self.allowed_origins = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
        self._sem = threading.BoundedSemaphore(max_threads)
        super().__init__(("127.0.0.1", port), Handler)

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows: no other process may share this port
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def process_request(self, request, client_address) -> None:
        if not self._sem.acquire(blocking=False):  # thread cap: shed load instead of exhausting the machine
            try:
                request.sendall(b"HTTP/1.0 503 Busy\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return

        def run() -> None:
            try:
                self.finish_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
            finally:
                self.shutdown_request(request)
                self._sem.release()

        threading.Thread(target=run, name="mot-http", daemon=True).start()

    def handle_error(self, request, client_address) -> None:  # keep the default traceback printer off stderr
        log.debug("connection error from %s", client_address[0])

    def start_idle_watchdog(self) -> threading.Thread:
        def loop() -> None:
            while not self.stop_event.wait(10):
                try:
                    self.app.idle_check()
                except Exception:
                    log.exception("idle watchdog error")

        t = threading.Thread(target=loop, name="mot-idle", daemon=True)
        t.start()
        return t


def mint_launch_link(secret: bytes, port: int) -> str:
    """Used by the supervisor. The token goes into a local launch file, never onto a command line."""
    return Sessions(secret).mint_launch()
