"""MULTI-OSINT-TOOL :: connector framework.

Every network call and every subprocess goes through Ctx, which (1) asks the shield for
permission first, (2) isolates Tor circuits per connector, (3) caps response sizes, (4) retries
with back-off, (5) never puts a secret in an exception message. One connector failing can never
break another.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

import requests

import mot_config as C
from mot_netguard import NetGuard, NetworkUnsafe
from mot_vault import Redactor

log = logging.getLogger("mot.conn")

OK, EMPTY, NO_KEY, KEY_INVALID, PLAN, RATE = "ok", "empty", "no_key", "key_invalid", "plan_limit", "rate_limited"
BLOCKED, MISSING, UNSUPPORTED, HANDOFF, SKIPPED = "blocked", "missing_tool", "unsupported", "handoff", "skipped"
ERROR, TIMEOUT, CANCELLED, OFFLINE, EXPORT = "error", "timeout", "cancelled", "offline", "export"
FALLBACK_STATUSES = (KEY_INVALID, PLAN)
AUTH_HEADERS = {"authorization", "x-api-key", "x-key", "x-apikey", "api-key", "hibp-api-key", "dehashed-api-key"}
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


class Cancelled(Exception):
    pass


class NetError(Exception):
    pass


@dataclass
class Finding:
    kind: str
    title: str
    value: str = ""
    url: str = ""
    data: dict = field(default_factory=dict)
    ents: list = field(default_factory=list)  # [(entity_type, value, relation)]
    confidence: float = 0.5
    sensitive: bool = False
    source: str = ""
    fid: str = field(default_factory=lambda: uuid.uuid4().hex[:10])

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        keep = {k: d[k] for k in ("kind", "title", "value", "url", "data", "confidence", "sensitive", "source", "fid") if k in d}
        f = cls(**keep)
        f.ents = [tuple(e) for e in d.get("ents", []) if isinstance(e, (list, tuple)) and len(e) == 3]
        return f

    def to_dict(self, public: bool = True) -> dict:
        d = asdict(self)
        if public:
            d["has_secret"] = any(str(k).startswith("_") for k in self.data)
            d["data"] = {k: v for k, v in self.data.items() if not str(k).startswith("_")}
        return d


@dataclass
class Result:
    connector: str
    status: str = ERROR
    mode: str = ""
    findings: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0
    handoff_url: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Result":
        r = cls(**{k: d[k] for k in ("connector", "status", "mode", "notes", "error", "elapsed", "handoff_url") if k in d})
        r.findings = [Finding.from_dict(x) for x in d.get("findings", [])]
        return r

    def to_dict(self, public: bool = True) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict(public) for f in self.findings]
        return d


@dataclass(frozen=True)
class Meta:
    id: str
    name: str
    category: str
    kind: str  # api | cli | handoff | export | local
    targets: tuple
    key_fields: tuple = ()
    optional_fields: tuple = ()
    free_mode: str = ""
    site: str = ""
    key_url: str = ""
    docs_url: str = ""
    route: str = "vpn"  # preferred route when shield mode is tor_over_vpn
    cli_guard: bool = False
    needs_tor: bool = False
    tool_names: tuple = ()
    install: str = ""
    min_interval: float = 0.0
    canary: tuple = ()
    canary_cost: bool = False
    note: str = ""
    free_targets: tuple = ()  # target types the free tier can serve; empty = every supported type


class HttpResult:
    __slots__ = ("status", "headers", "body", "url")

    def __init__(self, status: int, headers: dict, body: bytes, url: str):
        self.status, self.headers, self.body, self.url = status, headers, body, url

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.text)


@dataclass
class CliResult:
    rc: int
    out: str
    err: str
    timed_out: bool


def _url_allowed(url: str) -> bool:
    u = urlparse(url)
    return u.scheme == "https" or (u.scheme == "http" and (u.hostname or "").endswith(".onion"))


def _retry_after(h: dict) -> Optional[float]:
    for k, v in h.items():
        if k.lower() == "retry-after":
            try:
                return float(v)
            except ValueError:
                return None
    return None


def _kill_tree(p: subprocess.Popen) -> None:
    try:
        import psutil

        parent = psutil.Process(p.pid)
        for ch in parent.children(recursive=True):
            try:
                ch.kill()
            except Exception:
                pass
        parent.kill()
        return
    except Exception:
        pass
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True, timeout=10)
        else:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


_RATE_LOCK = threading.Lock()
_RATE_LAST: dict[str, float] = {}


class Ctx:
    def __init__(self, guard: NetGuard, key_getter: Callable[[str], Optional[dict]], cfg: C.Config, job_id: str,
                 cancel: threading.Event, deadline: float, tmp_dir: Path):
        self.guard, self._keys, self.cfg, self.job_id = guard, key_getter, cfg, job_id
        self.cancel, self.deadline, self.tmp_dir = cancel, deadline, Path(tmp_dir)

    # ---- control
    def expired(self) -> bool:
        return self.cancel.is_set() or time.time() > self.deadline

    def check(self) -> None:
        if self.cancel.is_set():
            raise Cancelled()

    def sleep(self, secs: float) -> None:
        if self.cancel.wait(max(0.0, secs)):
            raise Cancelled()

    def key(self, cid: str) -> Optional[dict]:
        return self._keys(cid)

    def route(self, meta: Meta, pref: Optional[str] = None) -> str:
        override = self.cfg.connector(meta.id).get("route", "auto")
        want = override if override in ("tor", "vpn") else (pref or meta.route)
        return self.guard.route_for(want, needs_tor=meta.needs_tor)

    def _pace(self, meta: Meta) -> None:
        if meta.min_interval <= 0:
            return
        with _RATE_LOCK:
            wait = _RATE_LAST.get(meta.id, 0.0) + meta.min_interval - time.time()
            _RATE_LAST[meta.id] = max(time.time(), _RATE_LAST.get(meta.id, 0.0) + meta.min_interval)
        if wait > 0:
            self.sleep(min(wait, 60))

    # ---- HTTP
    def request(self, meta: Meta, method: str, url: str, *, headers: Optional[dict] = None, params: Optional[dict] = None,
                json_body=None, data=None, timeout=None, max_bytes: int = 5_000_000, retries: int = 2,
                pref: Optional[str] = None) -> HttpResult:
        if not _url_allowed(url):
            raise NetError("Only HTTPS endpoints (or http .onion) are allowed.")
        route = self.route(meta, pref)
        for attempt in range(retries + 1):
            self.check()
            self.guard.assert_safe(route)
            self._pace(meta)
            try:
                sess = self.guard.session(route, f"{self.job_id}-{meta.id}")
                resp = self._once(sess, method, url, headers, params, json_body, data, timeout, max_bytes)
            except requests.exceptions.RequestException as exc:
                if attempt < retries:
                    self.sleep(min(2 ** attempt + random.random(), 8))
                    continue
                raise NetError(Redactor.redact(f"{type(exc).__name__}: {exc}")[:200]) from None
            if resp.status in (429, 502, 503, 504) and attempt < retries:
                ra = _retry_after(resp.headers)
                self.sleep(min(ra if ra is not None else 2 ** attempt, 20))
                continue
            return resp
        raise NetError("Request failed.")

    def _once(self, sess, method, url, headers, params, json_body, data, timeout, max_bytes) -> HttpResult:
        tmo = tuple(timeout or self.cfg.get("search", "http_timeout", default=[10, 30]))
        cur, m, hdrs = url, method, dict(headers or {})
        for hop in range(4):
            r = sess.request(m, cur, headers=hdrs, params=params if hop == 0 else None, json=json_body if hop == 0 else None,
                             data=data if hop == 0 else None, timeout=tmo, stream=True, allow_redirects=False)
            try:
                if r.is_redirect and hop < 3:
                    nxt = urljoin(cur, r.headers.get("Location", ""))
                    if not _url_allowed(nxt):
                        raise NetError("Redirect to a disallowed URL was blocked.")
                    if urlparse(nxt).netloc != urlparse(cur).netloc:
                        hdrs = {k: v for k, v in hdrs.items() if k.lower() not in AUTH_HEADERS}
                    cur, m = nxt, ("GET" if r.status_code in (301, 302, 303) else m)
                    continue
                buf = bytearray()
                for chunk in r.iter_content(65536):
                    buf += chunk
                    if len(buf) > max_bytes:
                        break
                return HttpResult(r.status_code, dict(r.headers), bytes(buf), cur)
            finally:
                r.close()
        raise NetError("Too many redirects.")

    def resolve(self, meta: Meta, name: str) -> list[str]:
        """DNS over HTTPS through the shield. The target name never touches your local resolver."""
        import ipaddress

        out: list[str] = []
        for rtype in ("A", "AAAA"):
            r = self.request(meta, "GET", "https://cloudflare-dns.com/dns-query", params={"name": name, "type": rtype},
                             headers={"accept": "application/dns-json"}, retries=1)
            if r.ok:
                try:
                    for a in r.json().get("Answer") or []:
                        if a.get("type") in (1, 28):
                            try:
                                out.append(str(ipaddress.ip_address(str(a.get("data", "")).strip())))
                            except ValueError:
                                pass
                except ValueError:
                    pass
        return sorted(set(out))

    # ---- CLI
    def tool(self, cid: str, names: tuple) -> Optional[str]:
        p = self.cfg.get("tools", cid, default="")
        if p and Path(p).exists():
            return str(p)
        for base in (C.LIBS / "tools" / cid / "bin", C.LIBS / "tools" / cid / "Scripts", C.LIBS / "tools" / cid / "src", C.BIN):
            for n in names:
                for ext in ("", ".exe", ".cmd", ".bat"):
                    cand = base / (n + ext)
                    if cand.is_file():
                        return str(cand)
        for n in names:
            w = shutil.which(n)
            if w:
                return w
        return None

    def cli(self, meta: Meta, argv: list, *, timeout: int, route: Optional[str] = None, cwd: Optional[Path] = None,
            extra_env: Optional[dict] = None, max_bytes: int = 8_000_000) -> CliResult:
        route = route or self.route(meta)
        self.check()
        self.guard.assert_safe(route, cli_guard=meta.cli_guard)
        env = self.guard.subprocess_env(route, f"{self.job_id}-{meta.id}")
        env.update(extra_env or {})
        kw = dict(stdin=subprocess.DEVNULL, env=env, cwd=str(cwd or self.tmp_dir), shell=False)
        if os.name == "nt":
            kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            kw["start_new_session"] = True
        with tempfile.TemporaryFile() as fo, tempfile.TemporaryFile() as fe:
            p = subprocess.Popen([str(a) for a in argv], stdout=fo, stderr=fe, **kw)
            end, timed = time.time() + timeout, False
            while True:
                try:
                    rc = p.wait(timeout=0.5)
                    break
                except subprocess.TimeoutExpired:
                    if self.expired() or time.time() > end:
                        timed = True
                        _kill_tree(p)
                        try:
                            rc = p.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            rc = -9
                        break
            fo.seek(0)
            fe.seek(0)
            out = fo.read(max_bytes).decode("utf-8", "replace")
            err = fe.read(200_000).decode("utf-8", "replace")
        self.check()
        return CliResult(rc, out, err, timed)


# ---------------------------------------------------------------------------------- base class
REGISTRY: dict[str, "Connector"] = {}


def register(cls):
    inst = cls()
    REGISTRY[inst.meta.id] = inst
    return cls


def mask_secret(s: str) -> str:
    s = str(s)
    if len(s) <= 1:
        return "*" * len(s)
    return f"{s[0]}{'*' * min(8, len(s) - 1)} ({len(s)} chars)"  # first character + length only


def as_list(v) -> list:
    if v is None or v == "":
        return []
    return v if isinstance(v, list) else [v]


class Connector:
    meta: Meta

    @property
    def id(self) -> str:
        return self.meta.id

    def supports(self, ttype: str) -> bool:
        return ttype in self.meta.targets

    def keyed(self, target: str, ttype: str, ctx: Ctx, key: dict) -> Result:  # overridden by API connectors
        raise NotImplementedError

    def free(self, target: str, ttype: str, ctx: Ctx) -> Result:  # overridden when a free tier exists
        raise NotImplementedError

    @property
    def has_keyed(self) -> bool:
        return type(self).keyed is not Connector.keyed

    @property
    def has_free(self) -> bool:
        return type(self).free is not Connector.free

    def selftest(self) -> list[str]:  # offline parser self-check; returns problems
        return []

    def run(self, target: str, ttype: str, ctx: Ctx) -> Result:
        t0 = time.time()
        res = Result(connector=self.id)
        try:
            res = self._dispatch(target, ttype, ctx)
        except Cancelled:
            res.status = CANCELLED
        except NetworkUnsafe as exc:
            res.status, res.error = BLOCKED, str(exc)
        except NetError as exc:
            res.status, res.error = ERROR, str(exc)
        except Exception as exc:
            log.exception("connector %s crashed", self.id)
            res.status, res.error = ERROR, f"{type(exc).__name__} (details in logs/mot.log)"
        res.connector = self.id
        res.elapsed = round(time.time() - t0, 2)
        for f in res.findings:
            f.source = f.source or self.id
        return res

    def _dispatch(self, target: str, ttype: str, ctx: Ctx) -> Result:
        key = ctx.key(self.id)
        if key and self.has_keyed:
            r = self.keyed(target, ttype, ctx, key)
            r.mode = r.mode or "keyed"
            if r.status in FALLBACK_STATUSES and self.has_free:
                why = "API key rejected" if r.status == KEY_INVALID else "plan does not allow this lookup"
                r2 = self.free(target, ttype, ctx)
                r2.mode = "free"
                r2.notes.insert(0, f"{why}; fell back to the free tier.")
                return r2
            return r
        if self.has_free:
            r = self.free(target, ttype, ctx)
            r.mode = r.mode or "free"
            if self.meta.key_fields and not key:
                r.notes.append("Add an API key in Settings for fuller coverage.")
            return r
        return Result(connector=self.id, status=NO_KEY, mode="none", handoff_url=self.meta.key_url or self.meta.site,
                      notes=["This service has no free API. Add a key in Settings, or use the website manually."])

    # ---- helpers for subclasses
    def res(self, status: str, mode: str = "", **kw) -> Result:
        return Result(connector=self.id, status=status, mode=mode, **kw)

    def http_status(self, r: HttpResult, ok_status: str = OK) -> Optional[Result]:
        """Map common HTTP errors to a Result; None means 2xx (continue parsing)."""
        s = r.status
        if 200 <= s < 300:
            return None
        if s in (401,):
            return self.res(KEY_INVALID, error="Key rejected (HTTP 401).")
        if s in (402, 403):
            return self.res(PLAN, error=f"Not permitted for this plan or blocked (HTTP {s}).")
        if s == 404:
            return self.res(EMPTY, notes=["No record found."])
        if s == 429:
            return self.res(RATE, error="Rate limit reached; retry later.")
        return self.res(ERROR, error=f"Service returned HTTP {s}.")
