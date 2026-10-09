"""MULTI-OSINT-TOOL :: configuration, paths, atomic file IO.

Non-secret settings only. Secrets (API keys, shield baseline) live exclusively in the
encrypted vault (mot_vault.py). Environment overrides: MOT_DATA (data dir), MOT_HOME.
"""
from __future__ import annotations

import copy
import json
import os
import re
import sys
import tempfile
import threading
from pathlib import Path

APP_NAME = "MULTI-OSINT-TOOL"
APP_VERSION = "1.0.0"
MIN_PY = (3, 10)

ROOT = Path(os.environ.get("MOT_HOME") or Path(__file__).resolve().parent).resolve()
DATA = Path(os.environ.get("MOT_DATA") or ROOT / "mot_data").resolve()
SUBDIRS = ("vault", "cases", "logs", "recovery", "tmp", "exports", "tor")
UI_DIR = ROOT / "mot_ui"
LIBS = ROOT / "libs"
WHEELS = ROOT / "wheels"
MODELS = ROOT / "models"
BIN = ROOT / "bin"
CONFIG_FILE = DATA / "mot_config.json"
VAULT_FILE = DATA / "vault" / "mot_vault.motv"

SHIELD_MODES = ("tor_over_vpn", "tor", "vpn", "proxy", "direct")
ROUTES = ("auto", "tor", "vpn")

DEFAULTS: dict = {
    "schema": 1,
    "server": {"host": "127.0.0.1", "port": 8765, "idle_lock_minutes": 15, "secure_window": True},
    "shield": {
        "mode": "tor_over_vpn",
        "tor_socks": "127.0.0.1:9050",
        "custom_proxy": "",
        "vpn_iface_pattern": "",
        "require_baseline": True,
        "allow_direct": False,
        "recheck_seconds": 60,
    },
    "search": {"max_workers": 0, "connector_timeout": 90, "job_timeout": 300, "http_timeout": [10, 30]},
    "connectors": {},
    "tools": {},
    "toolenv": {"python": ""},
    "theharvester": {
        "sources": "crtsh,certspotter,hackertarget,rapiddns,otx,subdomaincenter,urlscan,waybackarchive,commoncrawl,thc"
    },
    "privacy": {"mask_sensitive": True, "persist_secrets": False},
    "ack": {"version": 0},
    "ui": {"theme": "dark"},
}


def ensure_dirs() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    for d in SUBDIRS:
        (DATA / d).mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(DATA, 0o700)
        except OSError:
            pass


def atomic_write(path: Path | str, data: bytes, mode: int = 0o600) -> None:
    """Crash-safe write: temp file in same dir -> fsync -> atomic replace."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict) and k not in ("connectors", "tools"):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


_ID_RE = re.compile(r"^[a-z0-9_]{2,32}$")


class Config:
    """Thread-safe JSON config with validation. Invalid values are repaired, never trusted."""

    def __init__(self, path: Path = CONFIG_FILE):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.data: dict = copy.deepcopy(DEFAULTS)
        self.repairs: list[str] = []

    def load(self) -> "Config":
        with self._lock:
            self.repairs = []
            loaded: dict = {}
            if self.path.exists():
                try:
                    loaded = json.loads(self.path.read_text(encoding="utf-8"))
                    if not isinstance(loaded, dict):
                        raise ValueError("config root is not an object")
                except (OSError, ValueError) as exc:
                    bak = self.path.with_suffix(".corrupt")
                    try:
                        os.replace(self.path, bak)
                    except OSError:
                        pass
                    self.repairs.append(f"Config unreadable ({type(exc).__name__}); defaults restored, copy kept as {bak.name}")
                    loaded = {}
            self.data = _merge(DEFAULTS, loaded)
            self._validate()
            return self

    def _validate(self) -> None:
        d, fix = self.data, self.repairs
        srv = d["server"]
        if srv.get("host") != "127.0.0.1":
            fix.append("server.host must be 127.0.0.1 (loopback only); reset")
            srv["host"] = "127.0.0.1"
        if not (isinstance(srv.get("port"), int) and not isinstance(srv.get("port"), bool) and 1024 <= srv["port"] <= 65535):
            fix.append("server.port invalid; reset to 8765")
            srv["port"] = 8765
        if not (isinstance(srv.get("idle_lock_minutes"), int) and 1 <= srv["idle_lock_minutes"] <= 240):
            srv["idle_lock_minutes"] = 15
        srv["secure_window"] = bool(srv.get("secure_window", True))
        sh = d["shield"]
        if sh.get("mode") not in SHIELD_MODES:
            fix.append("shield.mode invalid; reset to tor_over_vpn")
            sh["mode"] = "tor_over_vpn"
        if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,100}:\d{2,5}", str(sh.get("tor_socks", ""))):
            sh["tor_socks"] = "127.0.0.1:9050"
        if not (isinstance(sh.get("recheck_seconds"), int) and 10 <= sh["recheck_seconds"] <= 900):
            sh["recheck_seconds"] = 60
        if len(str(sh.get("vpn_iface_pattern", ""))) > 80:
            sh["vpn_iface_pattern"] = ""
        for flag in ("require_baseline", "allow_direct"):
            sh[flag] = bool(sh.get(flag, flag == "require_baseline"))
        s = d["search"]
        if not (isinstance(s.get("connector_timeout"), int) and 10 <= s["connector_timeout"] <= 900):
            s["connector_timeout"] = 90
        if not (isinstance(s.get("job_timeout"), int) and 30 <= s["job_timeout"] <= 3600):
            s["job_timeout"] = 300
        if not (isinstance(s.get("max_workers"), int) and 0 <= s["max_workers"] <= 32):
            s["max_workers"] = 0
        ht = s.get("http_timeout")
        if not (isinstance(ht, list) and len(ht) == 2 and all(isinstance(x, (int, float)) and 1 <= x <= 300 for x in ht)):
            s["http_timeout"] = [10, 30]
        conns = d.get("connectors", {})
        clean = {}
        for cid, v in (conns.items() if isinstance(conns, dict) else []):
            if _ID_RE.match(str(cid)) and isinstance(v, dict):
                route = v.get("route", "auto")
                clean[cid] = {"enabled": bool(v.get("enabled", True)), "route": route if route in ROUTES else "auto"}
        d["connectors"] = clean
        tools = d.get("tools", {})
        d["tools"] = {k: str(v)[:400] for k, v in tools.items() if _ID_RE.match(str(k))} if isinstance(tools, dict) else {}
        te = d.get("toolenv")
        d["toolenv"] = {"python": str(te.get("python", ""))[:400]} if isinstance(te, dict) else {"python": ""}
        th = d.get("theharvester")
        src = str(th.get("sources", "")) if isinstance(th, dict) else ""
        d["theharvester"] = {"sources": src if re.fullmatch(r"[a-zA-Z0-9,_-]{1,300}", src) else DEFAULTS["theharvester"]["sources"]}
        pv = d.get("privacy") if isinstance(d.get("privacy"), dict) else {}
        d["privacy"] = {"mask_sensitive": bool(pv.get("mask_sensitive", True)), "persist_secrets": bool(pv.get("persist_secrets", False))}
        ak = d.get("ack") if isinstance(d.get("ack"), dict) else {}
        d["ack"] = {"version": ak.get("version") if isinstance(ak.get("version"), int) and not isinstance(ak.get("version"), bool) and 0 <= ak.get("version") <= 1000 else 0}
        ui = d.get("ui") if isinstance(d.get("ui"), dict) else {}
        d["ui"] = {"theme": ui.get("theme") if ui.get("theme") in ("dark", "light") else "dark"}

    def get(self, *keys, default=None):
        with self._lock:
            cur = self.data
            for k in keys:
                if not isinstance(cur, dict) or k not in cur:
                    return default
                cur = cur[k]
            return copy.deepcopy(cur)

    def set(self, *keys_and_value) -> None:
        *keys, value = keys_and_value
        with self._lock:
            cur = self.data
            for k in keys[:-1]:
                cur = cur.setdefault(k, {})
            cur[keys[-1]] = value
            self._validate()
            self.save()

    def save(self) -> None:
        with self._lock:
            atomic_write(self.path, json.dumps(self.data, indent=2, sort_keys=True).encode("utf-8"))

    def connector(self, cid: str) -> dict:
        return {"enabled": True, "route": "auto", **self.get("connectors", cid, default={})}


def python_ok() -> bool:
    return sys.version_info >= MIN_PY
