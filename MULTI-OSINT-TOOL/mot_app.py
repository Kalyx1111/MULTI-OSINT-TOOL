"""MULTI-OSINT-TOOL :: service layer.

Everything the interface can do lives here, with no HTTP in it, so it can be tested directly and
the server stays a thin, hardened shell. Rules that hold for every method:
  * nothing works while the vault is locked (the audit/case/journal keys are derived from it),
  * secrets leave this layer only through reveal_*() after the master password is re-entered,
  * every error is an AppError with a safe message: no paths, no stack traces, no secrets.
"""
from __future__ import annotations

import base64
import gc
import io
import logging
import os
import re
import shutil
import threading
import time
import webbrowser
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

import mot_config as C
import mot_conn_api  # noqa: F401  (importing registers the connectors)
import mot_conn_cli  # noqa: F401
import mot_conn_web  # noqa: F401
import mot_conn_intel  # noqa: F401
import mot_catalog as K
import mot_connectors_base as B
import mot_correlate as X
import mot_hwdetect as H
import mot_tools as T
from mot_audit import AuditLog
from mot_netguard import NetGuard, NetworkUnsafe, TorManager
from mot_orchestrator import TYPES, InputError, Orchestrator, detect_type, normalize
from mot_resilience import Doctor, Heartbeat, Journal, previous_run_crashed
from mot_store import CaseStore, StoreError
from mot_vault import Redactor, Vault, VaultAuthError, VaultError, VaultLocked, VaultThrottled

log = logging.getLogger("mot.app")

ACK_VERSION = 1
ENV_PREFIX = "MOT_KEY_"
REQUESTED = ["sherlock", "maltego", "shodan", "spiderfoot", "dehashed", "hibp", "pimeyes", "epieos", "hunter"]  # the nine you chose, in your order
ADDED = ["intelx", "virustotal", "urlscan", "github", "hudsonrock", "wayback", "maigret", "holehe", "theharvester", "phoneinfoga", "ahmia"]
EXPORTS = {"json": ("application/json", "json"), "csv": ("text/csv; charset=utf-8", "csv"), "md": ("text/markdown; charset=utf-8", "md"),
           "maltego": ("application/zip", "zip")}
CASE_ID = re.compile(r"^[0-9a-f]{16}$")
CID = re.compile(r"^[a-z0-9_]{2,32}$")

# Shown on the Shield page. They open OUTSIDE the shield, so the UI warns before following them.
GUIDANCE = [
    {"id": "vpn", "title": "A VPN with a kill-switch", "why": "Hides your real IP from every service MOT talks to. Turn the VPN client's own kill-switch ON: MOT is a second gate, not a replacement.",
     "links": [{"name": "Proton VPN", "url": "https://protonvpn.com"}, {"name": "Mullvad", "url": "https://mullvad.net"}, {"name": "IVPN", "url": "https://www.ivpn.net"}]},
    {"id": "tor", "title": "Tor", "why": "Routes searches through three relays and enables dark-web index lookups. MOT reaches onion services only through Tor and never opens onion pages itself.",
     "links": [{"name": "Tor Browser and Expert Bundle", "url": "https://www.torproject.org/download/"}]},
    {"id": "mail", "title": "A separate e-mail identity for tool accounts", "why": "Register vendor accounts with a dedicated alias that is not linked to your real identity, so a vendor breach cannot be tied back to you.",
     "links": [{"name": "Proton Mail", "url": "https://proton.me/mail"}, {"name": "SimpleLogin aliases", "url": "https://simplelogin.io"}]},
    {"id": "os", "title": "A clean environment for high-risk work", "why": "For sensitive investigations use a separate user account, a VM, or an amnesic system, so that nothing from your daily life is on the machine.",
     "links": [{"name": "Tails", "url": "https://tails.net"}]},
]


class AppError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request", **extra):
        super().__init__(message)
        self.status, self.code, self.extra = status, code, extra


def _b64_file(data: Optional[str], limit: int = 512 * 1024) -> Optional[bytes]:
    if not data:
        return None
    try:
        raw = base64.b64decode(data.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise AppError("Key file could not be read.") from exc
    if not raw or len(raw) > limit:
        raise AppError("Key file must be between 1 byte and 512 KiB.")
    return raw


_NOT_RUN = {
    "off": "Turned off in Connections, so it will not run.",
    "needs_key": "Needs a key. Add one in Connections to use it.",
    "handoff": "Website only. You open it yourself; the program never sends it the target.",
    "export": "Exported to a file; not searched live.",
    "manual": "Kept manual on purpose, so the program does not run it.",
    "research": "Not verified yet, so the program does not use it.",
}


def _catalog_row(e: K.Entry) -> dict:
    """A source with no connector. Listed on Connections so every source's purpose is visible."""
    row = {"id": e.id, "name": e.name, "kind": "catalog", "tier": "catalog", "targets": [], "free_mode": "", "site": e.official,
           "key_url": "", "docs_url": e.official, "key_fields": [], "optional_fields": [], "has_keyed": False, "has_free": False,
           "mode": e.status, "enabled": False, "route": "", "needs_tor": False, "cli_guard": False, "canary_cost": False,
           "free_targets": [], "testable": False, "note": e.note, "keys": {}}
    row.update(K.describe(e))
    return row


def _plan_row(e: K.Entry, c, state: str, mode: str, installed: bool) -> dict:
    """One line of the search preview: what this source is used for, and whether it will run for this search."""
    d = K.describe(e, tuple(c.meta.targets) if c else (), c.meta.kind if c else None)
    return {"id": e.id, "name": e.name, "use": e.use, "category": e.category, "mode": mode, "state": state,
            "kind": c.meta.kind if c else "catalog", "needs_tor": bool(c and c.meta.needs_tor), "installed": installed,
            "access": e.access, "access_label": d["access_label"], "search_types": d["search_types"],
            "reason": "" if state == "will_run" else _NOT_RUN.get(state, "")}


class App:
    def __init__(self) -> None:
        C.ensure_dirs()
        self.cfg = C.Config().load()
        self.hw = H.detect()
        self.tune = H.autotune(self.hw)
        self.vault = Vault()
        self.guard = NetGuard(self.cfg, self._baseline_get, self._baseline_set)
        self.tor = TorManager(self.cfg)
        self.tor_status = {"state": "idle", "msg": ""}
        self.audit: Optional[AuditLog] = None
        self.store: Optional[CaseStore] = None
        self.journal: Optional[Journal] = None
        self.orch: Optional[Orchestrator] = None
        self.doctor: Optional[Doctor] = None
        self.crash = previous_run_crashed()  # must be read BEFORE this run's heartbeat overwrites the file
        self.heartbeat = Heartbeat()
        self.installing: dict[str, dict] = {}
        self.started = time.time()
        self.last_activity = time.time()
        self._keyfile: Optional[bytes] = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ lifecycle
    def boot(self) -> None:
        self.heartbeat.start()

    def shutdown(self, clean: bool = True) -> None:
        try:
            self.lock(reason="shutdown")
        except Exception:
            log.exception("lock on shutdown failed")
        self.tor.stop()
        self.heartbeat.stop(clean=clean)

    @property
    def state(self) -> str:
        if not self.vault.exists():
            return "no_vault"
        return "unlocked" if self.vault.unlocked else "locked"

    def touch(self) -> None:
        self.last_activity = time.time()

    def running_jobs(self) -> int:
        return sum(1 for j in list(self.orch.jobs.values()) if j.status == "running") if self.orch else 0

    def idle_check(self) -> bool:
        if self.state != "unlocked":
            return False
        limit = int(self.cfg.get("server", "idle_lock_minutes", default=15)) * 60
        if time.time() - self.last_activity > limit and self.running_jobs() == 0:
            self.lock(reason="idle")
            return True
        return False

    def _need(self) -> Orchestrator:
        if self.state != "unlocked" or not (self.orch and self.audit and self.store and self.journal):
            raise AppError("The vault is locked.", 423, "locked")
        return self.orch

    def status(self) -> dict:
        d = {"name": C.APP_NAME, "version": C.APP_VERSION, "state": self.state, "uptime": int(time.time() - self.started)}
        if d["state"] != "unlocked":
            d["needs_keyfile"] = self.vault.needs_keyfile() if self.vault.exists() else False
        else:
            d["theme"] = self.cfg.get("ui", "theme", default="dark")
            d["ack_ok"] = int(self.cfg.get("ack", "version", default=0)) >= ACK_VERSION
            d["restored_from_backup"] = self.vault.restored_from_backup
        return d

    # ------------------------------------------------------------------ vault
    def create_vault(self, password: str, confirm: str, keyfile_b64: Optional[str] = None) -> dict:
        if self.vault.exists():
            raise AppError("A vault already exists.", 409, "conflict")
        if password != confirm:
            raise AppError("The two passwords do not match.")
        kf = _b64_file(keyfile_b64)
        try:
            self.vault.create(password, keyfile=kf, kdf=self.tune["kdf"])
        except VaultError as exc:
            raise AppError(str(exc), 400, "weak_password") from None
        self._keyfile = kf
        self._after_unlock(first=True)
        return self.status()

    def unlock(self, password: str, keyfile_b64: Optional[str] = None) -> dict:
        kf = _b64_file(keyfile_b64)
        try:
            self.vault.unlock(password, keyfile=kf)
        except VaultThrottled as exc:
            raise AppError(str(exc), 429, "throttled", wait=exc.wait) from None
        except VaultAuthError:
            raise AppError("Wrong password, missing key file, or the vault is damaged.", 401, "auth_failed") from None
        except VaultError as exc:
            raise AppError(str(exc), 400, "vault") from None
        self._keyfile = kf
        self._after_unlock()
        return self.status()

    def _after_unlock(self, first: bool = False) -> None:
        with self._lock:
            self.audit = AuditLog(C.DATA / "logs" / "mot_audit.log", self.vault.subkey("audit"))
            self.store = CaseStore(C.DATA / "cases", self.vault.subkey("cases"))
            self.journal = Journal(C.DATA / "recovery", self.vault.subkey("journal"))
            self.orch = Orchestrator(self.cfg, self.guard, self.key_getter, self.audit, self.store, self.journal, self.tune)
            self.doctor = Doctor(self.cfg, self.vault, self.audit, self.guard)
            self.guard.start_monitor()
            self.audit.append("vault_created" if first else "vault_unlocked", restored_from_backup=self.vault.restored_from_backup)
            self.touch()

    def lock(self, reason: str = "user") -> dict:
        with self._lock:
            if self.orch:
                for j in list(self.orch.jobs.values()):
                    if j.status == "running":
                        j.cancel.set()
            if self.audit:
                try:
                    self.audit.append("vault_locked", reason=reason)
                except Exception:
                    log.exception("audit write on lock failed")
            self.guard.stop_monitor()
            self.orch = self.store = self.journal = self.audit = self.doctor = None
            self._keyfile = None
            self.vault.lock()
            self._wipe_tmp()
            gc.collect()
        return self.status()

    def panic(self) -> dict:
        """One action: cancel everything, lock, remove temp files, stop the Tor process MOT started."""
        self.tor.stop()
        return self.lock(reason="panic")

    def _reauth(self, password: str) -> None:
        self._need()
        try:
            ok = self.vault.verify_password(password, keyfile=self._keyfile)
        except VaultThrottled as exc:
            raise AppError(str(exc), 429, "throttled", wait=exc.wait) from None
        except VaultLocked:
            raise AppError("The vault is locked.", 423, "locked") from None
        if not ok:
            self.audit.append("reauth_failed")
            raise AppError("Wrong master password.", 401, "reauth_failed")

    def change_password(self, old: str, new: str, confirm: str) -> dict:
        self._need()
        if new != confirm:
            raise AppError("The two new passwords do not match.")
        try:
            self.vault.change_password(old, new, keyfile=self._keyfile, new_keyfile=self._keyfile)
        except VaultThrottled as exc:
            raise AppError(str(exc), 429, "throttled", wait=exc.wait) from None
        except VaultAuthError:
            raise AppError("Current password is incorrect.", 401, "reauth_failed") from None
        except VaultError as exc:
            raise AppError(str(exc), 400, "weak_password") from None
        self.audit.append("vault_password_changed")
        return {"changed": True}

    def vault_backup(self, password: str) -> tuple[bytes, str]:
        self._reauth(password)
        self.audit.append("vault_backup_exported")
        return self.vault.backup_bytes(), f"mot-vault-backup-{time.strftime('%Y%m%d-%H%M%S')}.motv"

    @staticmethod
    def _wipe_tmp() -> None:
        t = C.DATA / "tmp"
        if not t.is_dir():
            return
        for child in t.iterdir():
            try:
                shutil.rmtree(child) if child.is_dir() else child.unlink()
            except OSError:
                pass

    # ------------------------------------------------------------------ baseline (kept inside the vault)
    def _baseline_get(self) -> str:
        try:
            return str((self.vault.get("__baseline") or {}).get("ip", ""))
        except VaultLocked:
            return ""

    def _baseline_set(self, ip: str) -> None:
        self.vault.set("__baseline", {"ip": ip}, internal=True)

    # ------------------------------------------------------------------ keys
    def _env_key(self, cid: str, field: str) -> str:
        return os.environ.get(f"{ENV_PREFIX}{cid.upper()}_{field.upper()}", "").strip()

    def key_getter(self, cid: str) -> Optional[dict]:
        """Vault first, then MOT_KEY_<TOOL>_<FIELD> environment variables. A key counts only when all required fields exist."""
        conn = B.REGISTRY.get(cid)
        if not conn or not conn.meta.key_fields:
            return None
        try:
            have = dict(self.vault.get(cid) or {})
        except VaultLocked:
            return None
        for f in conn.meta.key_fields + conn.meta.optional_fields:
            if f not in have:
                ev = self._env_key(cid, f)
                if ev:
                    have[f] = ev
                    Redactor.register(ev)
        return have if all(f in have for f in conn.meta.key_fields) else None

    def _key_state(self, conn: B.Connector) -> dict:
        out: dict = {}
        stored = {}
        try:
            stored = self.vault.get(conn.id) or {}
        except VaultLocked:
            pass
        for f in conn.meta.key_fields + conn.meta.optional_fields:
            if f in stored:
                out[f] = {"set": True, "source": "vault", "preview": B.mask_secret(stored[f]) if f in ("api_key", "token", "key") or "key" in f or "token" in f else "(set)", "required": f in conn.meta.key_fields}
            elif self._env_key(conn.id, f):
                out[f] = {"set": True, "source": "environment", "preview": "(from environment)", "required": f in conn.meta.key_fields}
            else:
                out[f] = {"set": False, "source": "", "preview": "", "required": f in conn.meta.key_fields}
        return out

    def _tool_path(self, conn: B.Connector) -> Optional[str]:
        dummy = type("D", (), {"cfg": self.cfg})()
        return B.Ctx.tool(dummy, conn.id, conn.meta.tool_names) if conn.meta.tool_names else None

    def connections(self) -> dict:
        self._need()
        order = REQUESTED + ADDED + [c for c in B.REGISTRY if c not in REQUESTED + ADDED]
        rows = []
        for cid in order:
            conn = B.REGISTRY.get(cid)
            if not conn:
                continue
            m = conn.meta
            keyed = bool(self.key_getter(cid)) and conn.has_keyed
            if m.kind == "handoff":
                mode = "handoff"
            elif m.kind == "export":
                mode = "export"
            elif keyed:
                mode = "paid"
            elif conn.has_free:
                mode = "free"
            else:
                mode = "needs_key"
            cfg = self.cfg.connector(cid)
            row = {"id": cid, "name": m.name, "category": m.category, "kind": m.kind, "targets": list(m.targets), "tier": "requested" if cid in REQUESTED else "added",
                   "free_mode": m.free_mode, "site": m.site, "key_url": m.key_url, "docs_url": m.docs_url, "key_fields": list(m.key_fields), "optional_fields": list(m.optional_fields),
                   "has_keyed": conn.has_keyed, "has_free": conn.has_free, "mode": mode, "enabled": bool(cfg.get("enabled", True)), "route": cfg.get("route", "auto"),
                   "needs_tor": m.needs_tor, "cli_guard": m.cli_guard, "canary_cost": m.canary_cost, "free_targets": list(m.free_targets), "testable": bool(m.canary and conn.has_keyed), "note": m.note,
                   "keys": self._key_state(conn) if m.key_fields else {}}
            if m.kind in ("cli", "local") and m.tool_names:
                path = self._tool_path(conn)
                row["installed"] = bool(path)
                row["installable"] = cid in T.RECIPES
            entry = K.BY_ID.get(cid)
            if entry:
                row.update(K.describe(entry, tuple(m.targets), m.kind))
                row["official"] = entry.official or m.site or m.docs_url
            rows.append(row)
        rows.extend(_catalog_row(e) for e in K.OTHER_ENTRIES)
        paid = sum(1 for r in rows if r["mode"] == "paid")
        return {"connections": rows, "summary": {"total": len(rows), "paid": paid, "free_ready": sum(1 for r in rows if r["mode"] == "free"), "needs_key": sum(1 for r in rows if r["mode"] == "needs_key")}}

    def _conn(self, cid: str) -> B.Connector:
        if not CID.match(cid) or cid not in B.REGISTRY:
            raise AppError("Unknown tool.", 404, "not_found")
        return B.REGISTRY[cid]

    def set_key(self, cid: str, fields: dict) -> dict:
        self._need()
        conn = self._conn(cid)
        allowed = set(conn.meta.key_fields + conn.meta.optional_fields)
        if not allowed:
            raise AppError("This tool does not use an API key.")
        bad = set(fields) - allowed
        if bad:
            raise AppError("Unexpected field(s): " + ", ".join(sorted(bad)))
        merged = dict(self.vault.get(cid) or {})
        for k, v in fields.items():
            v = str(v).strip()
            if v:
                merged[k] = v
            elif k in merged and k not in conn.meta.key_fields:
                merged.pop(k)  # blank optional field = remove it; blank required field = keep the stored one
        missing = [f for f in conn.meta.key_fields if f not in merged and not self._env_key(cid, f)]
        try:
            self.vault.set(cid, merged)
        except VaultError as exc:
            raise AppError(str(exc)) from None
        self.audit.append("key_saved", connector=cid, fields=sorted(fields))
        return {"saved": True, "complete": not missing, "missing": missing}

    def delete_key(self, cid: str) -> dict:
        self._need()
        self._conn(cid)
        self.vault.delete(cid)
        self.audit.append("key_deleted", connector=cid)
        return {"deleted": True}

    def reveal_key(self, cid: str, field: str, password: str) -> dict:
        conn = self._conn(cid)
        self._reauth(password)
        if field not in conn.meta.key_fields + conn.meta.optional_fields:
            raise AppError("Unknown field.")
        v = (self.vault.get(cid) or {}).get(field)
        if not v:
            raise AppError("Nothing is stored in the vault for this field.", 404, "not_found")
        self.audit.append("key_revealed", connector=cid, field=field)
        return {"value": v}

    def set_connector(self, cid: str, enabled: Optional[bool], route: Optional[str]) -> dict:
        self._need()
        self._conn(cid)
        cur = self.cfg.connector(cid)
        if enabled is not None:
            cur["enabled"] = bool(enabled)
        if route is not None:
            if route not in C.ROUTES:
                raise AppError("Route must be auto, tor or vpn.")
            cur["route"] = route
        self.cfg.set("connectors", cid, {"enabled": cur["enabled"], "route": cur["route"]})
        return {"enabled": cur["enabled"], "route": cur["route"]}

    def test_connection(self, cid: str, confirm_cost: bool = False) -> dict:
        self._need()
        conn = self._conn(cid)
        key = self.key_getter(cid)
        if not conn.has_keyed or not conn.meta.canary:
            raise AppError("This tool has no key test.", 409, "conflict")
        if not key:
            raise AppError("No complete key is stored for this tool.", 409, "no_key")
        if conn.meta.canary_cost and not confirm_cost:
            raise AppError("This test uses one credit of your plan. Confirm to continue.", 409, "confirm_cost")
        ttype, target = conn.meta.canary
        ctx = B.Ctx(self.guard, self.key_getter, self.cfg, f"test-{cid}", threading.Event(), time.time() + 60, C.DATA / "tmp")
        r = conn.run(target, ttype, ctx)
        if r.mode == "keyed" and r.status in (B.OK, B.EMPTY):
            verdict, msg = "connected", "Key accepted. This tool now runs on your paid plan."
        elif r.status == B.PLAN:
            verdict, msg = "connected_limited", "Key accepted, but your plan does not include this lookup."
        elif r.status == B.RATE:
            verdict, msg = "rate_limited", "Rate limit reached. The key may be fine; try again shortly."
        elif r.status == B.BLOCKED:
            verdict, msg = "shield_down", r.error or "The network shield is not verified."
        elif r.status == B.KEY_INVALID or (r.mode == "free" and any("rejected" in n for n in r.notes)):
            verdict, msg = "rejected", "The vendor rejected this key. Check it on the vendor's site."
        else:
            verdict, msg = "error", r.error or "The test did not complete."
        self.audit.append("key_tested", connector=cid, verdict=verdict)
        return {"verdict": verdict, "message": msg, "status": r.status, "mode": r.mode, "elapsed": r.elapsed}

    # ------------------------------------------------------------------ search
    def detect(self, target: str) -> dict:
        self._need()
        try:
            return {"ttype": detect_type(target)}
        except InputError as exc:
            raise AppError(str(exc)) from None

    def plan(self, ttype: str) -> dict:
        o = self._need()
        if ttype not in TYPES:
            raise AppError("Unknown target type.")
        rows, counts = [], {"will_run": 0, "needs_key": 0, "off": 0, "not_automated": 0}
        for e, c in K.for_type(ttype, B.REGISTRY):
            if c is None:
                counts["not_automated"] += 1
                rows.append(_plan_row(e, None, e.status, e.status, True))
                continue
            m = c.meta
            keyed = bool(self.key_getter(c.id)) and c.has_keyed
            free_ok = c.has_free and (not m.free_targets or ttype in m.free_targets)
            mode = "handoff" if m.kind == "handoff" else "export" if m.kind == "export" else "paid" if keyed else "free" if free_ok else "needs_key"
            if not self.cfg.connector(c.id).get("enabled", True):
                state = "off"
            elif mode in ("handoff", "export"):
                state = mode
            elif mode == "needs_key":
                state = "needs_key"
            else:
                state = "will_run"
            counts[state if state in ("will_run", "needs_key", "off") else "not_automated"] += 1
            rows.append(_plan_row(e, c, state, mode, (self._tool_path(c) is not None) if m.kind == "cli" else True))
        return {"ttype": ttype, "tools": rows, "counts": counts}

    def types(self) -> dict:
        self._need()
        out = []
        for t in TYPES:
            pairs = K.for_type(t, B.REGISTRY)
            ready = 0
            for _e, c in pairs:
                if c is None or not self.cfg.connector(c.id).get("enabled", True):
                    continue
                keyed = bool(self.key_getter(c.id)) and c.has_keyed
                free_ok = c.has_free and (not c.meta.free_targets or t in c.meta.free_targets)
                if c.meta.kind == "cli" and self._tool_path(c) is None:
                    continue
                if c.meta.kind == "api" and not (keyed or free_ok):
                    continue
                if c.meta.kind in ("api", "cli", "local"):
                    ready += 1
            out.append({"id": t, "label": K.TYPE_INFO[t][0], "example": K.TYPE_INFO[t][1], "catalogue": len(pairs), "will_run": ready})
        return {"types": out}

    def search(self, target: str, ttype: Optional[str], tools: Optional[list], save: bool, face_consent: bool, purpose: str) -> dict:
        o = self._need()
        if int(self.cfg.get("ack", "version", default=0)) < ACK_VERSION:
            raise AppError("Please accept the lawful-use notice first.", 409, "ack_required")
        try:
            t = ttype or detect_type(target)
            normalize(t, target)
            plan = o.connectors_for(t, tools)
            if tools and set(tools) - {c.id for c in plan}:
                raise AppError("A selected tool is disabled or does not support this kind of target.")
            if any(c.meta.kind in ("api", "cli") for c in plan):
                st = self.guard.verify()
                if not st.ok:
                    raise AppError("The network shield is not verified, so no search was sent. " + " ".join(st.reasons), 409, "shield_down", reasons=st.reasons)
            job = o.start(target, t, selected=tools, save=save, face_consent=face_consent, purpose=purpose)
        except InputError as exc:
            raise AppError(str(exc)) from None
        self.touch()
        return job.public(with_case=False)

    def job(self, jid: str, have: Optional[list] = None) -> dict:
        o = self._need()
        j = o.get(jid)
        if not j:
            raise AppError("That search is no longer in memory. Open it from Cases.", 404, "not_found")
        return j.public(skip=frozenset(have or []))

    def jobs(self) -> dict:
        o = self._need()
        rows = [{"id": j.id, "target": j.target if j.ttype != "password" else "(password)", "ttype": j.ttype, "status": j.status, "created": j.created,
                 "done": sum(1 for s in j.state.values() if s == "done"), "total": len(j.plan)} for j in sorted(o.jobs.values(), key=lambda x: -x.created)]
        return {"jobs": rows[:30]}

    def cancel(self, jid: str) -> dict:
        o = self._need()
        return {"cancelled": o.cancel(jid)}

    def reveal(self, jid: str, fid: str, password: str) -> dict:
        o = self._need()
        self._reauth(password)
        try:
            return o.reveal(jid, fid)
        except InputError as exc:
            raise AppError(str(exc), 404, "not_found") from None

    # ------------------------------------------------------------------ cases
    def cases(self) -> dict:
        self._need()
        return {"cases": self.store.list()}

    def case(self, cid: str) -> dict:
        self._need()
        if not CASE_ID.match(cid):
            raise AppError("Invalid case id.", 404, "not_found")
        try:
            return X.strip_secrets(self.store.load(cid))
        except StoreError as exc:
            raise AppError(str(exc), 404, "not_found") from None

    def case_update(self, cid: str, title: Optional[str], notes: Optional[str]) -> dict:
        self._need()
        if not CASE_ID.match(cid):
            raise AppError("Invalid case id.", 404, "not_found")
        try:
            c = self.store.update_meta(cid, title=title, notes=notes)
        except StoreError as exc:
            raise AppError(str(exc), 404, "not_found") from None
        self.audit.append("case_updated", case=cid)
        return {"id": cid, "title": c.get("title", "")}

    def case_delete(self, cid: str) -> dict:
        self._need()
        if not CASE_ID.match(cid):
            raise AppError("Invalid case id.", 404, "not_found")
        try:
            self.store.delete(cid)
        except StoreError as exc:
            raise AppError(str(exc), 404, "not_found") from None
        self.audit.append("case_deleted", case=cid)
        return {"deleted": True}

    def case_export(self, cid: str, fmt: str) -> tuple[bytes, str, str]:
        case = self.case(cid)
        if fmt not in EXPORTS:
            raise AppError("Unknown export format.")
        mime, ext = EXPORTS[fmt]
        if fmt == "json":
            data = X.export_json(case)
        elif fmt == "csv":
            data = X.export_csv(case)
        elif fmt == "md":
            data = X.export_markdown(case)
        else:
            ent, lnk = X.export_maltego(case)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("mot_entities.csv", ent)
                z.writestr("mot_links.csv", lnk)
                z.writestr("README.txt", "In Maltego: Import | Import Graph from Table. Map entity_type and value for mot_entities.csv; source_value and target_value for mot_links.csv.\n")
            data = buf.getvalue()
        self.audit.append("case_exported", case=cid, fmt=fmt)
        return data, mime, f"mot-case-{cid}.{ext}"

    # ------------------------------------------------------------------ recovery
    def recovery(self) -> dict:
        self._need()
        pend = []
        for snap in self.journal.pending():
            plan = [c for c in snap.get("plan", []) if c in B.REGISTRY]
            done = [c for c in plan if snap.get("state", {}).get(c) == "done"]
            pend.append({"id": str(snap.get("id", ""))[:24], "target": snap.get("target", ""), "ttype": snap.get("ttype", ""), "created": snap.get("created", 0),
                         "done": done, "todo": [c for c in plan if c not in done]})
        return {"crash": bool(self.crash.get("crashed")), "pending": pend}

    def recover(self, jid: str, action: str) -> dict:
        o = self._need()
        snap = next((s for s in self.journal.pending() if str(s.get("id", ""))[:24] == jid), None)
        if not snap:
            raise AppError("No such recoverable search.", 404, "not_found")
        try:
            if action == "resume":
                todo = [c for c in snap["plan"] if c in B.REGISTRY and snap.get("state", {}).get(c) != "done"]
                if any(B.REGISTRY[c].meta.kind in ("api", "cli") for c in todo):
                    st = self.guard.verify()
                    if not st.ok:
                        raise AppError("The network shield is not verified. " + " ".join(st.reasons), 409, "shield_down", reasons=st.reasons)
                job = o.resume(snap)
                self.journal.clear(jid)
                return {"job": job.public(with_case=False)}
            if action == "case":
                case = o.recover_case(snap)
                self.journal.clear(jid)
                return {"case": case["id"]}
            if action == "discard":
                self.journal.clear(jid)
                self.audit.append("recovery_discarded", job=jid)
                return {"discarded": True}
        except InputError as exc:
            raise AppError(str(exc)) from None
        raise AppError("Unknown recovery action.")

    # ------------------------------------------------------------------ shield
    def shield(self) -> dict:
        self._need()
        st = self.guard.state.public()
        found = []
        try:
            found = [f"{h}:{p}" for h, p in self.tor.detect()]
        except Exception:
            pass
        return {"state": st, "mode": self.guard.mode, "baseline_set": bool(self._baseline_get()),
                "config": {k: self.cfg.get("shield", k) for k in ("mode", "tor_socks", "custom_proxy", "vpn_iface_pattern", "allow_direct", "require_baseline", "recheck_seconds")},
                "tor": {"binary": bool(self.tor.binary()), "detected": found, "status": dict(self.tor_status)}, "guidance": GUIDANCE,
                "modes": [{"id": "tor_over_vpn", "name": "Tor over VPN", "text": "Recommended. Your VPN hides Tor from your ISP; Tor hides your identity from services."},
                          {"id": "tor", "name": "Tor only", "text": "Dark-web lookups and strong anonymity. Some sites block Tor exits."},
                          {"id": "vpn", "name": "VPN only", "text": "Fast, and needed by tools that cannot be forced through Tor."},
                          {"id": "proxy", "name": "Your own proxy", "text": "A proxy you control (no credentials in the URL)."},
                          {"id": "direct", "name": "Direct (unshielded)", "text": "Your real IP is visible to every service. Off unless you explicitly allow it."}]}

    def shield_verify(self) -> dict:
        self._need()
        self.guard.verify(force=True)
        self.audit.append("shield_verified", ok=self.guard.state.ok, mode=self.guard.mode)
        return self.shield()

    def shield_config(self, mode: Optional[str], tor_socks: Optional[str], custom_proxy: Optional[str], vpn_iface_pattern: Optional[str], allow_direct: Optional[bool]) -> dict:
        self._need()
        if mode is not None:
            if mode not in C.SHIELD_MODES:
                raise AppError("Unknown shield mode.")
            if mode == "direct" and not (allow_direct if allow_direct is not None else self.cfg.get("shield", "allow_direct", default=False)):
                raise AppError("Direct mode exposes your real IP. Tick 'I understand' to allow it.", 409, "confirm_direct")
        if tor_socks is not None and not re.fullmatch(r"[A-Za-z0-9_.\-]{1,100}:\d{2,5}", tor_socks):
            raise AppError("Tor address must look like 127.0.0.1:9050.")
        if custom_proxy:
            from urllib.parse import urlparse

            u = urlparse(custom_proxy)
            if u.scheme not in ("socks5", "socks5h", "http", "https") or not u.hostname or not u.port or u.username or u.password:
                raise AppError("Proxy must be socks5/http(s)://host:port with no username or password in the URL.")
        if vpn_iface_pattern:
            if len(vpn_iface_pattern) > 80:
                raise AppError("Pattern is too long.")
            try:
                re.compile(vpn_iface_pattern)
            except re.error:
                raise AppError("That is not a valid pattern.") from None
        for key, val in (("allow_direct", allow_direct), ("mode", mode), ("tor_socks", tor_socks), ("custom_proxy", custom_proxy), ("vpn_iface_pattern", vpn_iface_pattern)):
            if val is not None:
                self.cfg.set("shield", key, val)
        self.guard.state.checked_at = 0.0
        self.audit.append("shield_configured", mode=self.guard.mode)
        return self.shield()

    def shield_baseline(self, ip: Optional[str], force: bool) -> dict:
        self._need()
        try:
            masked = self.guard.record_baseline(force=force, ip=ip or None)
        except NetworkUnsafe as exc:
            raise AppError(str(exc), 409, "vpn_active") from None
        except ValueError:
            raise AppError("That is not a valid IP address.") from None
        except Exception as exc:
            raise AppError(f"Could not determine your real IP ({type(exc).__name__}). Type it in manually.", 502, "upstream") from None
        self.audit.append("baseline_recorded", typed=bool(ip))
        return {"recorded": True, "masked": masked}

    def tor_start(self) -> dict:
        self._need()
        if self.tor_status.get("state") == "starting":
            return {"state": "starting"}
        self.tor_status = {"state": "starting", "msg": "Starting Tor ..."}

        def work() -> None:
            try:
                r = self.tor.start()
                self.tor_status = {"state": "ok" if r["ok"] else "failed", "msg": r["msg"]}
            except Exception as exc:  # never let a Tor failure take the app down
                log.exception("tor start failed")
                self.tor_status = {"state": "failed", "msg": f"Tor could not be started ({type(exc).__name__})."}

        threading.Thread(target=work, name="mot-tor-start", daemon=True).start()
        return {"state": "starting"}

    # ------------------------------------------------------------------ tools
    def tools(self) -> dict:
        self._need()
        rows = []
        for cid, rec in T.RECIPES.items():
            conn = B.REGISTRY.get(cid)
            offline = (C.WHEELS / cid).is_dir() and any((C.WHEELS / cid).iterdir())
            rows.append({"id": cid, "name": conn.meta.name if conn else cid, "installed": T.installed(cid, self.cfg), "offline_bundle": offline,
                         "needs_python": ".".join(map(str, rec["needs"])) if "needs" in rec else "", "state": dict(self.installing.get(cid, {}))})
        pi = B.REGISTRY.get("phoneinfoga")
        if pi:
            rows.append({"id": "phoneinfoga", "name": pi.meta.name, "installed": self._tool_path(pi), "offline_bundle": False, "needs_python": "", "state": {},
                         "manual": "Download the release for your OS into the bin folder (optional; offline analysis always works)."})
        tor = {"binary": self.tor.binary(), "detected": [f"{h}:{p}" for h, p in self.tor.detect()]}
        return {"tools": rows, "tor": tor}

    def tool_install(self, cid: str) -> dict:
        self._need()
        if cid not in T.RECIPES:
            raise AppError("Unknown tool.", 404, "not_found")
        if self.installing.get(cid, {}).get("state") == "running":
            return {"state": "running"}
        offline = (C.WHEELS / cid).is_dir() and any((C.WHEELS / cid).iterdir())
        proxy = None
        if not offline:
            try:
                proxy = T.install_proxy(self.guard)
            except NetworkUnsafe as exc:
                raise AppError("Not downloading: " + str(exc), 409, "shield_down") from None
        state = {"state": "running", "msg": "Installing ...", "log": []}
        self.installing[cid] = state
        audit = self.audit

        def work() -> None:
            def say(line: str) -> None:
                state["log"] = (state["log"] + [Redactor.redact(str(line))[:200]])[-12:]

            try:
                r = T.install_tool(cid, self.cfg, offline=offline, proxy=proxy, log=say)
                state.update(state="done" if r["ok"] else "failed", msg=Redactor.redact(r["msg"])[:520])
            except Exception as exc:
                log.exception("tool install failed")
                state.update(state="failed", msg=f"Install failed ({type(exc).__name__}).")
            if audit:
                audit.append("tool_install", tool=cid, ok=state["state"] == "done", offline=offline)

        threading.Thread(target=work, name=f"mot-install-{cid}", daemon=True).start()
        return {"state": "running"}

    # ------------------------------------------------------------------ health
    def health(self) -> dict:
        self._need()
        checks = self.doctor.run()
        worst = "fail" if any(c["status"] == "fail" for c in checks) else "warn" if any(c["status"] == "warn" for c in checks) else "ok"
        return {"checks": checks, "overall": worst, "hardware": self.hw, "tuning": self.tune}

    def health_fix(self, cid: str) -> dict:
        self._need()
        r = self.doctor.fix(cid)
        self.audit.append("doctor_fix", item=cid, ok=bool(r.get("ok")))
        return r

    def audit_view(self, limit: int) -> dict:
        self._need()
        return {"rows": self.audit.tail(limit), "verify": self.audit.verify()}

    # ------------------------------------------------------------------ settings
    def settings(self) -> dict:
        self._need()
        c = self.cfg
        return {"idle_lock_minutes": c.get("server", "idle_lock_minutes"), "max_workers": c.get("search", "max_workers"), "connector_timeout": c.get("search", "connector_timeout"),
                "job_timeout": c.get("search", "job_timeout"), "theharvester_sources": c.get("theharvester", "sources"), "persist_secrets": c.get("privacy", "persist_secrets"),
                "mask_sensitive": c.get("privacy", "mask_sensitive"), "toolenv_python": c.get("toolenv", "python"), "theme": c.get("ui", "theme"),
                "secure_window": c.get("server", "secure_window"), "recommended": {"max_workers": self.tune["max_workers"], "cli_parallel": self.tune["cli_parallel"]},
                "env_keys": f"{ENV_PREFIX}<TOOL>_<FIELD>"}

    def settings_set(self, patch: dict) -> dict:
        self._need()
        c = self.cfg

        def intr(name: str, lo: int, hi: int) -> int:
            v = patch[name]
            if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                raise AppError(f"{name} must be a whole number from {lo} to {hi}.")
            return v

        for name, lo, hi, path in (("idle_lock_minutes", 1, 240, ("server", "idle_lock_minutes")), ("max_workers", 0, 32, ("search", "max_workers")),
                                   ("connector_timeout", 10, 900, ("search", "connector_timeout")), ("job_timeout", 30, 3600, ("search", "job_timeout"))):
            if name in patch:
                c.set(*path, intr(name, lo, hi))
        if "theharvester_sources" in patch:
            if not re.fullmatch(r"[a-zA-Z0-9,_-]{1,300}", str(patch["theharvester_sources"])):
                raise AppError("Sources: letters, digits, commas, dash and underscore only.")
            c.set("theharvester", "sources", str(patch["theharvester_sources"]))
        for name, path in (("persist_secrets", ("privacy", "persist_secrets")), ("mask_sensitive", ("privacy", "mask_sensitive")), ("secure_window", ("server", "secure_window"))):
            if name in patch:
                if not isinstance(patch[name], bool):
                    raise AppError(f"{name} must be true or false.")
                c.set(*path, patch[name])
        if "toolenv_python" in patch:
            p = str(patch["toolenv_python"]).strip()
            if p and not Path(p).is_file():
                raise AppError("That Python executable does not exist.")
            c.set("toolenv", "python", p)
        if "theme" in patch:
            if patch["theme"] not in ("dark", "light"):
                raise AppError("Theme must be dark or light.")
            c.set("ui", "theme", patch["theme"])
        if self.orch:
            self.orch.workers = c.get("search", "max_workers", default=0) or self.tune["max_workers"]
        self.audit.append("settings_changed", keys=sorted(patch))
        return self.settings()

    def accept_ack(self) -> dict:
        self._need()
        self.cfg.set("ack", "version", ACK_VERSION)
        self.audit.append("lawful_use_acknowledged", version=ACK_VERSION)
        return {"ack_ok": True}

    # ------------------------------------------------------------------ links that leave the shield
    def external_url(self, kind: str, ident: str, which: str) -> str:
        """Vendor sign-up / key / docs pages and the safety-guide links. The page never supplies a URL, only a name,
        so this cannot become an open redirect or a way to launch arbitrary schemes."""
        url = ""
        if kind == "vendor":
            m = self._conn(ident).meta
            url = {"site": m.site, "key": m.key_url, "docs": m.docs_url}.get(which, "")
        elif kind == "guide":
            g = next((x for x in GUIDANCE if x["id"] == ident), None)
            if g and which.isdigit() and int(which) < len(g["links"]):
                url = g["links"][int(which)]["url"]
        u = urlsplit(url) if url else None
        if not u or u.scheme != "https" or not u.hostname or u.username or u.password or len(url) > 300 or re.search(r"[\s\x00-\x1f\x7f]", url):
            raise AppError("There is no link for that.", 404, "not_found")
        return url

    def external_link(self, kind: str, ident: str, which: str) -> dict:
        """Returns the URL as text so it can be copied into Tor Browser or any browser you trust. Opens nothing."""
        self._need()
        url = self.external_url(kind, ident, which)
        return {"url": url, "host": urlsplit(url).hostname}

    def open_external(self, kind: str, ident: str, which: str, confirm: bool) -> dict:
        """Opens the vendor page in the operating system's DEFAULT browser. That browser is not behind MOT's shield, so the
        vendor sees whatever network your computer is on. The server insists on an explicit confirmation, not just the UI."""
        self._need()
        url = self.external_url(kind, ident, which)
        if not confirm:
            raise AppError("This opens your normal browser, outside MOT's network shield. Confirm to continue.", 409, "confirm_outside_shield")
        host = urlsplit(url).hostname
        try:
            opened = bool(webbrowser.open(url, new=2))
        except Exception:  # no browser, headless box, sandbox: the caller falls back to showing the link
            opened = False
        self.audit.append("external_opened", host=host, kind=kind, ref=ident, opened=opened, shield_ok=bool(self.guard.state.ok))
        return {"opened": opened, "url": url, "host": host, "shield_ok": bool(self.guard.state.ok)}

    # ------------------------------------------------------------------ dashboard
    def overview(self) -> dict:
        self._need()
        conns = self.connections()["summary"]
        pend = len(self.journal.pending())
        return {"shield": self.guard.state.public(), "shield_mode": self.guard.mode, "cases": len(list(C.DATA.joinpath("cases").glob("*.motc"))), "connections": conns,
                "pending_recovery": pend, "crash": bool(self.crash.get("crashed")), "hardware": self.hw, "tuning": self.tune, "audit": self.audit.verify(), "running_jobs": self.running_jobs(),
                "restored_from_backup": self.vault.restored_from_backup}
