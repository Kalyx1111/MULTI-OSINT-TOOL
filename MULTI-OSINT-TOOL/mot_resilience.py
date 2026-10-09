"""MULTI-OSINT-TOOL :: crash tolerance, diagnostics and self-repair.

"Crash proof" is not an honest promise for any software; this module delivers crash TOLERANCE:
  * encrypted job journal  -> after a crash you can Recover partial results or Resume unfinished tools
  * heartbeat file         -> next start knows the previous run did not shut down cleanly
  * process supervisor     -> in mot_main.py: restarts the server with back-off after a crash
  * faulthandler + hooks   -> native crashes and thread exceptions are written (redacted) to logs/
  * Doctor                 -> one-click detection + repair of the problems that actually occur
"""
from __future__ import annotations

import faulthandler
import json
import logging
import logging.handlers
import os
import shutil
import socket
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import mot_config as C
from mot_vault import Redactor, VaultCorrupt, _parse

log = logging.getLogger("mot.resilience")
HB_FILE = C.DATA / "recovery" / "heartbeat.json"
JMAGIC = b"MOTJ1"


# ----------------------------------------------------------------------------- logging
class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = Redactor.redact(record.getMessage())
            record.args = ()
            if record.exc_info:
                record.exc_text = Redactor.redact("".join(traceback.format_exception(*record.exc_info)))
                record.exc_info = None
        except Exception:
            record.msg, record.args = "[log record suppressed]", ()
        return True


def setup_logging(debug: bool = False) -> None:
    C.ensure_dirs()
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    for h in list(root.handlers):
        root.removeHandler(h)
    fh = logging.handlers.RotatingFileHandler(C.DATA / "logs" / "mot.log", maxBytes=2_000_000, backupCount=4, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    fh.addFilter(RedactFilter())
    root.addHandler(fh)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    sh.addFilter(RedactFilter())
    sh.setLevel(logging.WARNING)
    root.addHandler(sh)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def install_crash_handlers() -> None:
    try:
        fault = open(C.DATA / "logs" / "mot_fault.log", "a", buffering=1)
        faulthandler.enable(file=fault, all_threads=True)
    except Exception as err:
        logging.getLogger("mot.crash").warning("native fault log not opened (%s): hard crashes will not be recorded", type(err).__name__)

    def write(kind: str, exc_type, exc, tb) -> None:
        text = Redactor.redact("".join(traceback.format_exception(exc_type, exc, tb)))
        try:
            p = C.DATA / "logs" / f"mot_crash_{int(time.time())}.log"
            C.atomic_write(p, f"{kind}\n{text}".encode("utf-8", "replace"))
        except Exception as err:
            logging.getLogger("mot.crash").warning("crash report file not written (%s)", type(err).__name__)
        logging.getLogger("mot.crash").error("%s: %s", kind, text[-1500:])

    def hook(t, e, tb):
        if issubclass(t, KeyboardInterrupt):
            sys.__excepthook__(t, e, tb)
            return
        write("UNHANDLED", t, e, tb)

    sys.excepthook = hook
    threading.excepthook = lambda a: write(f"THREAD {a.thread.name if a.thread else '?'}", a.exc_type, a.exc_value, a.exc_traceback)


# ----------------------------------------------------------------------------- heartbeat
def _pid_alive(pid: int) -> bool:
    try:
        import psutil

        return psutil.pid_exists(pid)
    except Exception:
        pass
    if os.name == "posix":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    return False


def previous_run_crashed() -> dict:
    """Inspect the heartbeat left by the previous run BEFORE this run overwrites it. Garbage in the file never raises."""
    try:
        hb = json.loads(HB_FILE.read_text(encoding="utf-8"))
        if hb.get("clean"):
            return {"crashed": False}
        pid, ts = int(hb.get("pid", 0)), float(hb.get("ts", 0))
    except (OSError, ValueError, TypeError, AttributeError):
        return {"crashed": False}
    if pid != os.getpid() and (not _pid_alive(pid) or time.time() - ts > 30):
        return {"crashed": True, "when": ts, "pid": pid}
    return {"crashed": False}


class Heartbeat:
    def __init__(self, interval: float = 5.0):
        self.interval, self._stop = interval, threading.Event()
        self._thr: Optional[threading.Thread] = None
        self.started = time.time()
        self._failing = False

    def _write(self, clean: bool) -> None:
        try:
            C.atomic_write(HB_FILE, json.dumps({"pid": os.getpid(), "ts": time.time(), "started": self.started, "clean": clean}).encode())
            if self._failing:
                self._failing = False
                logging.getLogger("mot.heartbeat").warning("heartbeat writes work again")
        except Exception as err:  # reported once per outage, never silent
            if not self._failing:
                self._failing = True
                logging.getLogger("mot.heartbeat").warning("heartbeat not written (%s): crash detection is unreliable until writes succeed", type(err).__name__)

    def start(self) -> None:
        self._write(False)

        def loop() -> None:
            while not self._stop.wait(self.interval):
                self._write(False)

        self._thr = threading.Thread(target=loop, name="mot-heartbeat", daemon=True)
        self._thr.start()

    def stop(self, clean: bool = True) -> None:
        self._stop.set()
        self._write(clean)


# ----------------------------------------------------------------------------- journal
class Journal:
    """Encrypted per-job state snapshots. Plain job data never touches disk unencrypted."""

    def __init__(self, directory: Path | str, key: bytes):
        self.dir, self._key = Path(directory), key
        self.dir.mkdir(parents=True, exist_ok=True)

    def _p(self, jid: str) -> Path:
        return self.dir / f"job-{''.join(c for c in jid if c.isalnum())[:24]}.motj"

    def write(self, jid: str, snap: dict) -> None:
        nonce = os.urandom(12)
        ct = AESGCM(self._key).encrypt(nonce, json.dumps(snap, default=str).encode(), JMAGIC)
        C.atomic_write(self._p(jid), JMAGIC + nonce + ct)

    def clear(self, jid: str) -> None:
        try:
            self._p(jid).unlink()
        except OSError:
            pass

    def pending(self) -> list[dict]:
        out = []
        for p in sorted(self.dir.glob("job-*.motj")):
            try:
                raw = p.read_bytes()
                out.append(json.loads(AESGCM(self._key).decrypt(raw[5:17], raw[17:], JMAGIC)))
            except (InvalidTag, ValueError, OSError):
                try:
                    p.rename(p.with_suffix(".damaged"))
                except OSError:
                    pass
        return out


# ----------------------------------------------------------------------------- doctor
def _chk(cid: str, title: str, status: str, detail: str = "", fixable: bool = False) -> dict:
    return {"id": cid, "title": title, "status": status, "detail": detail, "fixable": fixable}


class Doctor:
    def __init__(self, cfg: C.Config, vault=None, audit=None, guard=None):
        self.cfg, self.vault, self.audit, self.guard = cfg, vault, audit, guard

    def run(self) -> list[dict]:
        out: list[dict] = []
        out.append(_chk("python", "Python version", "ok" if C.python_ok() else "fail", f"{sys.version.split()[0]} (need >= {'.'.join(map(str, C.MIN_PY))})"))
        miss_req = [m for m in ("requests", "socks", "cryptography") if not self._has(m)]
        miss_opt = [m for m in ("argon2", "psutil", "phonenumbers") if not self._has(m)]
        out.append(_chk("deps", "Python dependencies", "fail" if miss_req else ("warn" if miss_opt else "ok"),
                        ("Missing required: " + ", ".join(miss_req) + ". " if miss_req else "") + ("Missing optional: " + ", ".join(miss_opt) if miss_opt else "All present." if not miss_req else ""), bool(miss_req or miss_opt)))
        bad = [d for d in C.SUBDIRS if not (C.DATA / d).is_dir()]
        out.append(_chk("dirs", "Data folders", "fail" if bad else "ok", ("Missing: " + ", ".join(bad)) if bad else str(C.DATA), bool(bad)))
        out.append(_chk("config", "Configuration", "warn" if self.cfg.repairs else "ok", "; ".join(self.cfg.repairs) or "Valid", bool(self.cfg.repairs)))
        out.append(self._vault_check())
        if self.audit:
            v = self.audit.verify()
            out.append(_chk("audit", "Audit log integrity", "ok" if v["ok"] else "fail", f"{v['records']} records" + ("" if v["ok"] else f"; chain broken at #{v['first_bad_seq']} (possible tampering)")))
        free = shutil.disk_usage(C.DATA if C.DATA.exists() else C.ROOT).free / 2**20
        out.append(_chk("disk", "Free disk space", "ok" if free > 200 else "warn", f"{free:,.0f} MiB free"))
        out.append(_chk("tmp", "Temporary files", "ok" if self._tmp_bytes() < 200 * 2**20 else "warn", f"{self._tmp_bytes() / 2**20:.1f} MiB in tmp/", self._tmp_bytes() > 0))
        out.append(_chk("logs", "Log size", "ok" if self._log_bytes() < 30 * 2**20 else "warn", f"{self._log_bytes() / 2**20:.1f} MiB", self._log_bytes() > 30 * 2**20))
        if self.guard:
            st = self.guard.state
            out.append(_chk("shield", "Network shield", "ok" if st.ok else "warn", ("Verified." if st.ok else "; ".join(st.reasons) or "Not verified yet.") + (" " + "; ".join(st.warnings) if st.warnings else "")))
        out += self._tool_checks()
        out += self._connector_selftests()
        return out

    # ---- helpers
    @staticmethod
    def _has(mod: str) -> bool:
        try:
            __import__(mod)
            return True
        except ImportError:
            return False

    def _vault_check(self) -> dict:
        vp = C.VAULT_FILE
        if not vp.exists() and not vp.with_suffix(".bak").exists():
            return _chk("vault", "Key vault", "warn", "No vault yet (created on first run).")
        try:
            hdr = _parse(vp.read_bytes())[0]
            return _chk("vault", "Key vault", "ok", f"AES-256-GCM, KDF {hdr.get('kdf')}" + (", backup present" if vp.with_suffix(".bak").exists() else ", no backup yet"))
        except (OSError, VaultCorrupt) as exc:
            bak = vp.with_suffix(".bak")
            ok_bak = False
            try:
                _parse(bak.read_bytes())
                ok_bak = True
            except (OSError, VaultCorrupt):
                pass
            return _chk("vault", "Key vault", "fail", f"Main vault file unreadable ({exc}). " + ("A valid backup exists and can be restored." if ok_bak else "No valid backup."), ok_bak)

    @staticmethod
    def _tmp_bytes() -> int:
        t = C.DATA / "tmp"
        return sum(f.stat().st_size for f in t.rglob("*") if f.is_file()) if t.exists() else 0

    @staticmethod
    def _log_bytes() -> int:
        t = C.DATA / "logs"
        return sum(f.stat().st_size for f in t.glob("*") if f.is_file()) if t.exists() else 0

    def _tool_checks(self) -> list[dict]:
        import mot_connectors_base as B
        import mot_conn_api, mot_conn_cli, mot_conn_web, mot_conn_intel  # noqa: F401  (registers)

        out, ctx_tool = [], B.Ctx.tool
        dummy = type("D", (), {"cfg": self.cfg})()
        for cid, c in B.REGISTRY.items():
            if c.meta.kind != "cli" and not (c.meta.kind == "local" and c.meta.tool_names):
                continue
            found = ctx_tool(dummy, cid, c.meta.tool_names)
            optional = c.meta.kind == "local"
            out.append(_chk(f"tool_{cid}", f"{c.meta.name} installed", "ok" if found else "warn", found or ("Optional. " if optional else "") + f"Run: python mot_main.py tools --install {cid}"))
        return out

    def _connector_selftests(self) -> list[dict]:
        import mot_connectors_base as B

        problems = []
        for cid, c in B.REGISTRY.items():
            try:
                problems += [f"{cid}: {p}" for p in c.selftest()]
            except Exception as exc:
                problems.append(f"{cid}: selftest crashed ({type(exc).__name__})")
        n = len(B.REGISTRY)
        return [_chk("connectors", f"{n} connectors: offline parser self-check", "ok" if not problems else "fail", "All parsers behave as specified." if not problems else "; ".join(problems))]

    # ---- repairs
    def fix(self, cid: str) -> dict:
        try:
            if cid == "dirs":
                C.ensure_dirs()
                return {"ok": True, "msg": "Data folders recreated."}
            if cid == "config":
                self.cfg.save()
                self.cfg.repairs = []
                return {"ok": True, "msg": "Configuration repaired and saved (invalid values reset to safe defaults)."}
            if cid == "vault":
                vp, bak = C.VAULT_FILE, C.VAULT_FILE.with_suffix(".bak")
                _parse(bak.read_bytes())
                if vp.exists():
                    shutil.copy2(vp, vp.with_suffix(".damaged"))
                C.atomic_write(vp, bak.read_bytes())
                return {"ok": True, "msg": "Vault restored from backup. The damaged file was kept as .damaged."}
            if cid == "tmp":
                n = 0
                cutoff = time.time() - 3600
                for f in sorted((C.DATA / "tmp").rglob("*"), reverse=True):
                    try:
                        if f.is_file() and f.stat().st_mtime < cutoff:
                            f.unlink()
                            n += 1
                        elif f.is_dir() and not any(f.iterdir()):
                            f.rmdir()
                    except OSError:
                        pass
                return {"ok": True, "msg": f"Removed {n} stale temporary file(s)."}
            if cid == "logs":
                n = 0
                for f in (C.DATA / "logs").glob("mot_crash_*.log"):
                    if time.time() - f.stat().st_mtime > 7 * 86400:
                        f.unlink()
                        n += 1
                return {"ok": True, "msg": f"Pruned {n} old crash report(s). Main log rotates automatically."}
            if cid == "deps":
                return self._fix_deps()
        except Exception as exc:
            return {"ok": False, "msg": f"Repair failed: {type(exc).__name__}: {Redactor.redact(str(exc))[:160]}"}
        return {"ok": False, "msg": "No automatic repair for this item."}

    def _fix_deps(self) -> dict:
        import subprocess

        import mot_tools as T

        req = C.ROOT / "mot_requirements.txt"
        if not req.exists():
            return {"ok": False, "msg": "mot_requirements.txt is missing from the project folder."}
        wheels = C.WHEELS / "core"
        cmd = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-r", str(req)]
        if wheels.is_dir() and any(wheels.iterdir()):
            problems = T.verify_manifest(wheels)
            if problems:
                return {"ok": False, "msg": "Offline bundle failed its integrity check: " + "; ".join(problems[:3])}
            cmd[4:4] = ["--no-index", "--find-links", str(wheels)]
            where = "the offline wheel bundle (integrity verified)"
        else:
            if self.guard is None:
                return {"ok": False, "msg": "Refusing to download packages without the network shield. Use the offline bundle or start via mot_main.py."}
            try:
                proxy = T.install_proxy(self.guard)
            except Exception as exc:  # NetworkUnsafe: fail closed, never fetch from the real IP
                return {"ok": False, "msg": f"Not downloading: {Redactor.redact(str(exc))[:200]}"}
            if proxy and proxy.startswith("socks") and not self._has("socks"):
                return {"ok": False, "msg": "PySocks is missing, so packages cannot be fetched through Tor. Use the offline bundle."}
            if proxy:  # None is legitimate in VPN mode: the OS route is the verified VPN
                cmd[4:4] = ["--proxy", proxy]
            where = "PyPI through your shield"
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, shell=False)
        return {"ok": r.returncode == 0, "msg": f"Installed from {where}." if r.returncode == 0 else Redactor.redact((r.stderr or r.stdout)[-300:])}


def port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False
