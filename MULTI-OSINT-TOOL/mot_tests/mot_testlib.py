"""MULTI-OSINT-TOOL :: shared test fixtures.

Import this module FIRST in every test file: it points MOT_DATA at a throw-away folder so tests can
never touch real vaults, cases or logs, and it builds a complete in-memory service stack.
"""
from __future__ import annotations

import atexit
import os
import secrets
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
_TMP = tempfile.mkdtemp(prefix="mot_test_")
os.environ.setdefault("MOT_DATA", str(Path(_TMP) / "data"))
atexit.register(lambda: shutil.rmtree(_TMP, ignore_errors=True))

import mot_config as C  # noqa: E402

C.ensure_dirs()

from mot_audit import AuditLog  # noqa: E402
from mot_netguard import NetGuard  # noqa: E402
from mot_orchestrator import Orchestrator  # noqa: E402
from mot_resilience import Journal  # noqa: E402
from mot_store import CaseStore  # noqa: E402
from mot_vault import Vault  # noqa: E402

FAST_KDF = {"kdf": "argon2id", "t": 2, "m": 19456, "p": 1}
PASSWORD = secrets.token_urlsafe(24)  # generated per run: no password literal in the source


class Stack:
    """Everything the orchestrator needs, isolated per test case."""

    def __init__(self, mode: str = "direct", keys: dict | None = None):
        self.dir = Path(tempfile.mkdtemp(prefix="stack_", dir=_TMP))
        self.cfg = C.Config(self.dir / "mot_config.json").load()
        if mode == "direct":
            self.cfg.set("shield", "allow_direct", True)
        self.cfg.set("shield", "mode", mode)
        self.baseline = {"ip": ""}
        self.guard = NetGuard(self.cfg, lambda: self.baseline["ip"], lambda ip: self.baseline.update(ip=ip))
        self.vault = Vault(self.dir / "vault.motv")
        self.keys = keys or {}
        self.audit = AuditLog(self.dir / "audit.log", os.urandom(32))
        self.store = CaseStore(self.dir / "cases", os.urandom(32))
        self.journal = Journal(self.dir / "journal", os.urandom(32))
        self.orch = Orchestrator(self.cfg, self.guard, lambda cid: self.keys.get(cid), self.audit, self.store, self.journal,
                                 {"max_workers": 6, "cli_parallel": 3})

    def wait(self, job, timeout: float = 20.0):
        import time

        t0 = time.time()
        while job.status == "running" and time.time() - t0 < timeout:
            time.sleep(0.05)
        return job
