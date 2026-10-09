"""MULTI-OSINT-TOOL :: tamper-evident audit log (HMAC-SHA256 hash chain).

Every record's MAC covers its content AND the previous record's MAC, so edits, deletions and
re-ordering are detectable. Targets are never stored in clear: only a keyed hash (so you can
prove what you searched, without the log itself becoming a leak).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path

from mot_vault import Redactor

GENESIS = "0" * 64


def _canon(rec: dict) -> bytes:
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _scrub(v, depth: int = 0):
    if depth > 4:
        return "…"
    if isinstance(v, str):
        return Redactor.redact(v)[:240]
    if isinstance(v, dict):
        return {str(k)[:40]: _scrub(x, depth + 1) for k, x in list(v.items())[:40]}
    if isinstance(v, (list, tuple)):
        return [_scrub(x, depth + 1) for x in list(v)[:40]]
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    return str(v)[:80]


class AuditLog:
    def __init__(self, path: Path | str, key: bytes):
        self.path = Path(path)
        self._key = key
        self._lock = threading.Lock()
        self.seq = 0
        self.prev = GENESIS
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._load_tail()

    def _mac(self, body: bytes) -> str:
        return hmac.new(self._key, body, hashlib.sha256).hexdigest()

    def hash_target(self, target: str) -> str:
        return hmac.new(self._key, b"target|" + target.strip().lower().encode(), hashlib.sha256).hexdigest()[:20]

    def _load_tail(self) -> None:
        if not self.path.exists():
            return
        good_end = 0
        with open(self.path, "rb") as fh:
            pos = 0
            for raw in fh:
                try:
                    rec = json.loads(raw)
                    self.seq, self.prev = int(rec["seq"]), str(rec["mac"])
                    good_end = pos + len(raw)
                except (ValueError, KeyError):
                    break
                pos += len(raw)
        if good_end < self.path.stat().st_size:  # trailing partial line from a crash -> drop it
            with open(self.path, "r+b") as fh:
                fh.truncate(good_end)

    def append(self, event: str, **details) -> None:
        with self._lock:
            self.seq += 1
            rec = {"seq": self.seq, "ts": round(time.time(), 3), "event": str(event)[:60], "d": _scrub(details), "prev": self.prev}
            mac = self._mac(_canon(rec))
            line = json.dumps({**rec, "mac": mac}, sort_keys=True, separators=(",", ":")) + "\n"
            with open(self.path, "ab") as fh:
                fh.write(line.encode())
                fh.flush()
                os.fsync(fh.fileno())
            self.prev = mac

    def verify(self) -> dict:
        """Returns {ok, records, first_bad_seq}."""
        prev, n = GENESIS, 0
        if not self.path.exists():
            return {"ok": True, "records": 0, "first_bad_seq": None}
        with open(self.path, "rb") as fh:
            for raw in fh:
                try:
                    obj = json.loads(raw)
                    mac = obj.pop("mac")
                    if obj.get("prev") != prev or not hmac.compare_digest(mac, self._mac(_canon(obj))):
                        return {"ok": False, "records": n, "first_bad_seq": obj.get("seq")}
                    prev, n = mac, n + 1
                except (ValueError, KeyError, TypeError):
                    return {"ok": False, "records": n, "first_bad_seq": n + 1}
        return {"ok": True, "records": n, "first_bad_seq": None}

    def tail(self, limit: int = 50) -> list[dict]:
        if not self.path.exists():
            return []
        rows = []
        with open(self.path, "rb") as fh:
            for raw in fh:
                try:
                    o = json.loads(raw)
                    rows.append({"seq": o["seq"], "ts": o["ts"], "event": o["event"], "d": o.get("d", {})})
                except (ValueError, KeyError):
                    continue
        return rows[-limit:]
