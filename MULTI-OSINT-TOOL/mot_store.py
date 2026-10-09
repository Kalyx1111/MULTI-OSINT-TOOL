"""MULTI-OSINT-TOOL :: encrypted case store (AES-256-GCM, per-file random nonce, id bound as AAD).

Raw credentials are NOT persisted unless privacy.persist_secrets is enabled: the data you
investigate is itself sensitive, so by default it is kept masked on disk.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import mot_config as C
from mot_correlate import strip_secrets  # noqa: F401  (re-exported: one implementation for stores and exports)

MAGIC = b"MOTC1"
ID_RE = re.compile(r"^[0-9a-f]{16}$")


class StoreError(Exception):
    pass


class CaseStore:
    def __init__(self, directory: Path | str, key: bytes):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._key = key

    def _path(self, cid: str) -> Path:
        if not ID_RE.match(cid):
            raise StoreError("Invalid case id.")
        return self.dir / f"{cid}.motc"

    def new_id(self) -> str:
        return secrets.token_hex(8)

    def save(self, case: dict) -> str:
        cid = case.get("id") or self.new_id()
        case["id"] = cid
        data = json.dumps(case, default=str, separators=(",", ":")).encode("utf-8")
        nonce = os.urandom(12)
        aad = MAGIC + cid.encode()
        C.atomic_write(self._path(cid), MAGIC + nonce + AESGCM(self._key).encrypt(nonce, data, aad))
        return cid

    def load(self, cid: str) -> dict:
        p = self._path(cid)
        try:
            raw = p.read_bytes()
        except OSError as exc:
            raise StoreError("Case not found.") from exc
        if not raw.startswith(MAGIC) or len(raw) < len(MAGIC) + 12 + 16:
            raise StoreError("Case file is corrupt.")
        nonce, ct = raw[5:17], raw[17:]
        try:
            return json.loads(AESGCM(self._key).decrypt(nonce, ct, MAGIC + cid.encode()))
        except (InvalidTag, ValueError) as exc:
            raise StoreError("Case could not be decrypted (wrong key or tampered file).") from exc

    def update_meta(self, cid: str, title: Optional[str] = None, notes: Optional[str] = None) -> dict:
        """Analyst-editable fields only; everything else in the case stays exactly as produced."""
        c = self.load(cid)
        if title is not None:
            c["title"] = re.sub(r"[\x00-\x1f\x7f]", " ", str(title)).strip()[:120] or c.get("title", "")
        if notes is not None:
            c["notes_user"] = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(notes))[:20000]
        self.save(c)
        return c

    def list(self, limit: int = 300) -> list[dict]:
        out = []
        for p in sorted(self.dir.glob("*.motc"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
            try:
                c = self.load(p.stem)
                out.append({"id": c["id"], "title": c.get("title", ""), "target": c.get("target", ""), "ttype": c.get("ttype", ""), "created": c.get("created", 0),
                            "score": (c.get("score") or {}).get("score", 0), "level": (c.get("score") or {}).get("level", ""), "tools_ok": c.get("tools_ok", 0)})
            except StoreError:
                out.append({"id": p.stem, "title": "(unreadable case)", "target": "", "ttype": "", "created": p.stat().st_mtime, "score": 0, "level": "", "tools_ok": 0, "damaged": True})
        return out

    def delete(self, cid: str) -> None:
        """Best-effort secure delete: overwrite with random bytes, fsync, unlink (SSDs may keep remnants)."""
        p = self._path(cid)
        if not p.exists():
            raise StoreError("Case not found.")
        try:
            size = p.stat().st_size
            with open(p, "r+b") as fh:
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            pass
        p.unlink()
