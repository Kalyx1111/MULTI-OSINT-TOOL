"""MULTI-OSINT-TOOL :: encrypted key vault.

Crypto design
  * Master key  : Argon2id (scrypt fallback), 16-byte random salt, parameters stored in header
                  and range-checked before use (a tampered header cannot cause a memory bomb).
  * Encryption  : AES-256-GCM, fresh 96-bit random nonce on EVERY save, header bound as AAD.
  * Subkeys     : HKDF-SHA256(master, purpose) -> independent keys for cases / audit / journal.
  * Hygiene     : plaintext padded to 4 KiB blocks (hides key count), atomic writes + .bak,
                  unlock throttling, best-effort key zeroisation on lock, secret redaction in logs.
Python cannot guarantee memory wiping; see mot_SECURITY.md for the residual-risk statement.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import threading
import time
import unicodedata
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import mot_config as C

MAGIC = b"MOTV1"
PAD_BLOCK = 4096
SERVICE_RE = re.compile(r"^(__)?[a-z0-9_]{2,32}$")
FIELD_RE = re.compile(r"^[a-z0-9_]{1,32}$")


class VaultError(Exception):
    pass


class VaultAuthError(VaultError):
    pass


class VaultCorrupt(VaultError):
    pass


class VaultLocked(VaultError):
    pass


class VaultThrottled(VaultError):
    def __init__(self, wait: int):
        super().__init__(f"Too many attempts. Retry in {wait}s.")
        self.wait = wait


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


# --------------------------------------------------------------------------- redaction
class Redactor:
    """Scrubs registered secrets and key=value patterns from any text before it is logged/returned."""

    _lock = threading.Lock()
    _secrets: set = set()
    _pat = re.compile(
        r"(?i)((?:api[_-]?key|x-api-key|x-apikey|x-key|dehashed-api-key|hibp-api-key|authorization|bearer|token|"
        r"password|passwd|secret|key)\s*[=:]\s*)([^\s&\"',;]+)"
    )

    @classmethod
    def register(cls, *values: str) -> None:
        with cls._lock:
            for v in values:
                if isinstance(v, str) and len(v) >= 6:
                    cls._secrets.add(v)

    @classmethod
    def clear(cls) -> None:
        with cls._lock:
            cls._secrets.clear()

    @classmethod
    def redact(cls, text) -> str:
        if not isinstance(text, str):
            text = str(text)
        with cls._lock:
            secs = sorted(cls._secrets, key=len, reverse=True)
        for s in secs:
            text = text.replace(s, "[REDACTED]")
        return cls._pat.sub(lambda m: m.group(1) + "[REDACTED]", text)


# --------------------------------------------------------------------------- KDF
KDF_LIMITS = {
    "argon2id": {"t": (1, 12), "m": (8192, 524288), "p": (1, 16)},
    "scrypt": {"n": (2**14, 2**20), "r": (8, 16), "p": (1, 4)},
}


def default_kdf(ram_gb: float = 4.0, cores: int = 2) -> dict:
    """Hardware-aware KDF cost. Always >= OWASP minimum (Argon2id 19 MiB/2 iter)."""
    try:
        import argon2  # noqa: F401

        m = 65536 if ram_gb < 6 else 131072 if ram_gb < 16 else 262144
        return {"kdf": "argon2id", "t": 3, "m": m, "p": max(1, min(4, int(cores)))}
    except ImportError:
        return {"kdf": "scrypt", "n": 2**17, "r": 8, "p": 1}


def _check_params(p: dict) -> None:
    kdf = p.get("kdf")
    lim = KDF_LIMITS.get(kdf)
    if not lim:
        raise VaultCorrupt("Unknown KDF.")
    for k, (lo, hi) in lim.items():
        v = p.get(k)
        if not isinstance(v, int) or isinstance(v, bool) or not (lo <= v <= hi):
            raise VaultCorrupt(f"KDF parameter {k} out of range.")
    if kdf == "scrypt" and (p["n"] & (p["n"] - 1)):
        raise VaultCorrupt("scrypt N must be a power of two.")


def _derive(password: str, salt: bytes, p: dict, keyfile: Optional[bytes]) -> bytes:
    pw = unicodedata.normalize("NFKC", password).encode("utf-8")
    if keyfile:
        pw += b"\x00" + hashlib.sha256(keyfile).digest()
    if p["kdf"] == "argon2id":
        from argon2.low_level import Type, hash_secret_raw

        return hash_secret_raw(pw, salt, time_cost=p["t"], memory_cost=p["m"], parallelism=p["p"], hash_len=32, type=Type.ID)
    maxmem = 2 * 128 * p["n"] * p["r"] + (1 << 20)
    return hashlib.scrypt(pw, salt=salt, n=p["n"], r=p["r"], p=p["p"], maxmem=maxmem, dklen=32)


def check_password_strength(pw: str) -> None:
    if len(pw) < 12:
        raise VaultError("Master password must be at least 12 characters.")
    classes = sum(bool(re.search(r, pw)) for r in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]"))
    if len(pw) < 20 and classes < 3:
        raise VaultError("Use at least 3 character types, or a passphrase of 20+ characters.")
    if len(set(pw)) < 6:
        raise VaultError("Password is too repetitive.")


# --------------------------------------------------------------------------- file format
def _pack(key: bytes, header: dict, payload: dict) -> bytes:
    hb = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    body = json.dumps(payload, separators=(",", ":")).encode()
    padded = struct.pack(">I", len(body)) + body
    padded += os.urandom((-len(padded)) % PAD_BLOCK)
    nonce = os.urandom(12)
    aad = MAGIC + struct.pack(">I", len(hb)) + hb
    return aad + nonce + AESGCM(key).encrypt(nonce, padded, aad)


def _parse(blob: bytes):
    if len(blob) < len(MAGIC) + 4 + 12 + 16 or not blob.startswith(MAGIC):
        raise VaultCorrupt("Not a MOT vault file.")
    (hl,) = struct.unpack(">I", blob[5:9])
    if hl > 4096 or 9 + hl + 12 + 16 > len(blob):
        raise VaultCorrupt("Bad header length.")
    try:
        header = json.loads(blob[9 : 9 + hl])
    except ValueError as exc:
        raise VaultCorrupt("Unreadable header.") from exc
    if not isinstance(header, dict) or header.get("v") != 1:
        raise VaultCorrupt("Unsupported vault version.")
    return header, blob[: 9 + hl], blob[9 + hl : 9 + hl + 12], blob[9 + hl + 12 :]


def _unpad(plain: bytes) -> dict:
    (n,) = struct.unpack(">I", plain[:4])
    if n > len(plain) - 4:
        raise VaultCorrupt("Bad payload length.")
    return json.loads(plain[4 : 4 + n])


class Vault:
    def __init__(self, path: Path | str = C.VAULT_FILE):
        self.path = Path(path)
        self.bak = self.path.with_suffix(".bak")
        self._key: Optional[bytearray] = None
        self._data: dict = {}
        self._hdr: dict = {}
        self._lock = threading.RLock()
        self._fails = 0
        self._locked_until = 0.0
        self.restored_from_backup = False

    # ---- state
    @property
    def unlocked(self) -> bool:
        return self._key is not None

    def exists(self) -> bool:
        return self.path.exists() or self.bak.exists()

    def needs_keyfile(self) -> bool:
        for p in (self.path, self.bak):
            try:
                return bool(_parse(p.read_bytes())[0].get("kf"))
            except (OSError, VaultCorrupt):
                continue
        return False

    # ---- lifecycle
    def create(self, password: str, keyfile: Optional[bytes] = None, kdf: Optional[dict] = None) -> None:
        with self._lock:
            if self.exists():
                raise VaultError("A vault already exists.")
            check_password_strength(password)
            params = dict(kdf or default_kdf())
            _check_params(params)
            salt = os.urandom(16)
            hdr = {"v": 1, "salt": b64(salt), "kf": bool(keyfile), **params}
            self._key = bytearray(_derive(password, salt, params, keyfile))
            self._hdr = hdr
            self._data = {"services": {}, "meta": {"created": time.time()}}
            self._save()

    def unlock(self, password: str, keyfile: Optional[bytes] = None) -> None:
        with self._lock:
            now = time.time()
            if now < self._locked_until:
                raise VaultThrottled(int(self._locked_until - now) + 1)
            cands = [p for p in (self.path, self.bak) if p.exists()]
            if not cands:
                raise VaultError("No vault found. Create one first.")
            for cand in cands:
                try:
                    header, aad, nonce, ct = _parse(cand.read_bytes())
                    _check_params(header)
                    key = _derive(password, b64d(header["salt"]), header, keyfile if header.get("kf") else None)
                    plain = AESGCM(key).decrypt(nonce, ct, aad)
                    data = _unpad(plain)
                except (InvalidTag, VaultCorrupt, ValueError, KeyError, OSError):
                    continue
                self._key, self._hdr, self._data = bytearray(key), header, data
                self._fails = 0
                self._locked_until = 0.0
                self.restored_from_backup = cand == self.bak
                if self.restored_from_backup:
                    # Heal the main file FROM the good backup; never copy the damaged file over the backup.
                    try:
                        if self.path.exists():
                            shutil.copy2(self.path, self.path.with_suffix(".damaged"))
                        C.atomic_write(self.path, self.bak.read_bytes())
                    except OSError:
                        pass
                for svc in self._data.get("services", {}).values():
                    Redactor.register(*[v for v in svc.values() if isinstance(v, str)])
                return
            self._fails += 1
            self._locked_until = (time.time() + min(2 ** min(self._fails, 8), 300)) if self._fails >= 3 else 0.0
            raise VaultAuthError("Wrong password, missing key file, or vault is damaged.")

    def verify_password(self, password: str, keyfile: Optional[bytes] = None) -> bool:
        """Re-authentication for sensitive actions (e.g. revealing credentials). Throttled like unlock."""
        with self._lock:
            self._need()
            now = time.time()
            if now < self._locked_until:
                raise VaultThrottled(int(self._locked_until - now) + 1)
            probe = _derive(password, b64d(self._hdr["salt"]), self._hdr, keyfile if self._hdr.get("kf") else None)
            ok = hmac.compare_digest(probe, bytes(self._key))
            if ok:
                self._fails = 0
                self._locked_until = 0.0
            else:
                self._fails += 1
                self._locked_until = (time.time() + min(2 ** min(self._fails, 8), 300)) if self._fails >= 3 else 0.0
            return ok

    def lock(self) -> None:
        with self._lock:
            if self._key is not None:
                for i in range(len(self._key)):
                    self._key[i] = 0
            self._key = None
            self._data = {}
            Redactor.clear()

    def _need(self) -> None:
        if self._key is None:
            raise VaultLocked("Vault is locked.")

    def _save(self, rekey: bool = False) -> None:
        self._need()
        blob = _pack(bytes(self._key), self._hdr, self._data)
        if rekey:
            # After a password change the old backup would still open with the OLD password: replace it too.
            C.atomic_write(self.bak, blob)
        elif self.path.exists():
            try:
                cur = self.path.read_bytes()
                _parse(cur)  # only promote a structurally valid file to backup
                C.atomic_write(self.bak, cur)
            except (OSError, VaultCorrupt):
                pass
        C.atomic_write(self.path, blob)

    # ---- secrets
    def services(self) -> list[str]:
        with self._lock:
            self._need()
            return sorted(s for s in self._data["services"] if not s.startswith("__"))

    def get(self, service: str) -> Optional[dict]:
        with self._lock:
            self._need()
            v = self._data["services"].get(service)
            return dict(v) if v else None

    def set(self, service: str, fields: dict, internal: bool = False) -> None:
        if not SERVICE_RE.match(service) or (service.startswith("__") and not internal):
            raise VaultError("Invalid service id.")
        clean = {}
        for k, v in (fields or {}).items():
            if not FIELD_RE.match(str(k)):
                raise VaultError("Invalid field name.")
            v = str(v).strip()
            if len(v) > 4096 or re.search(r"[\x00-\x1f\x7f]", v):
                raise VaultError("Invalid field value.")
            if v:
                clean[k] = v
        with self._lock:
            self._need()
            if clean:
                self._data["services"][service] = clean
                Redactor.register(*clean.values())
            else:
                self._data["services"].pop(service, None)
            self._save()

    def delete(self, service: str) -> None:
        with self._lock:
            self._need()
            self._data["services"].pop(service, None)
            self._save()

    def fields_present(self, service: str) -> list[str]:
        v = self.get(service)
        return sorted(v) if v else []

    # ---- derived keys / maintenance
    def subkey(self, purpose: str) -> bytes:
        with self._lock:
            self._need()
            return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mot|" + purpose.encode()).derive(bytes(self._key))

    def change_password(self, old: str, new: str, keyfile: Optional[bytes] = None, new_keyfile: Optional[bytes] = None) -> None:
        with self._lock:
            self._need()
            check_password_strength(new)
            if not self.verify_password(old, keyfile):
                raise VaultAuthError("Current password is incorrect.")
            salt = os.urandom(16)
            params = {k: self._hdr[k] for k in self._hdr if k in ("kdf", "t", "m", "p", "n", "r")}
            new_hdr = {"v": 1, "salt": b64(salt), "kf": bool(new_keyfile), **params}
            new_key = bytearray(_derive(new, salt, params, new_keyfile))
            old_key = self._key
            self._hdr, self._key = new_hdr, new_key
            for i in range(len(old_key)):
                old_key[i] = 0
            self._save(rekey=True)

    def export_backup(self, dest: Path | str) -> None:
        with self._lock:
            C.atomic_write(Path(dest), self.path.read_bytes())

    def backup_bytes(self) -> bytes:
        with self._lock:
            return self.path.read_bytes()

    def header_info(self) -> dict:
        for p in (self.path, self.bak):
            try:
                h = _parse(p.read_bytes())[0]
                return {k: h[k] for k in h if k not in ("salt",)}
            except (OSError, VaultCorrupt):
                continue
        return {}
