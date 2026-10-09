"""MULTI-OSINT-TOOL :: external tool manager.

Each third-party CLI gets its OWN virtual environment under libs/tools/<id>/ with a pinned
version, so dependency conflicts cannot occur and nothing is installed system-wide. Offline
installs use wheels/<id>/ and are verified against a SHA-256 manifest before pip runs.
PhoneInfoga is a Go binary: download it from its releases page into ./bin/ (no installer here).
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

import mot_config as C

RECIPES = {
    "sherlock": {"pkg": "sherlock-project==0.16.2", "bin": "sherlock"},
    "maigret": {"pkg": "maigret==0.6.6", "bin": "maigret"},
    "holehe": {"pkg": "holehe==1.61", "bin": "holehe"},
    "theharvester": {"pkg": "https://github.com/laramies/theHarvester/archive/refs/tags/4.9.2.zip", "bin": "theHarvester", "needs": (3, 12)},
    "spiderfoot": {"archive": "https://github.com/smicallef/spiderfoot/archive/refs/tags/v4.0.zip", "script": "sf.py"},
}
ALLOWED_HOSTS = {"github.com", "codeload.github.com", "pypi.org", "files.pythonhosted.org"}
MANIFEST = C.WHEELS / "mot_wheels.sha256"

# SpiderFoot 4.0 was released in 2022 and pins PyYAML<6. That source package no longer builds with current Python/Cython
# ("'build_ext' object has no attribute 'cython_sources'"; verified while building the bundle), so only that one pin is widened.
# Every other line of the vendor's requirements stays exactly as published.
RELAX = {"spiderfoot": {"pyyaml": ">=5.4.1,<7"}}


def relaxed_requirements(cid: str, text: str) -> str:
    rules = RELAX.get(cid, {})
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*([<>=!~].*)?$", line)
        key = m.group(1).lower().replace("_", "-") if m else ""
        out.append(f"{m.group(1)}{rules[key]}" if key in rules else line)
    return "\n".join(out) + "\n"


def install_proxy(guard) -> Optional[str]:
    """Package downloads go through the shield like everything else. Raises NetworkUnsafe when the shield is down."""
    route = guard.route_for("tor" if guard.has_tor() else "vpn")
    guard.assert_safe(route)
    return guard.proxy_url(route, "mot-install")


def tool_dir(cid: str) -> Path:
    return C.LIBS / "tools" / cid


def venv_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def read_manifest() -> tuple[dict, list[str]]:
    """Strict parse of wheels/mot_wheels.sha256 (`<sha256>  <relative/path>`). A malformed line or an entry that points
    outside wheels/ is reported, never skipped silently: a manifest that cannot be trusted line by line is not trusted."""
    try:
        text = MANIFEST.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}, ["wheels/mot_wheels.sha256 cannot be read."]
    known: dict[str, str] = {}
    bad: list[str] = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        digest, sep, name = line.partition("  ")
        name = name.strip()
        if (not sep or not _HEX64.match(digest) or not name or name.startswith("/") or "\\" in name or ":" in name
                or any(part in ("..", ".", "") for part in name.split("/"))):
            bad.append(f"manifest line {n} is malformed or points outside wheels/")
            continue
        known[name] = digest
    if not known and not bad:
        bad.append("the manifest is empty")
    return known, bad


def verify_manifest(folder: Path) -> list[str]:
    """Compare every file in `folder` with the manifest and the manifest with the folder. Returns the problems ([] = all good):
    changed file, unlisted file, listed-but-missing file, malformed manifest."""
    if not MANIFEST.exists():
        return ["No wheels/mot_wheels.sha256 manifest. Rebuild the bundle with mot_build_offline_bundle.py."]
    known, bad = read_manifest()
    base, folder = C.WHEELS.resolve(), Path(folder).resolve()
    try:
        prefix = folder.relative_to(base).as_posix()
    except ValueError:
        return bad + ["the folder is outside wheels/"]
    if not folder.is_dir():
        return bad + [f"{prefix}: the folder is missing"]
    prefix = "" if prefix == "." else prefix + "/"
    seen = set()
    for f in sorted(folder.iterdir()):
        if not f.is_file() or f.name == ".gitkeep":
            continue
        rel = prefix + f.name
        seen.add(rel)
        if known.get(rel) != sha256_file(f):
            bad.append(f"{rel}: hash missing or mismatched")
    for rel in sorted(known):
        if rel.startswith(prefix) and "/" not in rel[len(prefix):] and rel not in seen:
            bad.append(f"{rel}: listed in the manifest but missing")
    return bad


def _py_version(py: str) -> tuple:
    try:
        out = subprocess.run([py, "-c", "import sys;print('%d.%d' % sys.version_info[:2])"], capture_output=True, text=True, timeout=15, shell=False).stdout.strip()
        a, b = out.split(".")
        return int(a), int(b)
    except Exception:
        return (0, 0)


def _host_pip_ok() -> bool:
    """`pip --python` (needed to install into a venv THROUGH a SOCKS proxy) exists from pip 22.3."""
    try:
        out = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True, text=True, timeout=20, shell=False).stdout
        m = re.search(r"pip (\d+)\.(\d+)", out)
        return bool(m) and (int(m.group(1)), int(m.group(2))) >= (22, 3)
    except Exception:
        return False


def _run(cmd: list, timeout: int = 900, log: Callable = print) -> subprocess.CompletedProcess:
    log("  $ " + " ".join(str(c) for c in cmd[:6]) + (" ..." if len(cmd) > 6 else ""))
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, timeout=timeout, shell=False)


def _download(url: str, dest: Path, proxy: Optional[str]) -> None:
    """HTTPS only, allow-listed hosts only (every redirect hop is checked too), 80 MiB cap, TLS verification always on."""
    import requests

    with requests.Session() as s:
        s.trust_env = False  # no ambient proxies: the route is exactly the one the shield approved
        # A company TLS-inspection proxy needs its own root certificate. Honouring the standard variable keeps verification ON
        # (it only widens the trust roots you chose yourself); verification is never switched off.
        ca = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE") or True
        cur = url
        try:
            for _hop in range(4):
                u = urlparse(cur)
                if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
                    raise RuntimeError("Download host is not on the allow-list.")
                r = s.get(cur, stream=True, timeout=(15, 60), proxies={"https": proxy} if proxy else None, verify=ca, allow_redirects=False,
                          headers={"User-Agent": "MULTI-OSINT-TOOL/1.0"})
                try:
                    if r.status_code in (301, 302, 303, 307, 308):
                        cur = urljoin(cur, r.headers.get("Location", ""))
                        continue
                    r.raise_for_status()
                    size = 0
                    with open(dest, "wb") as fh:
                        for chunk in r.iter_content(1 << 16):
                            size += len(chunk)
                            if size > 80 * 2**20:
                                raise RuntimeError("Archive larger than 80 MiB; aborted.")
                            fh.write(chunk)
                    return
                finally:
                    r.close()
            raise RuntimeError("Too many redirects.")
        except BaseException:
            Path(dest).unlink(missing_ok=True)  # never leave a partial archive behind
            raise


def _safe_extract(zpath: Path, out: Path) -> Path:
    with zipfile.ZipFile(zpath) as z:
        root = out.resolve()
        infos = z.infolist()
        if len(infos) > 20000 or sum(i.file_size for i in infos) > 400 * 2**20:
            raise RuntimeError("Archive is unreasonably large (possible zip bomb); aborted.")
        for m in z.namelist():
            if m.startswith(("/", "\\")) or not (root / m).resolve().is_relative_to(root):
                raise RuntimeError("Archive contains an unsafe path (zip-slip).")
        z.extractall(out)
        top = sorted({n.split("/")[0] for n in z.namelist()})
    return out / top[0]


def installed(cid: str, cfg: C.Config) -> Optional[str]:
    p = cfg.get("tools", cid, default="")
    if p and Path(p).exists():
        return p
    r = RECIPES.get(cid, {})
    for sub in ("bin", "Scripts"):
        for ext in ("", ".exe"):
            cand = tool_dir(cid) / sub / f"{r.get('bin', '')}{ext}"
            if r.get("bin") and cand.is_file():
                return str(cand)
    sf = tool_dir(cid) / "src" / "sf.py"
    return str(sf) if cid == "spiderfoot" and sf.exists() else None


def install_tool(cid: str, cfg: C.Config, offline: Optional[bool] = None, proxy: Optional[str] = None, log: Callable = print) -> dict:
    if cid not in RECIPES:
        return {"ok": False, "msg": f"Unknown tool '{cid}'. Known: {', '.join(RECIPES)}"}
    r = RECIPES[cid]
    base_py = str(cfg.get("toolenv", "python", default="") or "") or sys.executable
    if base_py != sys.executable and not Path(base_py).is_file():
        return {"ok": False, "msg": "toolenv.python in your settings does not point to a Python executable."}
    if "needs" in r and _py_version(base_py) < r["needs"]:
        return {"ok": False, "msg": f"{cid} needs Python {'.'.join(map(str, r['needs']))}+ (set toolenv.python to a newer interpreter)."}
    wheel_dir = C.WHEELS / cid
    use_offline = wheel_dir.is_dir() and any(wheel_dir.iterdir()) if offline is None else offline
    target, src_zip = r.get("pkg"), None
    if use_offline:
        problems = verify_manifest(wheel_dir)
        if problems:
            return {"ok": False, "msg": "Offline bundle failed integrity check: " + "; ".join(problems[:3])}
        # Pre-flight, BEFORE anything is deleted: offline mode must never fall back to a download. A URL requirement is
        # fetched by pip even with --no-index (from your real IP, outside the shield), so offline installs use only files
        # that the bundle builder produced and the manifest vouches for.
        if target and target.startswith("https://"):
            local = next((w for w in sorted(wheel_dir.glob("*.whl")) if w.name.lower().startswith(str(r["bin"]).lower() + "-")), None)
            if local is None:
                return {"ok": False, "msg": f"The offline bundle has no built wheel for {cid}. Rebuild it with: python mot_build_offline_bundle.py --tools {cid}"}
            target = str(local)
        if "archive" in r:
            src_zip = wheel_dir / Path(urlparse(r["archive"]).path).name
            if not src_zip.is_file():
                return {"ok": False, "msg": f"The offline bundle has no source archive for {cid}. Rebuild it with: python mot_build_offline_bundle.py --tools {cid}"}
    socks = bool(proxy) and str(proxy).startswith("socks")
    if socks and not use_offline and not _host_pip_ok():
        return {"ok": False, "msg": "Installing through Tor needs pip 22.3+ (run: python -m pip install --upgrade pip) or use the offline bundle."}
    root = tool_dir(cid)
    try:
        if root.exists():  # a virtual environment cannot be moved, so the old copy goes only after every pre-flight check passed
            shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True, exist_ok=True)
        venv = root if "pkg" in r else root / "venv"
        log(f"Creating isolated environment for {cid} ...")
        p = _run([base_py, "-m", "venv", venv], 300, log)
        if p.returncode:
            return {"ok": False, "msg": "venv creation failed: " + p.stderr[-200:]}
        py = venv_python(venv)
        # Through a SOCKS proxy the HOST pip does the work (it has PySocks); otherwise the venv's own pip.
        pip = ([sys.executable, "-m", "pip", "--python", py] if socks and not use_offline else [py, "-m", "pip"]) + ["install", "--disable-pip-version-check", "-q"]
        if use_offline:
            pip += ["--no-index", "--find-links", wheel_dir]
        elif proxy:
            pip += ["--proxy", proxy]
        if "pkg" in r:
            if target.startswith("https://") and not use_offline:
                # Fetch the pinned source archive ourselves (allow-list, size cap, the approved route) and let pip read the local file:
                # pip would otherwise download it on its own, with no allow-list.
                (C.DATA / "tmp").mkdir(parents=True, exist_ok=True)
                zp = C.DATA / "tmp" / f"mot_{cid}_{secrets.token_hex(4)}.zip"
                try:
                    _download(target, zp, proxy)
                    p = _run(pip + [str(zp)], 900, log)
                finally:
                    zp.unlink(missing_ok=True)
            else:
                p = _run(pip + [target], 900, log)
        else:
            zp = root / "src.zip"
            if use_offline:
                shutil.copy2(src_zip, zp)
            else:
                _download(r["archive"], zp, proxy)
            top = _safe_extract(zp, root / "_x")
            shutil.move(str(top), str(root / "src"))
            shutil.rmtree(root / "_x", ignore_errors=True)
            zp.unlink()
            req_file = root / "mot_requirements.txt"
            req_file.write_text(relaxed_requirements(cid, (root / "src" / "requirements.txt").read_text(encoding="utf-8")), encoding="utf-8")
            p = _run(pip + ["-r", req_file], 900, log)
        if p.returncode:
            hint = ""
            if cid == "spiderfoot" and _py_version(base_py) >= (3, 13):
                hint = (" SpiderFoot 4.0 depends on lxml 4.x, which has no prebuilt package for Python 3.13 or newer (verified when building the bundle). "
                        "Install Python 3.12 next to your current one and set 'Python for tools' in Settings to it.")
            return {"ok": False, "msg": (hint.strip() + " " if hint else "") + "pip said: " + (p.stderr or p.stdout)[-240:].strip()}
        found = installed(cid, cfg)
        if cid == "spiderfoot" and found:
            cfg.set("tools", cid, found)
        return {"ok": bool(found), "msg": f"{cid} installed at {found}" if found else "Install finished but the executable was not found."}
    except Exception as exc:
        return {"ok": False, "msg": f"{type(exc).__name__}: {str(exc)[:200]}"}
