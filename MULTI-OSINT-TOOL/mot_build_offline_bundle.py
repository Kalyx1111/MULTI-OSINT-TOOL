#!/usr/bin/env python3
"""MULTI-OSINT-TOOL :: build the offline bundle (run once, on a build machine, behind your VPN).

Fills wheels/ with every Python package MOT and its optional tools need, then writes a SHA-256
manifest (wheels/mot_wheels.sha256). After that the whole Master Folder installs and runs with NO
network: mot_main.py verifies every file against the manifest BEFORE pip touches it, and pip is
run with --no-index so nothing can be fetched from anywhere else.

  python mot_build_offline_bundle.py                 core packages only
  python mot_build_offline_bundle.py --tools all     core + sherlock, maigret, holehe, theHarvester, SpiderFoot
  python mot_build_offline_bundle.py --tools all --python /usr/bin/python3.12   build the CLI tools for Python 3.12 (needed for SpiderFoot)
  python mot_build_offline_bundle.py --proxy socks5h://127.0.0.1:9050   download through Tor

Wheels are specific to the operating system, CPU architecture and Python minor version they were
built on (recorded in wheels/mot_bundle_info.json). Build one bundle per target platform.
The manifest detects corruption and accidental changes; it is not a defence against an attacker who
can already write to this folder (they could rewrite the manifest too). Keep the folder on trusted storage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import mot_tools as T  # noqa: E402

WHEELS = HERE / "wheels"


def run(cmd: list) -> int:
    print("  $ " + " ".join(str(c) for c in cmd[:8]) + (" ..." if len(cmd) > 8 else ""))
    return subprocess.run([str(c) for c in cmd], shell=False).returncode


def pip_wheel(args: list, dest: Path, proxy: str, py: str = "") -> bool:
    dest.mkdir(parents=True, exist_ok=True)
    cmd = [py or sys.executable, "-m", "pip", "wheel", "--disable-pip-version-check", "-w", dest] + (["--proxy", proxy] if proxy else []) + args
    return run(cmd) == 0


def build_core(proxy: str) -> bool:
    return pip_wheel(["-r", HERE / "mot_requirements.txt"], WHEELS / "core", proxy)


def build_tool(cid: str, proxy: str, py: str = "") -> bool:
    rec = T.RECIPES[cid]
    dest = WHEELS / cid
    if "pkg" in rec and rec["pkg"].startswith("https://"):
        # same rule as the online install: this program fetches the pinned archive (allow-list, size cap, TLS verified) and pip builds from the local file
        dest.mkdir(parents=True, exist_ok=True)
        zp = dest / ("mot_src_" + Path(urlparse(rec["pkg"]).path).name)
        print(f"  downloading {rec['pkg']}")
        T._download(rec["pkg"], zp, proxy or None)
        try:
            return pip_wheel([zp], dest, proxy, py)
        finally:
            zp.unlink(missing_ok=True)
    if "pkg" in rec:
        return pip_wheel([rec["pkg"]], dest, proxy, py)
    dest.mkdir(parents=True, exist_ok=True)
    zp = dest / Path(rec["archive"]).name
    print(f"  downloading {rec['archive']}")
    T._download(rec["archive"], zp, proxy or None)
    with zipfile.ZipFile(zp) as z:
        name = next((n for n in z.namelist() if n.endswith("/requirements.txt") and n.count("/") == 1), None)
        if not name:
            print("  no requirements.txt found in the archive")
            return False
        req = dest / "mot_requirements_from_archive.txt"
        req.write_text(T.relaxed_requirements(cid, z.read(name).decode("utf-8")), encoding="utf-8")
    ok = pip_wheel(["-r", req], dest, proxy, py)
    req.unlink(missing_ok=True)
    return ok


def write_manifest() -> int:
    lines = []
    for f in sorted(WHEELS.rglob("*")):
        if f.is_file() and f.name not in ("mot_wheels.sha256", "mot_bundle_info.json", ".gitkeep"):
            h = hashlib.sha256()
            with open(f, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            lines.append(f"{h.hexdigest()}  {f.relative_to(WHEELS).as_posix()}")
    (WHEELS / "mot_wheels.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (WHEELS / "mot_bundle_info.json").write_text(json.dumps({"python": platform.python_version(), "implementation": platform.python_implementation(),
                                                           "machine": platform.machine(), "system": platform.system(), "files": len(lines)}, indent=2), encoding="utf-8")
    return len(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the MULTI-OSINT-TOOL offline bundle")
    ap.add_argument("--tools", default="", help="comma list of " + ", ".join(T.RECIPES) + " or 'all'")
    ap.add_argument("--proxy", default="", help="e.g. socks5h://127.0.0.1:9050 (needs PySocks) or http://host:port")
    ap.add_argument("--python", default="", help="interpreter used to build the CLI tools' wheels (default: this one). SpiderFoot 4.0 needs Python 3.10-3.12; use the same interpreter you will set as 'Python for tools'")
    ap.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    a = ap.parse_args()
    want = list(T.RECIPES) if a.tools == "all" else [t for t in a.tools.split(",") if t]
    bad = [t for t in want if t not in T.RECIPES]
    if bad:
        print("Unknown tool(s): " + ", ".join(bad))
        return 2
    if a.python and not Path(a.python).is_file():
        print("--python must be the full path of a Python executable.")
        return 2
    print("This downloads packages from PyPI" + (" and GitHub" if want else "") + (" through " + a.proxy if a.proxy else ", and the servers will see your real IP address") + ".")
    if not a.yes and input("Continue? [y/N] ").strip().lower() != "y":
        return 1
    ok = build_core(a.proxy)
    failed = [] if ok else ["core"]
    for cid in want:
        print(f"\n== {cid}")
        try:
            good = build_tool(cid, a.proxy, a.python)
        except Exception as exc:  # one tool failing must not lose the rest of the bundle
            print(f"  {cid} could not be fetched ({type(exc).__name__}: {str(exc)[:160]})")
            good = False
        if not good:
            failed.append(cid)
        ok = good and ok
    n = write_manifest()
    print(f"\nManifest written: {n} files hashed -> wheels/mot_wheels.sha256")
    if failed:
        print("Incomplete bundle. Failed: " + ", ".join(failed) + ". Fix the cause and run the builder again for those tools.")
    print("Bundle is valid for: " + f"{platform.system()} {platform.machine()}, Python {platform.python_version()[:4]}")
    return 0 if ok else 1


if __name__ == "__main__":
    code = 1
    try:
        code = main()
    except KeyboardInterrupt:
        code = 130
    if sys.stdin and sys.stdin.isatty():
        try:
            input("\nPress Enter to exit...")
        except EOFError:
            pass
    raise SystemExit(code)
