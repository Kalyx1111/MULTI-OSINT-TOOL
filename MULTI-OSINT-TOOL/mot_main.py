#!/usr/bin/env python3
"""MULTI-OSINT-TOOL :: launcher, supervisor and command-line tools.

  python mot_main.py                 start (supervised: restarts the service automatically after a crash)
  python mot_main.py run --no-browser  start without opening a window (type 'link' in this terminal to get one)
  python mot_main.py doctor [--fix]  diagnose (and repair) the installation, no vault needed
  python mot_main.py selftest        offline self-check of all 20 connectors and the crypto layer
  python mot_main.py tools --status | --install <id> [--offline]
  python mot_main.py bootstrap       install missing Python packages (offline bundle first)
  python mot_main.py version

Design: the heavy modules are imported only after the dependency check, so a half-installed
folder produces a clear message instead of a traceback. Nothing here touches the network unless
you explicitly consent (package download) or the shield has verified the route.
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from collections import deque
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
os.environ.setdefault("MOT_HOME", str(HERE))
_VENDORED = HERE / "libs" / "site-packages"  # optional pre-installed bundle inside the Master Folder
if _VENDORED.is_dir() and str(_VENDORED) not in sys.path:
    sys.path.insert(0, str(_VENDORED))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

MIN_PY = (3, 10)
REQUIRED = {"requests": "requests", "socks": "PySocks", "cryptography": "cryptography"}
OPTIONAL = {"argon2": "argon2-cffi", "psutil": "psutil", "phonenumbers": "phonenumbers"}
DATA = Path(os.environ.get("MOT_DATA") or HERE / "mot_data").resolve()


def say(msg: str = "") -> None:
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode(), flush=True)


def banner(version: str = "") -> None:
    say("")
    say("  MULTI-OSINT-TOOL" + (f"  v{version}" if version else ""))
    say("  Shielded open-source intelligence across 20 tools")
    say("  " + "-" * 49)


def pause_exit(code: int = 0) -> None:
    """Keep the window open so errors can be read (interactive terminals only; automation is never blocked)."""
    try:
        if sys.stdin and sys.stdin.isatty() or os.environ.get("MOT_PAUSE") == "1":
            input("\nPress Enter to exit...")
    except (EOFError, KeyboardInterrupt):
        pass
    raise SystemExit(code)


# ------------------------------------------------------------------------------------ dependencies
def missing_modules() -> tuple[list, list]:
    def miss(group: dict) -> list:
        out = []
        for mod, pip_name in group.items():
            try:
                __import__(mod)
            except ImportError:
                out.append(pip_name)
        return out

    return miss(REQUIRED), miss(OPTIONAL)


def offline_mode() -> bool:
    """Privacy-safe heuristic: sends no packets. Offline = no non-loopback network interface is up."""
    try:
        import psutil

        return not any(s.isup for n, s in psutil.net_if_stats().items() if not n.lower().startswith(("lo", "loopback")))
    except Exception:
        return False


def bootstrap(interactive: bool = True) -> bool:
    req_missing, opt_missing = missing_modules()
    if not req_missing and not opt_missing:
        return True
    say(f"Missing packages: {', '.join(req_missing + opt_missing)}")
    req = HERE / "mot_requirements.txt"
    wheels = HERE / "wheels" / "core"
    cmd = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-r", str(req)]
    if wheels.is_dir() and any(wheels.iterdir()):
        import mot_tools as T

        problems = T.verify_manifest(wheels)
        if problems:
            say("The offline bundle failed its integrity check, so nothing was installed:")
            for p in problems[:5]:
                say("  - " + p)
            return False
        say("Installing from the offline bundle (wheels/core, integrity verified) ...")
        cmd[4:4] = ["--no-index", "--find-links", str(wheels)]
    else:
        if offline_mode():
            say("No offline bundle (wheels/core) and no network connection. Copy a prepared Master Folder or connect, then retry.")
            return False
        say("No offline bundle was found. Packages would come from PyPI, which sees your real IP address.")
        say("Best practice: connect your VPN first, or build the bundle once on a clean machine (mot_build_offline_bundle.py).")
        if not interactive or input("Download from PyPI now? [y/N] ").strip().lower() != "y":
            return False
    r = subprocess.run(cmd, shell=False)
    if r.returncode != 0:
        say("Installation failed. See the messages above.")
        return False
    req_missing, _ = missing_modules()
    return not req_missing


# ------------------------------------------------------------------------------------ single instance + ports
class AlreadyRunning(Exception):
    pass


def _proc_stamp(pid: int) -> str:
    try:
        import psutil

        return f"{pid}:{int(psutil.Process(pid).create_time())}"
    except Exception:
        return f"{pid}:0"


class InstanceLock:
    """One supervisor per data folder: two writers would corrupt the tamper-evident audit chain."""

    def __init__(self) -> None:
        self.path = DATA / "recovery" / "instance.lock"

    def __enter__(self) -> "InstanceLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.write(fd, _proc_stamp(os.getpid()).encode())
                os.close(fd)
                return self
            except FileExistsError:
                try:
                    stamp = self.path.read_text().strip()
                    pid = int(stamp.split(":")[0])
                except (OSError, ValueError):
                    stamp, pid = "", 0
                alive = False
                if pid and pid != os.getpid():
                    try:
                        import psutil

                        alive = psutil.pid_exists(pid) and _proc_stamp(pid) == stamp
                    except ImportError:
                        if os.name == "posix":
                            try:
                                os.kill(pid, 0)
                                alive = True
                            except OSError:
                                alive = False
                    except Exception:
                        alive = False
                if alive:
                    raise AlreadyRunning(f"MULTI-OSINT-TOOL is already running from this folder (process {pid}).") from None
                try:
                    self.path.unlink()
                except OSError:
                    pass
        raise AlreadyRunning("Could not take the instance lock.")

    def __exit__(self, *exc) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if os.name != "nt":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def find_port(preferred: int) -> int:
    for p in range(preferred, min(preferred + 25, 65535)):
        if port_free(p):
            return p
    raise RuntimeError("No free local port found near " + str(preferred))


# ------------------------------------------------------------------------------------ secure window
def find_browser() -> Optional[str]:
    """Chromium-family browsers only: their flags are what makes the isolated profile possible."""
    env = os.environ.get("MOT_BROWSER", "")
    if env and Path(env).is_file():
        return env
    cands: list[str] = []
    if sys.platform == "win32":
        roots = [os.environ.get(k, "") for k in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData")]
        for r in filter(None, roots):
            cands += [rf"{r}\Google\Chrome\Application\chrome.exe", rf"{r}\Microsoft\Edge\Application\msedge.exe", rf"{r}\BraveSoftware\Brave-Browser\Application\brave.exe",
                      rf"{r}\Chromium\Application\chrome.exe"]
    elif sys.platform == "darwin":
        for app in ("Google Chrome", "Microsoft Edge", "Brave Browser", "Chromium"):
            cands.append(f"/Applications/{app}.app/Contents/MacOS/{app}")
    else:
        import shutil

        cands += [w for w in (shutil.which(n) for n in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "brave-browser")) if w]
    return next((c for c in cands if c and Path(c).is_file()), None)


def window_args(exe: str, url: str) -> list[str]:
    """Dead-proxy isolation (verified in testing): loopback is exempt from proxying, everything else fails closed,
    so the window can never contact an update server, safe-browsing list or tracker, and your IP stays out of it."""
    profile = DATA / "browser_profile"
    return [exe, f"--user-data-dir={profile}", "--incognito", "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-sync",
            "--disable-background-networking", "--disable-component-update", "--disable-default-apps", "--disable-breakpad", "--disable-domain-reliability",
            "--disable-client-side-phishing-detection", "--no-pings", "--disable-features=Translate,OptimizationHints,MediaRouter,AutofillServerCommunication",
            "--proxy-server=socks5://127.0.0.1:9", "--window-size=1380,900", f"--app={url}"]


def launch_window(port: int, secret: bytes, secure: bool = True) -> str:
    import mot_server as S

    token = S.Sessions(secret).mint_launch()
    tmp = DATA / "tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    f = tmp / f"mot_launch_{secrets.token_hex(6)}.html"
    page = (f'<!doctype html><meta charset="utf-8"><title>MULTI-OSINT-TOOL</title><body onload="document.forms[0].submit()">'
            f'<form method="post" action="http://127.0.0.1:{port}/mot-launch"><input type="hidden" name="t" value="{token}">'
            f'<noscript><button>Continue</button></noscript></form></body>')
    fd = os.open(f, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(page)
    cleanup = threading.Timer(180, lambda: f.unlink(missing_ok=True))  # the token is dead by then anyway
    cleanup.daemon = True
    cleanup.start()
    url = f.as_uri()
    exe = find_browser() if secure else None
    if exe:
        kw: dict = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if os.name == "posix":
            kw["start_new_session"] = True
        subprocess.Popen(window_args(exe, url), **kw)
        return "secure window (isolated profile, no outside network)"
    webbrowser.open(url)
    return "your default browser (NOT isolated: install Chrome, Edge, Brave or Chromium for the secure window)"


# ------------------------------------------------------------------------------------ service (child process)
def serve(port: int) -> int:
    from mot_resilience import install_crash_handlers, setup_logging

    setup_logging()
    install_crash_handlers()
    import mot_app
    import mot_server

    interactive = bool(sys.stdin and sys.stdin.isatty())
    secret = secrets.token_bytes(32)
    if not interactive:
        box: list = []
        reader = threading.Thread(target=lambda: box.append(sys.stdin.readline().strip()), daemon=True)
        reader.start()
        reader.join(8)  # started by hand without a supervisor? carry on with a private random secret
        if box and re.fullmatch(r"[0-9a-f]{64}", box[0]):
            secret = bytes.fromhex(box[0])
    app = mot_app.App()
    app.boot()
    srv = mot_server.MotServer(app, port, secret)
    srv.start_idle_watchdog()
    stop = srv.stop_event
    thr = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.25}, name="mot-serve", daemon=True)
    thr.start()

    def on_signal(*_a) -> None:
        stop.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), on_signal)
            except (ValueError, OSError):
                pass
    if not interactive:  # supervisor channel: 'quit' on stdin, or EOF when the supervisor dies (no orphan servers)
        def watch() -> None:
            for line in sys.stdin:
                if line.strip() == "quit":
                    break
            stop.set()

        threading.Thread(target=watch, name="mot-stdin", daemon=True).start()
    say(f"MOT_READY {port}")
    code = 0
    while not stop.wait(1.0):
        if not thr.is_alive():
            code = 3  # the accept loop died: report as a crash so the supervisor restarts us
            break
    try:
        srv.shutdown()
        srv.server_close()
    except Exception:
        pass
    app.shutdown(clean=(code == 0))
    return code


# ------------------------------------------------------------------------------------ supervisor
def _ready(port: int, child: subprocess.Popen, timeout: float = 40.0) -> bool:
    import urllib.request

    end = time.time() + timeout
    while time.time() < end and child.poll() is None:
        try:
            with urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/mot-health"), timeout=2) as r:  # noqa: S310 (loopback)
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def supervise(args: argparse.Namespace) -> int:
    from mot_config import APP_VERSION, Config, ensure_dirs

    ensure_dirs()
    banner(APP_VERSION)
    cfg = Config().load()
    if cfg.repairs:
        say("Configuration was repaired: " + "; ".join(cfg.repairs))
    port = find_port(args.port or int(cfg.get("server", "port", default=8765)))
    secret = secrets.token_bytes(32)
    secure = bool(cfg.get("server", "secure_window", default=True))
    quitting = threading.Event()
    state = {"child": None}
    crashes: deque = deque()

    def open_window() -> None:
        try:
            how = launch_window(port, secret, secure)
            say(f"  Opened {how}.")
        except Exception as exc:
            say(f"  Could not open a window automatically ({type(exc).__name__}). Check the launch file in {DATA / 'tmp'}.")

    def request_quit(*_a) -> None:
        quitting.set()
        c = state["child"]
        if c and c.poll() is None:
            try:
                c.stdin.write("quit\n")
                c.stdin.flush()
            except Exception:
                pass  # broken pipe = the child is already shutting down by itself

    for name in ("SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), request_quit)
            except (ValueError, OSError):
                pass

    def console() -> None:
        say("  Commands: link (open a new window) | status | quit")
        for line in sys.stdin:
            cmd = line.strip().lower()
            if cmd in ("q", "quit", "exit"):
                request_quit()
                return
            if cmd == "link":
                open_window()
            elif cmd == "status":
                c = state["child"]
                say(f"  service: {'running' if c and c.poll() is None else 'not running'} on http://127.0.0.1:{port}  | crashes in last 2 min: {len(crashes)}")
            elif cmd:
                say("  Commands: link | status | quit")

    if sys.stdin and sys.stdin.isatty():
        threading.Thread(target=console, name="mot-console", daemon=True).start()
    first = True
    while not quitting.is_set():
        child = subprocess.Popen([sys.executable, str(HERE / "mot_main.py"), "serve", "--port", str(port)], stdin=subprocess.PIPE, text=True, cwd=str(HERE),
                                 env={**os.environ, "PYTHONUTF8": "1"})
        state["child"] = child
        try:
            child.stdin.write(secret.hex() + "\n")
            child.stdin.flush()
        except Exception:
            pass
        if _ready(port, child):
            say(f"  Service running at http://127.0.0.1:{port}  (loopback only; nothing is reachable from the network)")
            if first and not args.no_browser:
                open_window()
            elif first:
                say("  No window opened (--no-browser). Type 'link' here to open one.")
            first = False
        try:
            rc = child.wait()
        except KeyboardInterrupt:
            request_quit()
            try:
                child.wait(25)
            except subprocess.TimeoutExpired:
                child.kill()
            break
        if quitting.is_set() or rc == 0:
            break
        now = time.time()
        crashes.append(now)
        while crashes and now - crashes[0] > 120:
            crashes.popleft()
        if len(crashes) >= 5:
            say("\n  The service crashed 5 times in 2 minutes, so automatic restarts stopped.")
            say("  Run diagnostics:  python mot_main.py doctor --fix     (crash reports are in mot_data/logs)")
            return 1
        delay = min(30, 2 ** len(crashes))
        say(f"\n  The service stopped unexpectedly (exit {rc}). Restarting in {delay}s. Your session stays valid; unlock again, then use 'Recover'.")
        if quitting.wait(delay):
            break
    say("  MULTI-OSINT-TOOL stopped. Temporary files are removed and the vault is locked.")
    return 0


# ------------------------------------------------------------------------------------ CLI tools
def cmd_doctor(fix: bool) -> int:
    import mot_config as C
    from mot_resilience import Doctor

    C.ensure_dirs()
    cfg = C.Config().load()
    d = Doctor(cfg)
    rows = d.run()
    mark = {"ok": "[ ok ]", "warn": "[warn]", "fail": "[FAIL]"}
    for r in rows:
        say(f"{mark[r['status']]} {r['title']}: {r['detail']}")
        if fix and r["status"] != "ok" and r["fixable"]:
            res = d.fix(r["id"])
            say(f"        repair: {'done' if res.get('ok') else 'not done'} - {res.get('msg', '')}")
    bad = sum(1 for r in rows if r["status"] == "fail")
    say(f"\n{len(rows)} checks, {bad} failing." + ("" if bad or not any(r['status'] == 'warn' for r in rows) else " Warnings are optional items (for example tools you have not installed)."))
    return 1 if bad else 0


def cmd_selftest() -> int:
    import mot_app  # noqa: F401  (registers connectors)
    import mot_connectors_base as B
    from mot_vault import Vault

    problems = 0
    for cid, c in B.REGISTRY.items():
        try:
            p = c.selftest()
        except Exception as exc:
            p = [f"crashed: {type(exc).__name__}"]
        say(f"[{'ok' if not p else 'FAIL'}] {cid}" + ("" if not p else ": " + "; ".join(p)))
        problems += len(p)
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        v = Vault(Path(td) / "t.motv")
        try:
            import argon2  # noqa: F401

            kdf = {"kdf": "argon2id", "t": 2, "m": 19456, "p": 1}
        except ImportError:
            kdf = None  # falls back to scrypt
        import secrets  # per-run self-test values: no literals in the source

        pw, probe = secrets.token_urlsafe(24), secrets.token_hex(12)
        v.create(pw, kdf=kdf)
        v.set("shodan", {"api_key": probe})
        v.lock()
        v.unlock(pw)
        ok = (v.get("shodan") or {}).get("api_key") == probe
        say(f"[{'ok' if ok else 'FAIL'}] vault: AES-256-GCM round trip")
        problems += 0 if ok else 1
    say(f"\n{len(B.REGISTRY)} connectors checked; {problems} problem(s).")
    return 1 if problems else 0


def cmd_tools(args: argparse.Namespace) -> int:
    import getpass

    import mot_app
    import mot_config as C
    import mot_tools as T

    app = mot_app.App()
    if args.install:
        offline = args.offline or ((C.WHEELS / args.install).is_dir() and any((C.WHEELS / args.install).iterdir()))
        if offline:
            r = T.install_tool(args.install, app.cfg, offline=True)
            say(("Installed: " if r["ok"] else "Failed: ") + r["msg"])
            return 0 if r["ok"] else 1
        if app.state == "no_vault":
            say("Create your vault first (start the app once). Online installs go through your shield, which needs the vault.")
            return 1
        say("Online install goes through your network shield, so the vault is needed to verify it.")
        try:
            app.unlock(getpass.getpass("Master password: "))
            r = app.tool_install(args.install)
        except Exception as exc:
            say(f"Not installed: {exc}")
            return 1
        while app.installing.get(args.install, {}).get("state") == "running":
            time.sleep(1)
        st = app.installing.get(args.install, {})
        say(st.get("msg", r))
        app.lock()
        return 0 if st.get("state") == "done" else 1
    for cid, rec in T.RECIPES.items():
        say(f"{cid:14s} {'installed: ' + T.installed(cid, app.cfg) if T.installed(cid, app.cfg) else 'not installed'}")
    return 0


# ------------------------------------------------------------------------------------ entry
def main(argv: Optional[list] = None) -> int:
    if sys.version_info < MIN_PY:
        say(f"Python {MIN_PY[0]}.{MIN_PY[1]} or newer is required (this is {sys.version.split()[0]}).")
        return 2
    p = argparse.ArgumentParser(prog="mot_main.py", description="MULTI-OSINT-TOOL launcher")
    sub = p.add_subparsers(dest="cmd")
    r = sub.add_parser("run", help="start supervised (default)")
    r.add_argument("--no-browser", action="store_true")
    r.add_argument("--port", type=int, default=0)
    s = sub.add_parser("serve", help="(internal) run the service in this process")
    s.add_argument("--port", type=int, required=True)
    d = sub.add_parser("doctor")
    d.add_argument("--fix", action="store_true")
    sub.add_parser("selftest")
    t = sub.add_parser("tools")
    t.add_argument("--install", metavar="ID")
    t.add_argument("--offline", action="store_true")
    t.add_argument("--status", action="store_true")
    sub.add_parser("bootstrap")
    sub.add_parser("version")
    args = p.parse_args(argv)
    cmd = args.cmd or "run"
    if cmd == "run" and args.cmd is None:
        args = argparse.Namespace(cmd="run", no_browser=False, port=0)
    if cmd == "version":
        import mot_config

        say(f"{mot_config.APP_NAME} {mot_config.APP_VERSION}")
        return 0
    if cmd == "bootstrap":
        return 0 if bootstrap() else 1
    if cmd != "serve" and not bootstrap(interactive=sys.stdin.isatty() if sys.stdin else False):
        say("Required packages are missing. Use mot_launch.sh / mot_launch.bat, or: python mot_main.py bootstrap")
        return 1
    if cmd == "serve":
        return serve(args.port)
    if cmd == "doctor":
        return cmd_doctor(args.fix)
    if cmd == "selftest":
        return cmd_selftest()
    if cmd == "tools":
        return cmd_tools(args)
    try:
        with InstanceLock():
            return supervise(args)
    except AlreadyRunning as exc:
        say(str(exc))
        say("Close the other window or finish it first. If you are sure nothing is running, delete mot_data/recovery/instance.lock.")
        return 1


if __name__ == "__main__":
    code = 1
    try:
        code = main()
    except KeyboardInterrupt:
        code = 130
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    except Exception as exc:  # never a bare traceback in a closing window
        try:
            from mot_resilience import setup_logging  # noqa: F401
            import logging

            logging.getLogger("mot.main").exception("fatal")
        except Exception:
            pass
        say(f"\nMULTI-OSINT-TOOL hit an unexpected problem ({type(exc).__name__}). Run: python mot_main.py doctor --fix")
        code = 1
    if len(sys.argv) < 2 or sys.argv[1] in ("run", "doctor", "selftest", "tools", "bootstrap"):
        pause_exit(code)
    raise SystemExit(code)
