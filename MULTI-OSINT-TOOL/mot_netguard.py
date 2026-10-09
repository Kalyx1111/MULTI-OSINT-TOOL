"""MULTI-OSINT-TOOL :: network shield.

Policy: FAIL CLOSED. No connector may send a packet unless the shield has verified the route.

Modes   tor_over_vpn (recommended) | tor | vpn | proxy | direct (off by default, needs explicit opt-in)
Checks  1) local pre-flight, no packets: VPN adapter up? Tor SOCKS reachable? baseline recorded?
        2) network proof: Tor Project check API (IsTor) and egress-IP != your recorded real IP.
Extras  per-connector Tor circuit isolation (SOCKS auth), socks5h only (DNS resolved remotely),
        live kill-switch (adapter drop is detected on every request), background re-verification.

Honest limits: user-space software cannot stop OS-level leaks. Keep your VPN client's own
kill-switch ON; MOT is a second, independent gate. See mot_SECURITY.md.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import quote, urlparse

import requests

import mot_config as C
from mot_vault import Redactor

log = logging.getLogger("mot.shield")

TOR_CHECK_URL = "https://check.torproject.org/api/ip"
UA = "MULTI-OSINT-TOOL/1.0"
BUILTIN_VPN_RE = re.compile(
    r"(?i)(^tun\d*$|^tap\d*$|^wg\d*$|^utun\d+$|^ppp\d*$|proton|nord|mullvad|wireguard|openvpn|ipsec|"
    r"surfshark|windscribe|expressvpn|cyberghost|ivpn|\bvpn\b)"
)


class NetworkUnsafe(Exception):
    """Raised instead of sending any traffic when the shield cannot prove the route is safe."""


class _Offline(Exception):
    pass


def mask_ip(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if a.version == 4:
        p = ip.split(".")
        return f"{p[0]}.{p[1]}.*.*"
    return ":".join(a.exploded.split(":")[:2]) + "::*"


def _tcp_ok(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def vpn_adapters(custom: str = "") -> Optional[list]:
    """Up VPN-looking interfaces. None = heuristic unavailable (macOS has permanent utun*)."""
    if sys.platform == "darwin" and not custom:
        return None
    try:
        rx = re.compile(custom) if custom else BUILTIN_VPN_RE
    except re.error:
        rx = BUILTIN_VPN_RE
    try:
        import psutil

        return sorted(n for n, s in psutil.net_if_stats().items() if s.isup and rx.search(n))
    except Exception:
        pass
    if sys.platform.startswith("linux"):
        out = []
        try:
            for p in Path("/sys/class/net").iterdir():
                if rx.search(p.name):
                    try:
                        st = (p / "operstate").read_text().strip()
                    except OSError:
                        st = "unknown"
                    if st in ("up", "unknown"):
                        out.append(p.name)
            return sorted(out)
        except OSError:
            return None
    return None


@dataclass
class ShieldState:
    ok: bool = False
    mode: str = ""
    checked_at: float = 0.0
    tor_port: Optional[bool] = None
    tor_exit: Optional[bool] = None
    vpn_adapter: Optional[bool] = None
    adapters: list = field(default_factory=list)
    egress_ip: str = ""  # Tor exit IP (when Tor in use)
    vpn_egress_ip: str = ""  # IP seen through the OS route (VPN)
    offline: bool = False
    reasons: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def public(self) -> dict:
        d = asdict(self)
        d["egress_ip"] = mask_ip(self.egress_ip)
        d["vpn_egress_ip"] = mask_ip(self.vpn_egress_ip)
        d["age"] = round(time.time() - self.checked_at, 1) if self.checked_at else None
        return d


class NetGuard:
    def __init__(self, cfg: C.Config, baseline_get: Callable[[], str], baseline_set: Callable[[str], None]):
        self.cfg = cfg
        self._bget, self._bset = baseline_get, baseline_set
        self.state = ShieldState()
        self._vlock = threading.RLock()
        self._stop = threading.Event()
        self._thr: Optional[threading.Thread] = None
        self._iso_salt = secrets.token_hex(8)

    # ------------------------------------------------------------------ config helpers
    @property
    def mode(self) -> str:
        return self.cfg.get("shield", "mode", default="tor_over_vpn")

    @property
    def recheck(self) -> int:
        return int(self.cfg.get("shield", "recheck_seconds", default=60))

    def _tor_hostport(self) -> tuple[str, int]:
        host, _, port = str(self.cfg.get("shield", "tor_socks", default="127.0.0.1:9050")).rpartition(":")
        return host or "127.0.0.1", int(port or 9050)

    def _custom_proxy(self) -> str:
        pu = str(self.cfg.get("shield", "custom_proxy", default="")).strip()
        if not pu:
            return ""
        u = urlparse(pu)
        if u.scheme not in ("socks5", "socks5h", "http", "https") or not u.hostname or not u.port or u.username or u.password:
            return ""  # credentials in a config URL would be stored in plaintext: not supported
        return pu.replace("socks5://", "socks5h://", 1)  # force remote DNS

    def has_tor(self) -> bool:
        return self.mode in ("tor", "tor_over_vpn")

    def has_vpn(self) -> bool:
        return self.mode in ("vpn", "tor_over_vpn")

    # ------------------------------------------------------------------ routing
    def route_for(self, pref: str = "vpn", needs_tor: bool = False) -> str:
        m = self.mode
        if needs_tor:
            if not self.has_tor():
                raise NetworkUnsafe("Dark-web / onion access requires Tor mode (tor or tor_over_vpn).")
            return "tor"
        if m == "tor":
            return "tor"
        if m == "vpn":
            return "vpn"
        if m == "proxy":
            return "proxy"
        if m == "direct":
            return "direct"
        return pref if pref in ("tor", "vpn") else "vpn"  # tor_over_vpn

    def proxy_url(self, route: str, iso: str = "") -> Optional[str]:
        if route == "tor":
            host, port = self._tor_hostport()
            if iso:
                user = "mot" + re.sub(r"[^A-Za-z0-9]", "", iso)[:40]
                pw = hashlib.sha256((self._iso_salt + iso).encode()).hexdigest()[:12]
                return f"socks5h://{quote(user)}:{pw}@{host}:{port}"  # distinct creds => distinct Tor circuit
            return f"socks5h://{host}:{port}"
        if route == "proxy":
            return self._custom_proxy() or None
        return None

    def tool_proxy(self, route: str, iso: str = "") -> Optional[str]:
        return self.proxy_url(route, iso)

    def session(self, route: str, iso: str = "") -> requests.Session:
        s = requests.Session()
        s.trust_env = False  # ignore ambient proxy variables: only MOT decides routing
        s.max_redirects = 3
        s.headers.update({"User-Agent": UA, "Accept": "application/json, text/html;q=0.8, */*;q=0.5", "Accept-Language": "en-US,en;q=0.5", "DNT": "1"})
        pu = self.proxy_url(route, iso)
        if pu:
            s.proxies = {"http": pu, "https": pu}
        return s

    def subprocess_env(self, route: str, iso: str = "") -> dict:
        keep = {"PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"}
        env = {k: v for k, v in os.environ.items() if k.upper() in keep}
        env.update({"NO_COLOR": "1", "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1", "NO_PROXY": ""})
        pu = self.proxy_url(route, iso)
        if pu:  # also covers tools' own update checks (e.g. Sherlock) that ignore their --proxy flag
            for k in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "http_proxy", "https_proxy"):
                env[k] = pu
        return env

    # ------------------------------------------------------------------ verification
    def _get_json(self, url: str, proxy: Optional[str]) -> dict:
        s = requests.Session()
        s.trust_env = False
        try:
            r = s.get(url, proxies={"http": proxy, "https": proxy} if proxy else None, timeout=(8, 15), headers={"User-Agent": UA})
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise _Offline(type(exc).__name__) from exc
        r.raise_for_status()
        return r.json()

    def verify(self, force: bool = False) -> ShieldState:
        with self._vlock:
            ttl = self.recheck if self.state.ok else 5
            if not force and self.state.checked_at and time.time() - self.state.checked_at < ttl:
                return self.state
            st = ShieldState(mode=self.mode, checked_at=time.time())
            try:
                self._verify_into(st)
            except _Offline as exc:
                st.ok, st.offline = False, True
                st.reasons.append(f"No network connectivity ({exc}).")
            except Exception as exc:  # fail closed
                st.ok = False
                st.reasons.append(Redactor.redact(f"Shield check failed: {type(exc).__name__}")[:160])
            self.state = st
            return st

    def _verify_into(self, st: ShieldState) -> None:
        mode = st.mode
        if mode == "direct":
            if not self.cfg.get("shield", "allow_direct", default=False):
                st.reasons.append("Direct mode is disabled. It exposes your real IP to every service.")
                return
            st.ok = True
            st.warnings.append("UNSHIELDED: your real IP is visible to every service.")
            return
        need_tor, need_vpn, need_proxy = self.has_tor(), self.has_vpn(), mode == "proxy"
        # ---- local pre-flight: NO packets leave the machine in this block
        if need_vpn:
            ads = vpn_adapters(str(self.cfg.get("shield", "vpn_iface_pattern", default="")))
            if ads is None:
                st.warnings.append("VPN adapter heuristic unavailable on this OS; relying on the IP baseline.")
            else:
                st.adapters, st.vpn_adapter = ads, bool(ads)
                if not ads:
                    st.reasons.append("No active VPN adapter detected. Connect your VPN (kill-switch ON).")
            if not self._bget() and self.cfg.get("shield", "require_baseline", default=True):
                st.reasons.append("Real-IP baseline not recorded yet (record it once with the VPN OFF).")
        if need_tor:
            host, port = self._tor_hostport()
            st.tor_port = _tcp_ok(host, port)
            if not st.tor_port:
                st.reasons.append(f"Tor SOCKS proxy not reachable at {host}:{port}.")
        if need_proxy:
            pu = self._custom_proxy()
            u = urlparse(pu) if pu else None
            if not u:
                st.reasons.append("Custom proxy is not configured or malformed.")
            elif not _tcp_ok(u.hostname, u.port):
                st.reasons.append("Custom proxy is not reachable.")
        if st.reasons:
            return  # fail closed before any network proof
        # ---- network proof
        if need_tor:
            j = self._get_json(TOR_CHECK_URL, self.proxy_url("tor", "shield-check"))
            st.tor_exit, st.egress_ip = bool(j.get("IsTor")), str(j.get("IP", ""))
            if not st.tor_exit:
                st.reasons.append("Traffic is NOT exiting through Tor.")
        if need_vpn or need_proxy:
            j = self._get_json(TOR_CHECK_URL, self._custom_proxy() if need_proxy else None)
            st.vpn_egress_ip = str(j.get("IP", ""))
            base = self._bget()
            if base and st.vpn_egress_ip == base:
                st.reasons.append("Your REAL IP is exposed: the VPN/proxy is not carrying traffic.")
            elif not base:
                st.warnings.append("No baseline recorded: VPN verified by adapter only.")
        st.ok = not st.reasons

    def assert_safe(self, route: str, cli_guard: bool = False) -> None:
        st = self.verify()
        if not st.ok:
            raise NetworkUnsafe("; ".join(st.reasons) or "Shield is down.")
        mode = st.mode
        if route == "tor" and not (self.has_tor() and st.tor_exit):
            raise NetworkUnsafe("Tor route is not verified.")
        if route == "vpn" and mode not in ("vpn", "tor_over_vpn"):
            raise NetworkUnsafe("VPN route is not available in the current shield mode.")
        if route == "proxy" and mode != "proxy":
            raise NetworkUnsafe("Proxy route is not active.")
        if route == "direct" and mode != "direct":
            raise NetworkUnsafe("Direct route is not allowed.")
        if cli_guard and mode not in ("vpn", "tor_over_vpn"):
            raise NetworkUnsafe("This tool cannot be proven to honour a proxy; it needs the VPN guard (mode vpn or tor_over_vpn).")
        if self.has_vpn():  # live kill-switch: adapter drop is caught on the very next request
            ads = vpn_adapters(str(self.cfg.get("shield", "vpn_iface_pattern", default="")))
            if ads is not None and not ads:
                self.state.ok = False
                self.state.reasons = ["VPN adapter went down (kill-switch engaged)."]
                raise NetworkUnsafe("VPN adapter went down (kill-switch engaged).")

    def record_baseline(self, force: bool = False, ip: Optional[str] = None) -> str:
        """Store your real egress IP (encrypted in the vault). Do it with the VPN OFF.

        Pass `ip` to type it yourself (no network request at all); otherwise one direct request
        to the Tor Project's check API is made, which shows your real IP to that service once.
        """
        ads = vpn_adapters(str(self.cfg.get("shield", "vpn_iface_pattern", default="")))
        if ip is None:
            if ads and not force:
                raise NetworkUnsafe(f"A VPN adapter looks active ({', '.join(ads)}). Disconnect it, then record the baseline.")
            ip = str(self._get_json(TOR_CHECK_URL, None).get("IP", ""))
        ip = str(ipaddress.ip_address(str(ip).strip()))
        self._bset(ip)
        with self._vlock:
            self.state.checked_at = 0.0
        return mask_ip(ip)

    # ------------------------------------------------------------------ monitor
    def start_monitor(self) -> None:
        if self._thr and self._thr.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(max(10, self.recheck)):
                try:
                    self.verify(force=True)
                except Exception:
                    log.exception("shield monitor error")

        self._thr = threading.Thread(target=loop, name="mot-shield", daemon=True)
        self._thr.start()

    def stop_monitor(self) -> None:
        self._stop.set()


class TorManager:
    """Optional managed Tor: SafeSocks (blocks local-DNS leaks), ClientOnly, no ControlPort."""

    def __init__(self, cfg: C.Config):
        self.cfg = cfg
        self.proc: Optional[subprocess.Popen] = None

    def binary(self) -> Optional[str]:
        exe = "tor.exe" if os.name == "nt" else "tor"
        for cand in (C.BIN / "tor" / exe, C.BIN / exe, shutil.which("tor")):
            if cand and Path(cand).exists():
                return str(cand)
        return None

    def detect(self) -> list[tuple[str, int]]:
        host, _, port = str(self.cfg.get("shield", "tor_socks", default="127.0.0.1:9050")).rpartition(":")
        cands = [(host or "127.0.0.1", int(port or 9050)), ("127.0.0.1", 9050), ("127.0.0.1", 9150)]
        seen, out = set(), []
        for c in cands:
            if c not in seen and _tcp_ok(*c, timeout=1.0):
                out.append(c)
            seen.add(c)
        return out

    def start(self, timeout: int = 120) -> dict:
        found = self.detect()
        if found:
            self.cfg.set("shield", "tor_socks", f"{found[0][0]}:{found[0][1]}")
            return {"ok": True, "msg": f"Tor already running on {found[0][0]}:{found[0][1]} (Tor Browser uses 9150)."}
        exe = self.binary()
        if not exe:
            return {"ok": False, "msg": "Tor not found. Install the Tor Expert Bundle into ./bin/tor/ or start Tor Browser, then press Verify."}
        port = 9050 if not _tcp_ok("127.0.0.1", 9050, 0.5) else 9350
        data_dir, log_file = C.DATA / "tor", C.DATA / "logs" / "tor.log"
        data_dir.mkdir(parents=True, exist_ok=True)
        torrc = C.DATA / "tor" / "torrc"
        q = lambda p: '"' + str(p).replace("\\", "/") + '"'  # noqa: E731
        torrc.write_text(
            f"SocksPort 127.0.0.1:{port} IsolateSOCKSAuth\nSafeSocks 1\nClientOnly 1\nAvoidDiskWrites 1\n"
            f"DataDirectory {q(data_dir)}\nLog notice file {q(log_file)}\n",
            encoding="utf-8",
        )
        kw = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if os.name == "nt":
            kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.proc = subprocess.Popen([exe, "-f", str(torrc)], **kw)
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                return {"ok": False, "msg": "Tor exited early. See logs/tor.log."}
            if _tcp_ok("127.0.0.1", port, 0.5):
                self.cfg.set("shield", "tor_socks", f"127.0.0.1:{port}")
                return {"ok": True, "msg": f"Managed Tor started on 127.0.0.1:{port}."}
            time.sleep(1)
        self.stop()
        return {"ok": False, "msg": "Tor did not become ready in time."}

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
