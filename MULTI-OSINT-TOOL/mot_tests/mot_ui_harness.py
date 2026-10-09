"""MULTI-OSINT-TOOL :: TEST-ONLY harness for the interface. Never imported by the program itself.

It starts the REAL server, vault, orchestrator, audit log, case store and UI files, but
  * replaces the 20 network/CLI connectors by canned results (fake data on reserved example domains and TEST-NET addresses), and
  * pins the network-shield state,
so every screen can be exercised in a headless browser without a single network packet leaving the machine.
"""
from __future__ import annotations

import os
import secrets
import shutil
import socket
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mot_testlib as T  # noqa: E402  (must be first: it points MOT_DATA at a throw-away folder)

import mot_app as A  # noqa: E402
import mot_config as C  # noqa: E402
import mot_connectors_base as B  # noqa: E402
import mot_server as S  # noqa: E402
from mot_connectors_base import Finding  # noqa: E402
from mot_netguard import ShieldState  # noqa: E402

PW = secrets.token_urlsafe(24)  # generated per run: no password literal in the source
FOUND_PW = "found-" + secrets.token_hex(6)  # sample value held back by the canned breach result
FAKE_IP = "203.0.113.9"  # TEST-NET-3 (RFC 5737)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ------------------------------------------------------------------------------------------------ canned results
def _acct(site: str, user: str, conf: float = 0.55, extra: dict | None = None) -> Finding:
    d = {"site": site}
    d.update(extra or {})
    return Finding("account", site, user, url=f"https://{site.lower().replace(' ', '')}.example/{user}", data=d, ents=[("account", f"{site}:{user}", "profile")], confidence=conf)


def canned(conn: B.Connector, target: str, ttype: str, scenario: str) -> B.Result:
    cid, m = conn.id, conn.meta
    user = "janedoe"
    R = conn.res

    if scenario == "blocked" and m.kind in ("api", "cli"):
        return R(B.BLOCKED, error="The network shield is not verified. VPN adapter not found.")
    if scenario == "offline" and m.kind in ("api", "cli"):
        return R(B.OFFLINE, notes=["No connectivity. Open the Cases tab for earlier results."])

    if cid == "sherlock":
        return R(B.OK, "free", findings=[_acct(s, target) for s in ("GitHub", "Reddit", "Keybase", "Mastodon", "Chess", "Medium")] + [Finding("account", "Pinterest (matched a similar name)", target, url=f"https://pinterest.example/{target}", confidence=0.3)])
    if cid == "maigret":
        return R(B.OK, "free", findings=[_acct("GitHub", target, 0.6, {"tags": ["coding"], "profile": {"name": "Jane Doe", "bio": "Builds things"}}), _acct("Reddit", target, 0.6), _acct("Keybase", target, 0.6),
                                         _acct("Gravatar", target, 0.5), _acct("About.me", target, 0.5)])
    if cid == "maltego":
        return R(B.EXPORT, "export", notes=["Maltego has no search API. Save this case as a Maltego file from Cases, then use Import Graph from Table."])
    if cid == "shodan":
        return R(B.NO_KEY, "none", handoff_url=m.key_url, notes=["Shodan needs an API key for this lookup. A free account key works for basic host data."])
    if cid == "spiderfoot":
        return R(B.MISSING, "none", notes=["SpiderFoot is not installed. Install it from Settings, then search again."])
    if cid == "dehashed":
        return R(B.KEY_INVALID, "keyed", error="Key rejected (HTTP 401).")
    if cid == "hibp":
        return R(B.OK, "keyed", findings=[
            Finding("breach", "Example Forum (2019-03-14)", "ExampleForum", data={"pwn_count": 1234567, "data_classes": ["Email addresses", "Passwords", "Usernames"], "verified": True}, ents=[("breach", "Example Forum", "breached_in")], confidence=0.9),
            Finding("breach", "Sample Store (2021-07-02)", "SampleStore", data={"pwn_count": 88211, "data_classes": ["Email addresses", "Names", "Phone numbers"], "verified": True}, ents=[("breach", "Sample Store", "breached_in"), ("phone", "+14155550123", "listed_phone")], confidence=0.9),
            Finding("breach", "Demo Mail (2016-11-30)", "DemoMail", data={"pwn_count": 5400210, "data_classes": ["Email addresses", "Password hashes"], "verified": False}, ents=[("breach", "Demo Mail", "breached_in")], confidence=0.7),
            # a credential record: the password is a `_`-prefixed secret, so the page sees has_secret=True and never the value
            Finding("credential", "Credential record in Example Forum (password held back)", user, data={"_password": FOUND_PW, "user": user, "source": "Example Forum"},
                    ents=[("username", user, "handle")], sensitive=True, confidence=0.85),
        ])
    if cid == "pimeyes":
        return R(B.HANDOFF, "handoff", handoff_url=m.site, notes=["PimEyes has no public API. Upload the photo yourself on their website; MULTI-OSINT-TOOL never sends a face image anywhere."])
    if cid == "epieos":
        return R(B.HANDOFF, "handoff", handoff_url="https://epieos.com/", notes=["Epieos needs your own endpoint details to run from here. Use their website for a one-off check."])
    if cid == "hunter":
        return R(B.PLAN, "keyed", error="Not permitted for this plan or blocked (HTTP 403).")
    if cid == "intelx":
        return R(B.OK, "keyed", findings=[
            Finding("darkweb", "2 record(s) across 3 bucket(s); dark-web buckets: 1", "2", data={"buckets": ["pastes", "leaks.public", "darknet.tor"]}, ents=[("domain", "example.com", "mentioned_on")], sensitive=True, confidence=0.6),
            Finding("leak", "combo_list_2022_part3.txt", "a1b2c3", data={"added": "2022-05-04", "size": "48 MB"}, sensitive=True, confidence=0.5),
            Finding("paste", "Paste on pastebin.example: dump 4411", "4411", url="https://pastebin.example/4411", ents=[("email", "j.doe@example.org", "co-listed")], confidence=0.5),
        ])
    if cid == "virustotal":
        return R(B.OK, "keyed", findings=[
            Finding("reputation", "VirusTotal: 2 malicious / 1 suspicious of 94 engines", "2/94", data={"stats": {"malicious": 2, "suspicious": 1, "harmless": 76, "undetected": 15}}, ents=[("ip", FAKE_IP, "resolves_to")], confidence=0.8),
            Finding("subdomains", "4 subdomain(s) known to VirusTotal", "4", data={"subdomains": ["mail.example.com", "vpn.example.com", "staging.example.com", "files.example.com"]}, ents=[("domain", "vpn.example.com", "subdomain"), ("domain", "staging.example.com", "subdomain")], confidence=0.7),
        ])
    if cid == "urlscan":
        return R(B.EMPTY, "free", notes=["No scans found for this target."])
    if cid == "github":
        return R(B.OK, "free", findings=[
            Finding("account", "GitHub: janedoe (Jane Doe)", user, url="https://github.example/janedoe", data={"public_repos": 14, "followers": 52, "created": "2013-02-11", "location": "Lisbon"}, ents=[("username", user, "handle"), ("org", "Example Holdings", "employer")], confidence=0.75),
            Finding("email", "j.doe@example.org", "j.doe@example.org", data={"name": "Jane Doe", "seen_in": "public push events"}, ents=[("email", "j.doe@example.org", "commit_author")], confidence=0.6),
            Finding("commit", "Commit in janedoe/notes", "9f2c1ab04e", url="https://github.example/janedoe/notes/commit/9f2c1ab04e", confidence=0.5),
        ])
    if cid == "hudsonrock":
        return R(B.OK, "free", findings=[
            Finding("infostealer", "1 infostealer infection record(s) linked to this email", "1", data={"total": 1}, ents=[("username", user, "handle")], sensitive=True, confidence=0.8),
            Finding("infostealer", "RedLine, 2024-01-18", "2024-01-18", data={"stealer_family": "RedLine", "computer_name": "DESKTOP-4K7Q", "operating_system": "Windows 10", "ip": FAKE_IP}, ents=[("ip", FAKE_IP, "infected_host")], sensitive=True, confidence=0.7),
        ])
    if cid == "wayback":
        return R(B.OK, "free", findings=[
            Finding("archive", "128 archived URL(s); first seen 20110403, last 20250812", "128", data={"first": "2011-04-03", "last": "2025-08-12"}, confidence=0.9),
            Finding("url", "https://example.com/team/jane-doe", "https://example.com/team/jane-doe", url="https://web.archive.org/web/2019/https://example.com/team/jane-doe", data={"timestamp": "20190611", "status": "200"}, ents=[("url", "https://example.com/team/jane-doe", "archived")], confidence=0.6),
        ])
    if cid == "holehe":
        return R(B.OK, "free", findings=[Finding("account", f"Registered on {s}", target, data={"service": s, "rate_limited": False}, ents=[("account", f"{s}:{target}", "registered_on"), ("domain", s, "service")], confidence=0.55) for s in ("spotify.com", "adobe.com", "wordpress.com")])
    if cid == "theharvester":
        return R(B.ERROR, "free", error="The tool exited with an error (code 1). Its sources may be unreachable through the shield.")
    if cid == "phoneinfoga":
        return R(B.OK, "local", findings=[Finding("phone", "+1 415-555-0123: valid (US, mobile)", "+14155550123", data={"international": "+1 415-555-0123", "region": "US", "line_type": "mobile", "valid": True}, ents=[("phone", "+14155550123", "subject")], confidence=0.8)])
    if cid == "ahmia":
        return R(B.RATE, "free", error="Rate limited (HTTP 429).")
    if cid == "rdap":  # the parser is the program's own; the fixture is an RFC 9083-shaped example, not a live answer
        import mot_conn_intel as MI
        return R(B.OK, "free", findings=MI.parse_rdap(MI.RDAP_FIXTURE, target))
    if cid == "abuseipdb":
        return R(B.NO_KEY, "none", notes=["Add an AbuseIPDB key in Settings."])
    if cid == "greynoise":
        return R(B.EMPTY, "free", notes=["GreyNoise has no record of this address."])
    return R(B.EMPTY, "free")


# per-connector pause (seconds, before scaling) so the dial visibly runs
DELAY = {"sherlock": 1.4, "maigret": 2.2, "maltego": 0.05, "shodan": 0.1, "spiderfoot": 0.1, "dehashed": 0.5, "hibp": 0.7, "pimeyes": 0.05, "epieos": 0.1, "hunter": 0.4, "intelx": 1.0,
         "virustotal": 0.9, "urlscan": 0.6, "github": 0.8, "hudsonrock": 0.6, "wayback": 1.1, "holehe": 1.6, "theharvester": 1.3, "phoneinfoga": 0.2, "ahmia": 0.3, "rdap": 0.2, "abuseipdb": 0.2, "greynoise": 0.3}


class UiHarness:
    def __init__(self, delay: float = 1.0, shield_ok: bool = True):
        self.secret = os.urandom(32)
        self.delay = delay
        self.scenario = "normal"
        self.shield_ok = shield_ok
        self.shield_reasons: list[str] = []
        self.shield_mode = "tor_over_vpn"
        self.app: A.App | None = None
        self.srv: S.MotServer | None = None
        self.port = 0

    # ---- lifecycle
    def start(self) -> str:
        for sub in ("vault", "cases", "recovery", "logs"):
            shutil.rmtree(C.DATA / sub, ignore_errors=True)
        C.ensure_dirs()
        self.app = A.App()
        self.app.tune["kdf"] = T.FAST_KDF
        self._patch_guard()
        self._patch_connectors()
        self.app.boot()
        self.port = free_port()
        self.srv = S.MotServer(self.app, self.port, self.secret)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.srv.start_idle_watchdog()
        return self.base

    def stop(self) -> None:
        if self.srv:
            self.srv.shutdown()
            self.srv.server_close()
        if self.app:
            self.app.shutdown()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def launch_token(self) -> str:
        return S.Sessions(self.secret).mint_launch()

    def reset_limits(self) -> None:
        if self.srv:
            self.srv.limiter._hits.clear()

    # ---- fakes
    def _patch_guard(self) -> None:
        g = self.app.guard
        h = self

        def verify(force: bool = False) -> ShieldState:
            st = ShieldState(mode=g.mode, checked_at=time.time())
            st.ok = h.shield_ok
            st.tor_port, st.tor_exit, st.vpn_adapter = True, h.shield_ok, h.shield_ok
            st.adapters = ["wg0"] if h.shield_ok else []
            st.egress_ip, st.vpn_egress_ip = ("185.220.101.7", "193.32.126.4") if h.shield_ok else ("", "")
            st.reasons = [] if h.shield_ok else (h.shield_reasons or ["No VPN adapter was found, so Tor is not hidden from your ISP."])
            st.warnings = []
            g.state = st
            return st

        g.verify = verify  # type: ignore[method-assign]
        g.state = ShieldState(mode=g.mode)

    def _patch_connectors(self) -> None:
        h = self

        for cid, conn in B.REGISTRY.items():
            def run(target, ttype, ctx, _c=conn):
                t0 = time.time()
                if ctx.cancel.wait(DELAY.get(_c.id, 0.3) * h.delay):
                    return _c.res(B.CANCELLED)
                r = canned(_c, target, ttype, h.scenario)
                r.elapsed = round(time.time() - t0, 2)
                for f in r.findings:
                    f.source = _c.meta.name
                return r

            conn.run = run  # type: ignore[method-assign]

    def set_shield(self, ok: bool, reasons: list[str] | None = None) -> None:
        self.shield_ok = ok
        self.shield_reasons = reasons or []
        self.app.guard.verify(force=True)


if __name__ == "__main__":  # manual use: print a one-time launch form you can open in a browser
    hx = UiHarness()
    base = hx.start()
    tok = hx.launch_token()
    html = f'<form method="post" action="{base}/mot-launch"><input name="t" value="{urllib.parse.quote(tok)}"><button>Open</button></form>'
    print(base, "\n", html)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        hx.stop()
