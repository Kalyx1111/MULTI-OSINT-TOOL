"""MULTI-OSINT-TOOL :: CLI connectors (flags AND output formats verified against the installed versions' source code, Oct 2026).

Pinned, isolated installs live in libs/tools/<id>/ (see mot_tools.py). Safety choices that matter:
  * Sherlock   --local        : otherwise it fetches its site list from GitHub, outside the proxy.
               runner wrapper : Sherlock 0.16.2 ALSO calls api.github.com at every start (an update check) and that request ignores --proxy.
                                Traced on a stock run: DNS lookup + TCP connect to api.github.com. MOT's shield already exports
                                HTTP(S)_PROXY to every tool, but the runner removes the call outright (no reliance on that variable or on
                                PySocks, no GitHub fingerprint on the exit node, no 10 s wait offline). It disables `requests.get`, which
                                nothing else uses once --local is set. Traced through the runner + a SOCKS5 server: the process opened one
                                connection (to the proxy) and handed the site's HOSTNAME to it (proxy-side DNS); Maigret does the same.
  * Maigret    --no-autoupdate: same reason. --no-recursion keeps the scope on YOUR target.
  * Holehe     -NP            : never triggers password-recovery e-mails to the target.
               runner wrapper : stock Holehe 1.61 asks PyPI at EVERY start (even for --help) and silently runs
                                `pip install --upgrade holehe` when a newer version exists. That defeats version pinning and the
                                integrity manifest, so MOT starts it through a 5-line runner that disables only that function.
  * SpiderFoot -u passive     : never touches the target's own infrastructure from your IP.
  * theHarvester passive keyless sources only; no DNS brute force, no takeover/screenshot probes.
  * Every tool runs with a private HOME inside mot_data/tmp, a minimal environment and no shell.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import sys
from pathlib import Path

import mot_config as C
from mot_connectors_base import (ANSI, EMPTY, ERROR, MISSING, OK, TIMEOUT, Connector, Ctx, Finding, Meta, Result, as_list,
                                 register)

USER_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,38}$")
DOMAIN_OK = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
EMAIL_OK = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")


def _s(x, n: int = 300) -> str:
    return "" if x is None else str(x)[:n]


def private_home(cid: str) -> tuple[Path, dict]:
    home = C.DATA / "tmp" / f"home-{cid}"
    home.mkdir(parents=True, exist_ok=True)
    env = {"HOME": str(home), "USERPROFILE": str(home), "APPDATA": str(home / "AppData"), "LOCALAPPDATA": str(home / "AppData"),
           "XDG_CONFIG_HOME": str(home / ".config"), "XDG_CACHE_HOME": str(home / ".cache"), "XDG_DATA_HOME": str(home / ".local" / "share")}
    return home, env


def work_dir(ctx: Ctx, cid: str) -> Path:
    """One scratch folder per tool AND per search: two searches running at once must never delete each other's reports.
    The orchestrator removes every `*-<job id>` folder when the search ends."""
    d = ctx.tmp_dir / f"{cid}-{ctx.job_id}"
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir(parents=True, exist_ok=True)
    return d


def missing(conn: Connector, hint: str = "") -> Result:
    return conn.res(MISSING, "local", error=f"{conn.meta.name} is not installed.", notes=[hint or f"Install it with: python mot_main.py tools --install {conn.id}"],
                    handoff_url=conn.meta.site)


def interpreter_for(script: str):
    """The Python that owns a console script: the shebang line (venv, pipx, system installs), else a python next to it (Windows venv)."""
    sp = Path(script)
    try:
        with open(sp, "rb") as fh:
            first = fh.readline(300)
        if first.startswith(b"#!"):
            parts = first[2:].decode("utf-8", "replace").strip().split()
            if parts and Path(parts[0]).is_file():
                return parts[0]
    except OSError:
        pass
    for name in ("python.exe", "python", "python3"):
        cand = sp.resolve().parent / name
        if cand.is_file():
            return str(cand)
    return None


# =============================================================================== Sherlock
SHERLOCK_RUNNER = ("import sys\n"
                   "import requests\n"
                   "def _blocked(*a, **k):\n"  # the stock update check (api.github.com) ignores --proxy; with --local nothing else calls requests.get
                   "    raise requests.exceptions.ConnectionError('blocked by MULTI-OSINT-TOOL: this request would bypass the privacy shield')\n"
                   "requests.get = _blocked\n"
                   "import sherlock_project.sherlock as s\n"
                   "sys.argv[0] = 'sherlock'\n"
                   "s.main()\n")
SHERLOCK_LINE = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://\S+)\s*$")


def parse_sherlock(out: str, username: str) -> list[Finding]:
    seen, res = set(), []
    for line in ANSI.sub("", out).splitlines():
        m = SHERLOCK_LINE.match(line.strip())
        if m and m.group(2) not in seen:
            seen.add(m.group(2))
            res.append(Finding("account", f"{m.group(1)}", username, url=m.group(2), data={"site": m.group(1)},
                               ents=[("url", m.group(2), "profile"), ("account", f"{m.group(1)}:{username}", "registered_on")], confidence=0.55))
    return res


@register
class Sherlock(Connector):
    meta = Meta(id="sherlock", name="Sherlock", category="Username", kind="cli", targets=("username",),
                free_mode="Open source, runs locally (400+ sites)", site="https://github.com/sherlock-project/sherlock",
                docs_url="https://github.com/sherlock-project/sherlock", route="tor", tool_names=("sherlock",), install="pip:sherlock-project==0.16.2",
                note="A matching username is NOT proof of the same person. Many sites block Tor exits (false negatives).")

    def free(self, target, ttype, ctx):
        if not USER_OK.match(target):
            return self.res(ERROR, error="Username contains characters Sherlock cannot take safely.")
        exe = ctx.tool(self.id, self.meta.tool_names)
        if not exe:
            return missing(self)
        py = interpreter_for(exe)
        if not py:
            return missing(self, "Sherlock contacts GitHub for an update check outside the proxy; MOT only runs it through its runner, which needs to know the copy's Python. "
                                 "Reinstall the isolated copy with: python mot_main.py tools --install sherlock")
        route = ctx.route(self.meta)
        proxy = ctx.guard.tool_proxy(route, f"{ctx.job_id}-{self.id}")
        _, env = private_home(self.id)
        argv = [py, "-c", SHERLOCK_RUNNER, "--local", "--print-found", "--no-color", "--timeout", "20"] + (["--proxy", proxy] if proxy else []) + ["--", target]
        r = ctx.cli(self.meta, argv, timeout=ctx.cfg.get("search", "connector_timeout", default=90) + 120, route=route, cwd=work_dir(ctx, self.id), extra_env=env)
        f = parse_sherlock(r.out, target)
        st = OK if f else (TIMEOUT if r.timed_out else EMPTY)
        return self.res(st, "local", findings=f, notes=["Username existence only; verify before attributing."] + (["Timed out; partial results shown."] if r.timed_out else []))

    def selftest(self):
        # captured from a real Sherlock 0.16.2 run (cat -v: ^M = carriage return, ^[ = escape)
        real = ("A problem occurred while checking for an update: blocked by MULTI-OSINT-TOOL: this request would bypass the privacy shield\n"
                "[*] Checking username alice on:\n\r\n[+] FakeSite: http://127.0.0.1:18765/user/alice\n\n[*] Search completed with 1 results\n\n"
                "Go deeper than a username. Explore public profiles and export your findings.\n"
                "Try OSINTSearch: \x1b]8;;https://osintsearch.org/go/sherlock\x1b\\https://osintsearch.org\x1b]8;;\x1b\\\n")
        f = parse_sherlock(real, "alice")
        ok = len(f) == 1 and f[0].url == "http://127.0.0.1:18765/user/alice" and f[0].data.get("site") == "FakeSite"
        ok = ok and parse_sherlock("[*] Checking username x on:\n[-] Foo: Not Found!\n", "x") == []
        try:
            compile(SHERLOCK_RUNNER, "sherlock_runner", "exec")
        except SyntaxError:
            ok = False
        return [] if ok else ["Sherlock parser or runner failed"]


# =============================================================================== Maigret
def _listish(v, limit: int = 5) -> list[str]:
    """Maigret stores some scraped fields as a real list and others as the TEXT of a list ("['https://a', 'https://b']").
    Third-party text: parsed with ast.literal_eval (data only, never executed) behind a size cap."""
    items: list = []
    if isinstance(v, list):
        items = v
    elif isinstance(v, str) and v.strip():
        t = v.strip()
        if t.startswith("[") and len(t) <= 4000:
            try:
                parsed = ast.literal_eval(t)
                items = parsed if isinstance(parsed, list) else []
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                items = []
        elif not t.startswith("["):
            items = [t]
    return [_s(x, 200) for x in items if isinstance(x, (str, int)) and str(x).strip()][:limit]


def parse_maigret(report: dict, username: str) -> list[Finding]:
    """`-J simple` report: {site: {url_user, status: {ids, tags, ...}, site: {tags, ...}, ids_usernames, ids_links, ...}} for CLAIMED sites only."""
    out = []
    for site, d in list(report.items())[:200]:
        if not isinstance(d, dict):
            continue
        st = d.get("status") if isinstance(d.get("status"), dict) else {}
        url = _s(d.get("url_user") or st.get("url"))
        ids = st.get("ids") if isinstance(st.get("ids"), dict) else (d.get("ids_data") if isinstance(d.get("ids_data"), dict) else {})
        ents = [("url", url, "profile"), ("account", f"{site}:{username}", "registered_on")]
        for k in ("username", "uid"):
            if ids.get(k) and isinstance(ids[k], (str, int)):
                ents.append(("alias", _s(ids[k], 80), "profile_field"))
        for k in ("fullname", "name"):
            if ids.get(k) and isinstance(ids[k], str):
                ents.append(("person", _s(ids[k], 80), "profile_field"))
                break
        if isinstance(ids.get("location"), str) and ids["location"].strip():
            ents.append(("location", _s(ids["location"], 80), "profile_field"))
        uname_map = d.get("ids_usernames") if isinstance(d.get("ids_usernames"), dict) else {}
        for u in list(uname_map)[:5]:
            if isinstance(u, str) and u and u.lower() != username.lower():
                ents.append(("alias", _s(u, 80), "other_username_on_profile"))
        links = _listish(ids.get("links")) + _listish(d.get("ids_links")) + _listish(ids.get("website"))
        for link in dict.fromkeys(links):
            ents.append(("url", link, "linked_from_profile"))
        tags = (d.get("site") or {}).get("tags") if isinstance(d.get("site"), dict) else None
        tags = tags or st.get("tags")
        out.append(Finding("account", site, username, url=url, data={"tags": as_list(tags)[:6], "profile": {k: _s(v, 160) for k, v in list(ids.items())[:12] if not isinstance(v, (dict, list))}},
                           ents=ents, confidence=0.6 if ids else 0.5))
    return out


@register
class Maigret(Connector):
    meta = Meta(id="maigret", name="Maigret", category="Username", kind="cli", targets=("username",),
                free_mode="Open source, runs locally (3000+ sites, profile data extraction)", site="https://github.com/soxoj/maigret",
                docs_url="https://maigret.readthedocs.io/", route="tor", tool_names=("maigret",), install="pip:maigret==0.6.6",
                note="Recursion disabled on purpose: MOT searches only the identifier you give it.")

    def free(self, target, ttype, ctx):
        if not USER_OK.match(target):
            return self.res(ERROR, error="Username contains characters Maigret cannot take safely.")
        exe = ctx.tool(self.id, self.meta.tool_names)
        if not exe:
            return missing(self)
        route = ctx.route(self.meta)
        proxy = ctx.guard.tool_proxy(route, f"{ctx.job_id}-{self.id}")
        wd = work_dir(ctx, self.id)
        _, env = private_home(self.id)
        argv = [exe, "--no-autoupdate", "--no-color", "--no-progressbar", "--no-recursion", "--timeout", "20", "--retries", "1", "-n", "40",
                "--top-sites", "500", "-J", "simple", "--folderoutput", str(wd)] + (["--proxy", proxy] if proxy else []) + ["--", target]
        r = ctx.cli(self.meta, argv, timeout=ctx.cfg.get("search", "connector_timeout", default=90) + 180, route=route, cwd=wd, extra_env=env)
        rep = next(iter(sorted(wd.glob("*_simple.json"))), None) or next(iter(sorted(wd.glob("*.json"))), None)
        f: list[Finding] = []
        if rep:
            try:
                f = parse_maigret(json.loads(rep.read_text(encoding="utf-8")), target)
            except ValueError:
                return self.res(ERROR, "local", error="Maigret wrote an unreadable report.")
        st = OK if f else (TIMEOUT if r.timed_out else EMPTY)
        return self.res(st, "local", findings=f, notes=["Top 500 sites by rank. Matching names can belong to different people."])

    def selftest(self):
        real = {"GitHub": {"username": "x", "url_main": "https://github.com", "url_user": "https://github.com/x", "http_status": 200, "is_similar": False, "rank": 10,
                           "status": {"username": "x", "site_name": "GitHub", "url": "https://github.com/x", "status": "Claimed", "tags": ["coding"],
                                      "ids": {"username": "x", "uid": "1", "fullname": "Ex Ample", "location": "Paris", "links": "['https://x.dev', 'https://x.dev/blog']"}},
                           "site": {"tags": ["coding"], "urlMain": "https://github.com"}, "ids_usernames": {"x2": "username"}, "ids_links": ["https://x.dev"]}}
        f = parse_maigret(real, "x")
        ents = {(t, v) for t, v, _ in f[0].ents} if f else set()
        ok = bool(f) and f[0].url and ("person", "Ex Ample") in ents and ("url", "https://x.dev/blog") in ents and ("alias", "x2") in ents and ("location", "Paris") in ents
        safe = (_listish("[__import__('os').system('x')]") == [] and _listish("['a'," + "[" * 3000) == [] and _listish("https://x.dev") == ["https://x.dev"]
                and _listish("['a', 'b']") == ["a", "b"])
        return [] if ok and safe else ["Maigret parser failed"]


# =============================================================================== Holehe
HOLEHE_RUNNER = ("import sys\n"
                 "import holehe.core as c\n"
                 "c.check_update = lambda: None\n"  # the stock function queries PyPI and runs `pip install --upgrade holehe` on every start
                 "sys.argv[0] = 'holehe'\n"
                 "c.main()\n")


HOLEHE_LINE = re.compile(r"^\[\+\]\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:\s+(.{1,200}))?$", re.I)  # trailing text = recovery hints


def parse_holehe(out: str, email: str) -> list[Finding]:
    sites: dict[str, str] = {}
    for line in ANSI.sub("", out).replace("\r", "\n").splitlines():
        m = HOLEHE_LINE.match(line.strip())
        if m and m.group(1).lower() not in sites:
            sites[m.group(1).lower()] = (m.group(2) or "").strip(" /")
    res = []
    for s_, hint in sites.items():
        data = {"site": s_}
        if hint:
            data["recovery_hint"] = hint[:160]  # partially masked e-mail / phone shown by the site's recovery flow
        res.append(Finding("account", f"Registered on {s_}", email, data=data, ents=[("account", f"{s_}:{email}", "registered_on"), ("domain", s_, "service")],
                           confidence=0.7))
    return res


@register
class Holehe(Connector):
    meta = Meta(id="holehe", name="Holehe", category="Email intelligence", kind="cli", targets=("email",),
                free_mode="Open source, runs locally (checks ~120 sites without alerting the owner)", site="https://github.com/megadose/holehe",
                docs_url="https://github.com/megadose/holehe", route="vpn", cli_guard=True, tool_names=("holehe",), install="pip:holehe==1.61",
                note="Runs with -NP (no password-recovery requests). Needs the VPN guard: the tool cannot be proven to honour Tor.")

    def free(self, target, ttype, ctx):
        if not EMAIL_OK.match(target):
            return self.res(ERROR, error="Email format rejected.")
        exe = ctx.tool(self.id, self.meta.tool_names)
        if not exe:
            return missing(self)
        _, env = private_home(self.id)
        py = interpreter_for(exe)
        if not py:
            return missing(self, "Holehe checks PyPI and silently upgrades itself on every start; MOT will only run it through its runner, which needs to know the copy's Python. "
                                 "Reinstall the isolated copy with: python mot_main.py tools --install holehe")
        argv = [py, "-c", HOLEHE_RUNNER, "--only-used", "--no-color", "--no-clear", "-NP", "-T", "15", "--", target]
        r = ctx.cli(self.meta, argv, timeout=ctx.cfg.get("search", "connector_timeout", default=90) + 60, route=ctx.route(self.meta, "vpn"), cwd=work_dir(ctx, self.id), extra_env=env)
        f = parse_holehe(r.out, target)
        return self.res(OK if f else (TIMEOUT if r.timed_out else EMPTY), "local", findings=f, notes=["Presence of an account is not proof of activity or identity."])

    def selftest(self):
        f = parse_holehe("[+] Email used, [-] Email not used, [x] Rate limit\n[+] github.com\n[-] nope.com\n[+] adobe.com j***@gmail.com / +33*****12\n", "a@b.co")
        ok = len(f) == 2 and f[1].data.get("recovery_hint", "").startswith("j***@gmail.com") and not f[0].data.get("recovery_hint")
        try:
            compile(HOLEHE_RUNNER, "holehe_runner", "exec")
        except SyntaxError:
            ok = False
        return [] if ok else ["Holehe parser or runner failed"]


# =============================================================================== theHarvester
def parse_harvester(j: dict, domain: str) -> list[Finding]:
    out: list[Finding] = []
    emails = sorted({_s(e).lower() for e in as_list(j.get("emails")) if "@" in _s(e)})
    hosts = sorted({_s(h).split(":")[0].lower() for h in as_list(j.get("hosts")) if h})
    ips = sorted({_s(i) for i in as_list(j.get("ips")) if i})
    if hosts:
        out.append(Finding("subdomains", f"{len(hosts)} host(s) discovered passively for {domain}", str(len(hosts)), data={"hosts": hosts[:200]},
                           ents=[("hostname", h, "subdomain") for h in hosts[:150]], confidence=0.7))
    for e in emails[:100]:
        out.append(Finding("email", e, e, ents=[("email", e, "found_for_domain")], confidence=0.6))
    if ips:
        out.append(Finding("ips", f"{len(ips)} IP address(es)", str(len(ips)), data={"ips": ips[:100]}, ents=[("ip", i, "resolves") for i in ips[:60]], confidence=0.6))
    asns = sorted({_s(a, 40) for a in as_list(j.get("asns")) if a})
    if asns:
        out.append(Finding("asn", f"{len(asns)} autonomous system(s)", str(len(asns)), data={"asns": asns[:60]}, ents=[("asn", a, "network") for a in asns[:40]], confidence=0.6))
    urls = [_s(u, 200) for u in as_list(j.get("interesting_urls"))][:30]
    if urls:
        out.append(Finding("url", f"{len(urls)} interesting URL(s)", str(len(urls)), data={"urls": urls}, ents=[("url", u, "interesting") for u in urls], confidence=0.5))
    return out


@register
class TheHarvester(Connector):
    meta = Meta(id="theharvester", name="theHarvester", category="Domain recon", kind="cli", targets=("domain",),
                free_mode="Open source, passive keyless sources only", site="https://github.com/laramies/theHarvester",
                docs_url="https://github.com/laramies/theHarvester", route="vpn", cli_guard=True, tool_names=("theHarvester", "theharvester"),
                install="zip:https://github.com/laramies/theHarvester/archive/refs/tags/4.9.2.zip",
                note="Passive sources only; no DNS brute force, takeover checks or screenshots (those touch the target directly).")

    def free(self, target, ttype, ctx):
        if not DOMAIN_OK.match(target):
            return self.res(ERROR, error="Domain format rejected.")
        exe = ctx.tool(self.id, self.meta.tool_names)
        if not exe:
            return missing(self)
        src = str(ctx.cfg.get("theharvester", "sources", default=""))
        if not re.fullmatch(r"[a-zA-Z0-9,_-]{1,300}", src):
            return self.res(ERROR, error="Invalid theHarvester source list in settings.")
        wd = work_dir(ctx, self.id)
        _, env = private_home(self.id)
        argv = [exe, "-d", target, "-b", src, "-l", "200", "-q", "-f", "mot_out"]
        r = ctx.cli(self.meta, argv, timeout=ctx.cfg.get("search", "connector_timeout", default=90) + 150, route=ctx.route(self.meta, "vpn"), cwd=wd, extra_env=env)
        jf = wd / "mot_out.json"
        if not jf.exists():
            return self.res(TIMEOUT if r.timed_out else EMPTY, "local", notes=["No output file produced."] + ([r.err[-200:]] if r.err and not r.timed_out else []))
        try:
            f = parse_harvester(json.loads(jf.read_text(encoding="utf-8")), target)
        except ValueError:
            return self.res(ERROR, "local", error="theHarvester wrote unreadable JSON.")
        return self.res(OK if f else EMPTY, "local", findings=f)

    def selftest(self):
        f = parse_harvester({"emails": ["a@x.com"], "hosts": ["www.x.com:1.2.3.4"], "ips": ["1.2.3.4"]}, "x.com")
        return [] if len(f) == 3 else ["theHarvester parser failed"]


# =============================================================================== SpiderFoot
# SpiderFoot 4.0 downloads the public-suffix (TLD) list from publicsuffix.org at the start of EVERY scan and CRASHES its scanner
# process when that download fails, while its main process then waits for ever (verified by running it without network).
# The `publicsuffixlist` package that SpiderFoot already depends on ships the same list, so MOT seeds SpiderFoot's own cache
# with it: no network call at start-up, no crash, and no hang.
SF_SEED = ("import hashlib, os\n"
           "import publicsuffixlist as p\n"
           "src = os.path.join(os.path.dirname(p.__file__), 'public_suffix_list.dat')\n"
           "dst = os.environ['SPIDERFOOT_CACHE']\n"
           "os.makedirs(dst, exist_ok=True)\n"
           "data = open(src, encoding='utf-8').read()\n"
           "assert len(data) > 10000\n"
           "open(os.path.join(dst, hashlib.sha224(b'internet_tlds').hexdigest()), 'w', encoding='utf-8').write(data)\n")

# Order matters: SpiderFoot names risky findings "Malicious IP Address", "Blacklisted Internet Name" ..., so risk must be tested BEFORE the entity names.
SF_MAP = [("malicious", "risk"), ("blacklisted", "risk"), ("vulnerab", "risk"), ("leaked", "leak"), ("compromised", "leak"), ("email address", "email"),
          ("internet name", "hostname"), ("domain name", "domain"), ("ip address", "ip"), ("username", "username"), ("phone number", "phone"),
          ("account on external site", "account"), ("linked url", "url"), ("human name", "person"), ("hash", "hash"), ("social media", "account")]


def parse_sf_json(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []
    m = re.search(r"\[\s*[\{\]]", text)  # the JSON array starts "[{" (or "[]"): a log line such as "[WARNING] ..." must not be mistaken for it
    body = text[m.start():] if m else text
    for cand in (body, body.rstrip().rstrip(",") + "]", body[: body.rfind("}") + 1] + "]"):
        try:
            v = json.loads(cand)
            return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []
        except ValueError:
            continue
    return []


def parse_spiderfoot(events: list, target: str) -> list[Finding]:
    groups: dict[str, list[str]] = {}
    for e in events:
        t, data = _s(e.get("type")).lower(), _s(e.get("data"), 240)
        if not data or t in ("", "root") or _s(e.get("module"), 40).lower() == "spiderfoot ui":
            continue  # "SpiderFoot UI" events are the scan's own seed (your target echoed back), not discoveries
        kind = next((v for k, v in SF_MAP if k in t), "other")
        bucket = groups.setdefault(f"{kind}|{_s(e.get('type'))}", [])
        if data not in bucket:
            bucket.append(data)
    out = []
    for key, vals in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:60]:
        kind, label = key.split("|", 1)
        ents = [(kind, v, "spiderfoot") for v in vals[:40]] if kind not in ("other", "risk", "leak") else []
        out.append(Finding("risk" if kind in ("risk", "leak") else "recon", f"{label}: {len(vals)}", str(len(vals)), data={"samples": vals[:25]}, ents=ents,
                           sensitive=kind == "leak", confidence=0.55))
    return out


@register
class SpiderFoot(Connector):
    meta = Meta(id="spiderfoot", name="SpiderFoot", category="Recon automation", kind="cli", targets=("domain", "ip", "email", "username", "phone"),
                free_mode="Open source 4.0, passive use-case (200+ modules)", site="https://www.spiderfoot.net", key_url="https://www.spiderfoot.net/hx/",
                docs_url="https://github.com/smicallef/spiderfoot", route="vpn", cli_guard=True, tool_names=("sf.py", "spiderfoot"),
                install="zip:https://github.com/smicallef/spiderfoot/archive/refs/tags/v4.0.zip",
                note="Passive only. SpiderFoot keeps its own module API keys in its own database (outside the MOT vault). HX (paid cloud) has no integrated API here: Research required.")

    def _python(self, script: str) -> str:
        base = Path(script).resolve().parent
        for cand in (base.parent / "venv" / "bin" / "python", base.parent / "venv" / "Scripts" / "python.exe", base / "venv" / "bin" / "python"):
            if cand.exists():
                return str(cand)
        return sys.executable

    def free(self, target, ttype, ctx):
        exe = ctx.tool(self.id, self.meta.tool_names)
        if not exe:
            return missing(self, "Install SpiderFoot 4.0 with: python mot_main.py tools --install spiderfoot")
        if ttype == "username" and not USER_OK.match(target):
            return self.res(ERROR, error="Username rejected.")
        t = f'"{target}"' if ttype == "username" else target
        # SpiderFoot keeps every scan in its own SQLite database. A private, per-run home means no scan data from one target
        # can linger next to the next target, and it is deleted as soon as the run ends.
        home, env = private_home(f"{self.id}-{ctx.job_id}")
        env.update({"SPIDERFOOT_DATA": str(home / "sf-data"), "SPIDERFOOT_CACHE": str(home / "sf-cache")})
        py = self._python(exe)
        base = [py, exe] if exe.endswith(".py") else [exe]
        try:
            if exe.endswith(".py"):
                seed = ctx.cli(self.meta, [py, "-c", SF_SEED], timeout=60, route=ctx.route(self.meta, "vpn"), cwd=work_dir(ctx, self.id), extra_env=env)
                if seed.rc != 0:
                    return self.res(ERROR, "local", error="Could not prepare SpiderFoot's TLD list (is its environment complete?). Reinstall it from Settings > Tools.")
            argv = base + ["-s", t, "-u", "passive", "-o", "json", "-q", "-max-threads", "8"]
            r = ctx.cli(self.meta, argv, timeout=max(240, ctx.cfg.get("search", "connector_timeout", default=90) * 3), route=ctx.route(self.meta, "vpn"), cwd=work_dir(ctx, self.id), extra_env=env)
        finally:
            shutil.rmtree(home, ignore_errors=True)
        f = parse_spiderfoot(parse_sf_json(r.out), target)
        st = OK if f else (TIMEOUT if r.timed_out else EMPTY)
        return self.res(st, "local", findings=f, notes=["Passive modules only (no direct contact with the target)."] + (["Timed out; partial results shown."] if r.timed_out else []))

    def selftest(self):
        raw = ('[WARNING] noise before the array\n[{"generated": 1, "type": "Email Address", "data": "a@x.com", "module": "m"},\n'
               '{"type": "Malicious IP Address", "data": "1.2.3.4 [AbuseIPDB]"},\n{"type": "Internet Name", "data": "www.x.com"}\n]')
        ev = parse_sf_json(raw)
        f = parse_spiderfoot(ev, "x.com")
        risk = [x for x in f if x.kind == "risk"]
        ok = len(ev) == 3 and len(f) == 3 and len(risk) == 1 and not any(e[0] == "ip" for x in risk for e in x.ents)
        # captured from a real SpiderFoot 4.0 run (-s example.de -u passive -o json): two seed events (module "SpiderFoot UI") + one discovery
        real = ('[{"generated": 1791128918, "type": "Internet Name", "data": "example.de", "module": "SpiderFoot UI", "source": "example.de"},\n'
                '{"generated": 1791128918, "type": "Domain Name", "data": "example.de", "module": "SpiderFoot UI", "source": "example.de"},\n'
                '{"generated": 1791128918, "type": "Country Name", "data": "Germany", "module": "sfp_countryname", "source": "example.de"}]')
        rf = parse_spiderfoot(parse_sf_json(real), "example.de")
        ok = ok and len(rf) == 1 and rf[0].title.startswith("Country Name") and rf[0].data["samples"] == ["Germany"]
        return [] if ok and parse_sf_json("[]") == [] and parse_sf_json('[{"type": "Email Address", "data": "a@x.com"}') else ["SpiderFoot parser failed"]


# =============================================================================== PhoneInfoga + libphonenumber
def analyse_phone(number: str) -> dict:
    import phonenumbers
    from phonenumbers import PhoneNumberFormat as F
    from phonenumbers import PhoneNumberType as T
    from phonenumbers import carrier, geocoder, timezone

    n = phonenumbers.parse(number, None)
    kinds = {v: k for k, v in vars(T).items() if isinstance(v, int) and k.isupper()}
    return {"valid": phonenumbers.is_valid_number(n), "possible": phonenumbers.is_possible_number(n), "e164": phonenumbers.format_number(n, F.E164),
            "international": phonenumbers.format_number(n, F.INTERNATIONAL), "national": phonenumbers.format_number(n, F.NATIONAL),
            "country_code": n.country_code, "region": phonenumbers.region_code_for_number(n) or "", "location": geocoder.description_for_number(n, "en"),
            "carrier_original": carrier.name_for_number(n, "en"), "line_type": kinds.get(phonenumbers.number_type(n), "UNKNOWN").replace("_", " ").title(),
            "timezones": list(timezone.time_zones_for_number(n))}


@register
class PhoneInfoga(Connector):
    meta = Meta(id="phoneinfoga", name="PhoneInfoga + libphonenumber", category="Phone", kind="local", targets=("phone",),
                free_mode="Offline number analysis always; PhoneInfoga CLI adds web reconnaissance when installed", site="https://github.com/sundowndev/phoneinfoga",
                docs_url="https://sundowndev.github.io/phoneinfoga/", route="vpn", cli_guard=True, tool_names=("phoneinfoga",),
                install="manual:https://github.com/sundowndev/phoneinfoga/releases",
                note="Offline analysis uses Google's libphonenumber (no network). PhoneInfoga text output is shown unparsed: Research required for a stable machine format.")

    def free(self, target, ttype, ctx):
        try:
            d = analyse_phone(target)
        except Exception:
            return self.res(ERROR, "local", error="Could not parse the number. Use international format, e.g. +14155552671.")
        f = [Finding("phone", f"{d['international']}: {'valid' if d['valid'] else 'not a valid number'} ({d['region'] or 'unknown region'}, {d['line_type']})", d["e164"], data=d,
                     ents=[("phone", d["e164"], "subject")] + ([("location", d["location"], "region")] if d["location"] else []), confidence=0.9 if d["valid"] else 0.4)]
        res = self.res(OK, "local", findings=f, notes=["Carrier shown is the ORIGINAL allocation; ported numbers may differ."])
        exe = ctx.tool(self.id, self.meta.tool_names)
        if exe and d["valid"]:
            try:
                _, env = private_home(self.id)
                r = ctx.cli(self.meta, [exe, "scan", "-n", d["e164"]], timeout=90, route=ctx.route(self.meta, "vpn"), cwd=work_dir(ctx, self.id), extra_env=env)
                lines = [ANSI.sub("", x).strip() for x in r.out.splitlines() if x.strip()][:40]
                if lines:
                    f.append(Finding("recon", "PhoneInfoga scan output (unparsed)", d["e164"], data={"lines": lines}, confidence=0.4))
            except Exception as exc:  # shield block must not discard the offline analysis
                res.notes.append(f"PhoneInfoga skipped: {str(exc)[:140]}")
        elif not exe:
            res.notes.append("PhoneInfoga binary not found (optional). Offline analysis shown.")
        return res

    def selftest(self):
        try:
            d = analyse_phone("+14155552671")
            return [] if d["e164"] == "+14155552671" and d["region"] == "US" else ["libphonenumber returned unexpected data"]
        except Exception as exc:
            return [f"libphonenumber failed: {type(exc).__name__}"]
