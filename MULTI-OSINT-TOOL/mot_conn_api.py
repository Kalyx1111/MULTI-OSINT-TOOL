"""MULTI-OSINT-TOOL :: API connectors (endpoints verified against vendor docs, Oct 2026).

Rule: a key in the vault => keyed (paid/free-account) mode. No key, or key rejected => free tier
where the vendor offers one; otherwise a clear 'no key' result with a link, never a fake result.
Pure parse_* functions are separated so they can be unit-tested and self-checked offline.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from urllib.parse import quote

from mot_connectors_base import (EMPTY, ERROR, KEY_INVALID, NO_KEY, OK, PLAN, RATE, Connector, Ctx, Finding, Meta,
                                 Result, as_list, mask_secret, register)

UA = "MULTI-OSINT-TOOL"


def _s(x, n: int = 300) -> str:
    return "" if x is None else str(x)[:n]


def _ents(*triples):
    return [(a, _s(b), c) for a, b, c in triples if b]


def flat_scalars(obj, limit: int = 24) -> dict:
    """Top-level scalar fields only: used to show an unrecognised response honestly instead of dropping it."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (str, int, float, bool)) and len(out) < limit:
                out[str(k)[:40]] = _s(v, 200)
            elif isinstance(v, list) and len(out) < limit:
                out[str(k)[:40]] = f"[{len(v)} item(s)]"
    return out


# =============================================================================== Shodan
def parse_internetdb(j: dict, ip: str) -> list[Finding]:
    ports, hosts = as_list(j.get("ports")), [_s(h) for h in as_list(j.get("hostnames"))]
    vulns = [_s(v) for v in as_list(j.get("vulns"))]
    out = [Finding("host", f"{ip}: {len(ports)} open port(s)", ip,
                   data={"ports": ports, "hostnames": hosts, "cpes": as_list(j.get("cpes"))[:20], "tags": as_list(j.get("tags")), "vulns": len(vulns)},
                   ents=_ents(("ip", ip, "host")) + [("hostname", h, "reverse_dns") for h in hosts[:10]], confidence=0.8)]
    out += [Finding("vuln", v, v, data={"note": "Inferred from service banners; verify before acting."}, ents=[("cve", v, "affects")], confidence=0.4)
            for v in vulns[:30]]
    return out


def parse_shodan_host(j: dict) -> list[Finding]:
    ip = _s(j.get("ip_str"))
    vulns = j.get("vulns") or []
    vulns = list(vulns.keys()) if isinstance(vulns, dict) else as_list(vulns)
    out = [Finding("host", f"{ip}: {_s(j.get('org') or j.get('isp'))} — {len(as_list(j.get('ports')))} port(s)", ip,
                   data={"org": _s(j.get("org")), "isp": _s(j.get("isp")), "asn": _s(j.get("asn")), "os": _s(j.get("os")),
                         "country": _s(j.get("country_name")), "city": _s(j.get("city")), "ports": as_list(j.get("ports")),
                         "hostnames": as_list(j.get("hostnames")), "domains": as_list(j.get("domains")), "tags": as_list(j.get("tags")),
                         "last_update": _s(j.get("last_update"))},
                   ents=_ents(("ip", ip, "host"), ("asn", j.get("asn"), "network")) + [("hostname", _s(h), "hostname") for h in as_list(j.get("hostnames"))[:10]],
                   confidence=0.9)]
    for b in as_list(j.get("data"))[:25]:
        prod = " ".join(x for x in (_s(b.get("product")), _s(b.get("version"))) if x)
        out.append(Finding("service", f"{b.get('port')}/{_s(b.get('transport'))} {prod}".strip(), _s(b.get("port")),
                           data={"module": _s((b.get("_shodan") or {}).get("module")), "timestamp": _s(b.get("timestamp"))}, confidence=0.8))
    out += [Finding("vuln", _s(v), _s(v), ents=[("cve", _s(v), "affects")], confidence=0.5) for v in vulns[:30]]
    return out


@register
class Shodan(Connector):
    meta = Meta(id="shodan", name="Shodan", category="Infrastructure", kind="api", targets=("ip", "domain"), key_fields=("api_key",),
                free_mode="InternetDB: ports, CVEs, hostnames (no key; IPv4; non-commercial use)", site="https://www.shodan.io",
                key_url="https://account.shodan.io", docs_url="https://developer.shodan.io/api", route="vpn", canary=("ip", "8.8.8.8"))

    def _ips(self, target, ttype, ctx):
        return [target] if ttype == "ip" else ctx.resolve(self.meta, target)[:4]

    def free(self, target, ttype, ctx):
        ips = self._ips(target, ttype, ctx)
        out = self.res(OK, "free")
        if not ips:
            return self.res(EMPTY, "free", notes=["Target did not resolve to an IP address."])
        for ip in ips:
            if ":" in ip:
                out.notes.append(f"{ip}: InternetDB covers IPv4 only.")
                continue
            r = ctx.request(self.meta, "GET", f"https://internetdb.shodan.io/{ip}", pref="tor")
            if r.status == 404:
                out.notes.append(f"{ip}: no data in InternetDB.")
                continue
            bad = self.http_status(r)
            if bad:
                return bad
            out.findings += parse_internetdb(r.json(), ip)
        out.status = OK if out.findings else EMPTY
        return out

    def keyed(self, target, ttype, ctx, key):
        out = self.res(OK, "keyed")
        for ip in self._ips(target, ttype, ctx):
            r = ctx.request(self.meta, "GET", f"https://api.shodan.io/shodan/host/{ip}", params={"key": key["api_key"], "minify": "false"})
            if r.status == 404:
                out.notes.append(f"{ip}: no information.")
                continue
            bad = self.http_status(r)
            if bad:
                return bad
            out.findings += parse_shodan_host(r.json())
        out.status = OK if out.findings else EMPTY
        return out

    def selftest(self):
        f = parse_internetdb({"ports": [80, 443], "hostnames": ["a.example"], "vulns": ["CVE-2020-0001"], "cpes": [], "tags": []}, "1.2.3.4")
        g = parse_shodan_host({"ip_str": "1.2.3.4", "org": "X", "ports": [22], "data": [{"port": 22, "transport": "tcp", "product": "OpenSSH"}], "vulns": {"CVE-2021-1": {}}})
        return [] if len(f) == 2 and len(g) == 3 else ["Shodan parsers returned unexpected output"]


# =============================================================================== HIBP
def parse_hibp_breaches(arr: list) -> list[Finding]:
    out = []
    for b in arr if isinstance(arr, list) else []:
        name = _s(b.get("Name"))
        classes = [_s(c) for c in as_list(b.get("DataClasses"))]
        out.append(Finding("breach", f"{_s(b.get('Title')) or name} ({_s(b.get('BreachDate')) or 'date n/a'})", name,
                           data={"domain": _s(b.get("Domain")), "breach_date": _s(b.get("BreachDate")), "pwn_count": b.get("PwnCount"),
                                 "data_classes": classes, "verified": b.get("IsVerified")},
                           ents=[("breach", name, "exposed_in")], sensitive="Passwords" in classes, confidence=0.9))
    return out


@register
class HIBP(Connector):
    meta = Meta(id="hibp", name="Have I Been Pwned", category="Breach data", kind="api", targets=("email", "domain", "password"),
                key_fields=("api_key",), free_mode="Pwned Passwords (k-anonymity) + domain breach catalogue; email lookups need a paid key",
                site="https://haveibeenpwned.com", key_url="https://haveibeenpwned.com/API/Key", docs_url="https://haveibeenpwned.com/API/v3",
                route="vpn", min_interval=1.7, canary=("email", "account-exists@hibp-integration-tests.com"), free_targets=("domain", "password"))

    def free(self, target, ttype, ctx):
        h = {"user-agent": UA}
        if ttype == "password":
            sha = hashlib.sha1(target.encode("utf-8"), usedforsecurity=False).hexdigest().upper()  # protocol requirement (k-anonymity), not storage
            pre, suf = sha[:5], sha[5:]
            r = ctx.request(self.meta, "GET", f"https://api.pwnedpasswords.com/range/{pre}", headers={**h, "Add-Padding": "true"}, pref="tor")
            bad = self.http_status(r)
            if bad:
                return bad
            n = 0
            for line in r.text.splitlines():
                a, _, c = line.strip().partition(":")
                if a.upper() == suf:
                    n = int(c or 0)
            if n > 0:
                return self.res(OK, "free", findings=[Finding("password_exposure", f"This password appeared {n:,} times in breach corpora", str(n), confidence=0.95, sensitive=True,
                                                              data={"count": n})], notes=["Only the first 5 hash characters left this machine (k-anonymity). Change this password everywhere."])
            return self.res(EMPTY, "free", notes=["Password not found in Pwned Passwords. Only the first 5 hash characters were sent."])
        if ttype == "domain":
            r = ctx.request(self.meta, "GET", "https://haveibeenpwned.com/api/v3/breaches", params={"domain": target}, headers=h)
            bad = self.http_status(r)
            if bad:
                return bad
            f = parse_hibp_breaches(r.json())
            return self.res(OK if f else EMPTY, "free", findings=f, notes=["Public breach catalogue entries for this domain's service (not individual accounts)."])
        return self.res(NO_KEY, "none", handoff_url="https://haveibeenpwned.com/", notes=["Email lookups require a paid HIBP key. You can check one address manually on the website."])

    def keyed(self, target, ttype, ctx, key):
        if ttype != "email":
            return self.free(target, ttype, ctx)
        h = {"hibp-api-key": key["api_key"], "user-agent": UA}
        acct = quote(target, safe="")
        r = ctx.request(self.meta, "GET", f"https://haveibeenpwned.com/api/v3/breachedaccount/{acct}", params={"truncateResponse": "false"}, headers=h)
        if r.status == 404:
            out = self.res(EMPTY, "keyed", notes=["Not found in any breach in HIBP."])
        else:
            bad = self.http_status(r)
            if bad:
                return bad
            out = self.res(OK, "keyed", findings=parse_hibp_breaches(r.json()))
        p = ctx.request(self.meta, "GET", f"https://haveibeenpwned.com/api/v3/pasteaccount/{acct}", headers=h)
        if p.ok:
            pastes = p.json()
            for x in pastes[:20] if isinstance(pastes, list) else []:
                out.findings.append(Finding("paste", f"Paste on {_s(x.get('Source'))}: {_s(x.get('Title')) or _s(x.get('Id'))}", _s(x.get("Id")),
                                            data={"date": _s(x.get("Date")), "email_count": x.get("EmailCount")}, ents=[("paste", _s(x.get("Id")), "mentioned_in")], confidence=0.8))
            out.status = OK if out.findings else out.status
        return out

    def selftest(self):
        f = parse_hibp_breaches([{"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Passwords"], "PwnCount": 1}])
        return [] if f and f[0].sensitive else ["HIBP parser failed"]


# =============================================================================== Dehashed
def parse_dehashed(j: dict) -> list[Finding]:
    out = []
    for e in as_list(j.get("entries"))[:100]:
        emails, users = [_s(x) for x in as_list(e.get("email"))], [_s(x) for x in as_list(e.get("username"))]
        pw, hp = [_s(x) for x in as_list(e.get("password"))], [_s(x) for x in as_list(e.get("hashed_password"))]
        data = {"database": _s(e.get("database_name")), "emails": emails, "usernames": users, "names": [_s(x) for x in as_list(e.get("name"))],
                "phones": [_s(x) for x in as_list(e.get("phone"))], "ips": [_s(x) for x in as_list(e.get("ip_address"))],
                "has_password": bool(pw), "password_masked": [mask_secret(p) for p in pw], "has_hash": bool(hp)}
        if pw or hp:
            data["_secret"] = {"passwords": pw, "hashes": hp}
        ents = [("email", x, "appears_with") for x in emails[:3]] + [("username", x, "appears_with") for x in users[:3]]
        out.append(Finding("credential", f"{data['database'] or 'unknown database'}: " + (", ".join(emails[:2] or users[:2]) or "record"), _s(e.get("id")),
                           data=data, ents=ents, sensitive=bool(pw or hp), confidence=0.8))
    return out


@register
class Dehashed(Connector):
    meta = Meta(id="dehashed", name="DeHashed", category="Breach data", kind="api", targets=("email", "username", "domain", "ip", "phone"),
                key_fields=("api_key",), free_mode="", site="https://dehashed.com", key_url="https://app.dehashed.com",
                docs_url="https://app.dehashed.com/documentation/api", route="vpn", canary=("domain", "example.com"), canary_cost=True,
                note="Each search consumes 1 DeHashed credit. No free API exists.")

    @staticmethod
    def query(ttype: str, target: str) -> str:
        t = target.replace('"', "")
        return {"email": f'email:"{t}"', "username": f'username:"{t}"', "domain": f"domain:{t}", "ip": f'ip_address:"{t}"', "phone": f'phone:"{t}"'}[ttype]

    def keyed(self, target, ttype, ctx, key):
        r = ctx.request(self.meta, "POST", "https://api.dehashed.com/v2/search",
                        headers={"Dehashed-Api-Key": key["api_key"], "Accept": "application/json", "Content-Type": "application/json"},
                        json_body={"query": self.query(ttype, target), "page": 1, "size": 100, "de_dupe": True})
        bad = self.http_status(r)
        if bad:
            return bad
        j = r.json()
        f = parse_dehashed(j)
        notes = [f"Credits remaining: {j.get('balance', '?')}. Total matches: {j.get('total', len(f))}."]
        if any(x.sensitive for x in f):
            notes.append("Passwords/hashes are masked; Reveal asks for your master password and is audited.")
        return self.res(OK if f else EMPTY, "keyed", findings=f, notes=notes)

    def selftest(self):
        import secrets  # runtime-generated probe: no password literal in the source

        probe = secrets.token_urlsafe(12)
        f = parse_dehashed({"entries": [{"id": "1", "email": ["a@b.com"], "password": probe, "database_name": "X"}], "balance": 5})
        ok = f and probe not in str(f[0].to_dict()) and f[0].data["_secret"]["passwords"] == [probe]
        return [] if ok else ["DeHashed parser leaks or fails masking"]


# =============================================================================== Hunter
def parse_hunter_domain(j: dict) -> list[Finding]:
    d = j.get("data") or {}
    out = [Finding("org", f"{_s(d.get('organization')) or _s(d.get('domain'))}: email pattern {_s(d.get('pattern')) or 'unknown'}", _s(d.get("domain")),
                   data={"pattern": _s(d.get("pattern")), "webmail": d.get("webmail"), "disposable": d.get("disposable")}, ents=_ents(("domain", d.get("domain"), "org_domain")), confidence=0.7)]
    for e in as_list(d.get("emails"))[:50]:
        v = _s(e.get("value"))
        out.append(Finding("email", v, v, data={"confidence": e.get("confidence"), "type": _s(e.get("type")), "position": _s(e.get("position")), "department": _s(e.get("department")),
                                                "sources": [_s(s.get("uri")) for s in as_list(e.get("sources"))[:5]]}, ents=_ents(("email", v, "works_at")), confidence=min(1.0, (e.get("confidence") or 50) / 100)))
    return out


def parse_hunter_email(j: dict, email: str) -> list[Finding]:
    d = j.get("data") or {}
    out = [Finding("email_check", f"{email}: {_s(d.get('status'))} (score {_s(d.get('score'))})", email,
                   data={k: d.get(k) for k in ("status", "score", "disposable", "webmail", "accept_all", "smtp_check", "block")}, ents=_ents(("email", email, "subject")), confidence=0.7)]
    for s in as_list(d.get("sources"))[:20]:
        out.append(Finding("url", _s(s.get("domain")) or _s(s.get("uri")), _s(s.get("uri")), url=_s(s.get("uri")), data={"extracted_on": _s(s.get("extracted_on"))},
                           ents=_ents(("url", s.get("uri"), "mentions")), confidence=0.6))
    return out


@register
class Hunter(Connector):
    meta = Meta(id="hunter", name="Hunter.io", category="Email intelligence", kind="api", targets=("domain", "email"), key_fields=("api_key",),
                free_mode="Email Count (free, unauthenticated) for domains; free account key gives monthly credits", site="https://hunter.io",
                key_url="https://hunter.io/api_keys", docs_url="https://hunter.io/api-documentation/v2", route="vpn",
                canary=("domain", "stripe.com"), free_targets=("domain",), note="Hunter's documented test key 'test-api-key' returns dummy data.")

    def free(self, target, ttype, ctx):
        if ttype != "domain":
            return self.res(NO_KEY, "none", handoff_url=self.meta.key_url, notes=["Email verification needs a (free-account) API key."])
        r = ctx.request(self.meta, "GET", "https://api.hunter.io/v2/email-count", params={"domain": target})
        bad = self.http_status(r)
        if bad:
            return bad
        d = (r.json().get("data") or {})
        return self.res(OK, "free", findings=[Finding("org", f"Hunter indexes ~{d.get('total', 0)} email addresses on {target}", _s(d.get("total")),
                                                      data={k: d.get(k) for k in ("total", "personal_emails", "generic_emails", "department", "seniority")}, confidence=0.7)],
                        notes=["Counts only. Add a key for the actual addresses and sources."])

    def keyed(self, target, ttype, ctx, key):
        h = {"X-API-KEY": key["api_key"]}
        if ttype == "domain":
            r = ctx.request(self.meta, "GET", "https://api.hunter.io/v2/domain-search", params={"domain": target, "limit": 25}, headers=h)
            bad = self.http_status(r)
            if bad:
                return bad
            f = parse_hunter_domain(r.json())
        else:
            r = ctx.request(self.meta, "GET", "https://api.hunter.io/v2/email-verifier", params={"email": target}, headers=h)
            bad = self.http_status(r)
            if bad:
                return bad
            f = parse_hunter_email(r.json(), target)
        return self.res(OK if f else EMPTY, "keyed", findings=f)

    def selftest(self):
        a = parse_hunter_domain({"data": {"domain": "x.com", "organization": "X", "pattern": "{first}", "emails": [{"value": "a@x.com", "confidence": 90, "sources": [{"uri": "https://x.com/a"}]}]}})
        b = parse_hunter_email({"data": {"status": "valid", "score": 90, "sources": [{"uri": "https://x.com/a"}]}}, "a@x.com")
        return [] if len(a) == 2 and len(b) == 2 else ["Hunter parsers failed"]


# =============================================================================== IntelX
def parse_intelx(records: list) -> list[Finding]:
    out, buckets = [], {}
    for r in records:
        b = _s(r.get("bucket"))
        buckets[b] = buckets.get(b, 0) + 1
    if records:
        dark = sum(v for k, v in buckets.items() if k.startswith("darknet"))
        out.append(Finding("darkweb" if dark else "leak", f"{len(records)} record(s) across {len(buckets)} bucket(s); dark-web buckets: {dark}", str(len(records)),
                           data={"buckets": buckets}, confidence=0.8))
    for r in records[:40]:
        b = _s(r.get("bucket"))
        out.append(Finding("darkweb" if b.startswith("darknet") else "leak", _s(r.get("name")) or "(unnamed item)", _s(r.get("systemid")),
                           data={"bucket": b, "date": _s(r.get("date")), "added": _s(r.get("added")), "size": r.get("size"), "media": r.get("mediah") or r.get("media")},
                           sensitive=True, confidence=0.7))
    return out


@register
class IntelX(Connector):
    meta = Meta(id="intelx", name="Intelligence X", category="Dark web & leaks", kind="api", targets=("email", "domain", "ip", "phone", "url"),
                key_fields=("api_key",), optional_fields=("host",), free_mode="", site="https://intelx.io", key_url="https://intelx.io/account?tab=developer",
                docs_url="https://help.intelx.io/api", route="vpn", canary=("domain", "example.com"),
                note="Free accounts use host free.intelx.io, paid use 2.intelx.io (shown on your Developer tab). Metadata only; MOT never opens leaked files.")
    HOST_RE = re.compile(r"^(free|public|2|3)\.intelx\.io$")

    def keyed(self, target, ttype, ctx, key):
        host = key.get("host") or "free.intelx.io"
        if not self.HOST_RE.match(host):
            return self.res(ERROR, error="Invalid IntelX host in settings (use free.intelx.io or 2.intelx.io).")
        base, hdr = f"https://{host}", {"x-key": key["api_key"], "User-Agent": UA}
        body = {"term": target, "buckets": [], "lookuplevel": 0, "maxresults": 100, "timeout": 0, "datefrom": "", "dateto": "", "sort": 4, "media": 0, "terminate": []}
        r = ctx.request(self.meta, "POST", base + "/intelligent/search", headers=hdr, json_body=body)
        bad = self.http_status(r)
        if bad:
            return bad
        sid = (r.json() or {}).get("id")
        if not sid or not re.fullmatch(r"[0-9a-fA-F-]{8,64}", str(sid)):
            return self.res(ERROR, error="IntelX did not return a search id.")
        recs, end = [], time.time() + 35
        try:
            while time.time() < end and not ctx.expired() and len(recs) < 300:
                rr = ctx.request(self.meta, "GET", base + "/intelligent/search/result", headers=hdr, params={"id": sid, "limit": 100, "statistics": 0, "previewlines": 0})
                bad = self.http_status(rr)
                if bad:
                    return bad
                j = rr.json() or {}
                recs += as_list(j.get("records"))
                if j.get("status") in (1, 2):
                    break
                ctx.sleep(1.5)
        finally:
            try:
                ctx.request(self.meta, "GET", base + "/intelligent/search/terminate", headers=hdr, params={"id": sid}, retries=0)
            except Exception:
                pass
        f = parse_intelx(recs)
        return self.res(OK if f else EMPTY, "keyed", findings=f, notes=["Item names/metadata only. Access to full content depends on your licence and is intentionally not automated."])

    def selftest(self):
        f = parse_intelx([{"name": "x.txt", "bucket": "darknet.tor", "systemid": "1"}])
        return [] if len(f) == 2 and f[0].kind == "darkweb" else ["IntelX parser failed"]


# =============================================================================== VirusTotal
def vt_path(ttype: str, target: str) -> str:
    if ttype == "domain":
        return f"domains/{quote(target, safe='')}"
    if ttype == "ip":
        return f"ip_addresses/{quote(target, safe='')}"
    if ttype == "url":
        return "urls/" + base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
    return f"files/{quote(target, safe='')}"


def parse_vt(j: dict, ttype: str, target: str) -> list[Finding]:
    a = (j.get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
    total = sum(v for v in st.values() if isinstance(v, int))
    return [Finding("reputation", f"VirusTotal: {mal} malicious / {sus} suspicious of {total} engines", f"{mal}/{total}",
                    data={"stats": st, "reputation": a.get("reputation"), "categories": a.get("categories"), "registrar": _s(a.get("registrar")), "asn": a.get("asn"),
                          "country": _s(a.get("country")), "as_owner": _s(a.get("as_owner")), "tags": as_list(a.get("tags"))[:15]},
                    ents=_ents((ttype, target, "subject"), ("asn", a.get("asn"), "network")), confidence=0.8)]


@register
class VirusTotal(Connector):
    meta = Meta(id="virustotal", name="VirusTotal", category="Reputation", kind="api", targets=("domain", "ip", "url", "hash"), key_fields=("api_key",),
                free_mode="", site="https://www.virustotal.com", key_url="https://www.virustotal.com/gui/my-apikey", docs_url="https://docs.virustotal.com/reference/overview",
                route="vpn", min_interval=3.0, canary=("domain", "example.com"), note="A free community key works (strict rate limit, non-commercial).")

    def keyed(self, target, ttype, ctx, key):
        h = {"x-apikey": key["api_key"]}
        r = ctx.request(self.meta, "GET", f"https://www.virustotal.com/api/v3/{vt_path(ttype, target)}", headers=h)
        bad = self.http_status(r)
        if bad:
            return bad
        out = self.res(OK, "keyed", findings=parse_vt(r.json(), ttype, target))
        if ttype == "domain" and not ctx.expired():
            s = ctx.request(self.meta, "GET", f"https://www.virustotal.com/api/v3/domains/{quote(target, safe='')}/subdomains", params={"limit": 40}, headers=h, retries=0)
            if s.ok:
                subs = [_s(x.get("id")) for x in as_list(s.json().get("data"))]
                if subs:
                    out.findings.append(Finding("subdomains", f"{len(subs)} subdomain(s) known to VirusTotal", str(len(subs)), data={"subdomains": subs},
                                                ents=[("hostname", x, "subdomain") for x in subs], confidence=0.8))
        return out

    def selftest(self):
        f = parse_vt({"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "harmless": 60}}}}, "domain", "x.com")
        return [] if f and "2 malicious" in f[0].title else ["VirusTotal parser failed"]


# =============================================================================== urlscan.io
def parse_urlscan(j: dict) -> list[Finding]:
    out = []
    for x in as_list(j.get("results"))[:50]:
        pg, tk = x.get("page") or {}, x.get("task") or {}
        rid = _s(x.get("_id"))
        out.append(Finding("scan", f"{_s(pg.get('url') or tk.get('url'))}", rid, url=f"https://urlscan.io/result/{rid}/" if rid else "",
                           data={"time": _s(tk.get("time")), "ip": _s(pg.get("ip")), "country": _s(pg.get("country")), "server": _s(pg.get("server")), "asn": _s(pg.get("asn"))},
                           ents=_ents(("url", pg.get("url"), "scanned"), ("ip", pg.get("ip"), "hosted_on"), ("domain", pg.get("domain"), "domain")), confidence=0.7))
    return out


@register
class UrlScan(Connector):
    meta = Meta(id="urlscan", name="urlscan.io", category="Web history", kind="api", targets=("domain", "ip", "url"), key_fields=("api_key",),
                free_mode="Public search works without a key at lower rate limits", site="https://urlscan.io", key_url="https://urlscan.io/user/profile/",
                docs_url="https://urlscan.io/docs/api/", route="vpn", min_interval=1.0, canary=("domain", "example.com"),
                note="Passive search only. MOT never submits new scans (that would make urlscan visit the target).")

    def _search(self, target, ttype, ctx, key):
        host = (re.sub(r"^https?://", "", target).split("/")[0]) if ttype == "url" else target
        q = f"ip:\"{host}\"" if ttype == "ip" else f"domain:{host}"
        h = {"API-Key": key["api_key"]} if key else {}
        r = ctx.request(self.meta, "GET", "https://urlscan.io/api/v1/search/", params={"q": q, "size": 50}, headers=h)
        bad = self.http_status(r)
        if bad:
            return bad
        f = parse_urlscan(r.json())
        return self.res(OK if f else EMPTY, "keyed" if key else "free", findings=f)

    def free(self, target, ttype, ctx):
        return self._search(target, ttype, ctx, None)

    def keyed(self, target, ttype, ctx, key):
        return self._search(target, ttype, ctx, key)

    def selftest(self):
        f = parse_urlscan({"results": [{"_id": "abc", "page": {"url": "https://x.com", "ip": "1.1.1.1", "domain": "x.com"}, "task": {"time": "t"}}]})
        return [] if f else ["urlscan parser failed"]


# =============================================================================== GitHub
NOREPLY = re.compile(r"noreply", re.I)


def parse_github_user(u: dict) -> list[Finding]:
    login = _s(u.get("login"))
    return [Finding("account", f"GitHub: {login} ({_s(u.get('name')) or 'no name'})", login, url=_s(u.get("html_url")),
                    data={k: _s(u.get(k)) for k in ("name", "company", "blog", "location", "email", "bio", "twitter_username", "created_at", "public_repos", "followers")},
                    ents=_ents(("username", login, "alias"), ("email", u.get("email"), "public_email"), ("url", u.get("blog"), "website")), confidence=0.6)]


def parse_github_events(events: list) -> list[Finding]:
    seen, out = set(), []
    for ev in events if isinstance(events, list) else []:
        for c in as_list((ev.get("payload") or {}).get("commits")):
            a = c.get("author") or {}
            em = _s(a.get("email")).lower()
            if em and not NOREPLY.search(em) and em not in seen:
                seen.add(em)
                out.append(Finding("email", em, em, data={"name": _s(a.get("name")), "seen_in": "public push events"}, ents=[("email", em, "commit_author")], confidence=0.6))
    return out


@register
class GitHub(Connector):
    meta = Meta(id="github", name="GitHub", category="Identity & code", kind="api", targets=("username", "email", "domain"), key_fields=("token",),
                free_mode="Unauthenticated REST API (60 requests/hour, 10 searches/minute)", site="https://github.com", key_url="https://github.com/settings/tokens",
                docs_url="https://docs.github.com/en/rest", route="vpn", min_interval=1.0, canary=("username", "octocat"),
                note="Use a fine-grained token with NO scopes (public data only).")

    def _go(self, target, ttype, ctx, key):
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if key:
            h["Authorization"] = f"Bearer {key['token']}"
        out = self.res(OK, "keyed" if key else "free")
        get = lambda path, **p: ctx.request(self.meta, "GET", "https://api.github.com" + path, headers=h, params=p or None)  # noqa: E731
        if ttype == "username":
            r = get(f"/users/{quote(target, safe='')}")
            if r.status == 404:
                return self.res(EMPTY, out.mode, notes=["No such GitHub user."])
            bad = self.http_status(r)
            if bad:
                return bad
            out.findings += parse_github_user(r.json())
            ev = get(f"/users/{quote(target, safe='')}/events/public", per_page=100)
            if ev.ok:
                out.findings += parse_github_events(ev.json())
        else:
            q = f"{target} in:email"
            r = get("/search/users", q=q, per_page=10)
            bad = self.http_status(r)
            if bad:
                return bad
            for it in as_list(r.json().get("items"))[:10]:
                out.findings.append(Finding("account", f"GitHub: {_s(it.get('login'))}", _s(it.get("login")), url=_s(it.get("html_url")),
                                            ents=[("username", _s(it.get("login")), "alias")], confidence=0.5))
            if ttype == "email":
                c = get("/search/commits", q=f"author-email:{target}", per_page=10)
                if c.ok:
                    for it in as_list(c.json().get("items"))[:10]:
                        repo = (it.get("repository") or {}).get("full_name")
                        au = it.get("author") or {}
                        out.findings.append(Finding("commit", f"Commit in {_s(repo)}", _s(it.get("sha"))[:10], url=_s(it.get("html_url")),
                                                    data={"author_login": _s(au.get("login")), "date": _s(((it.get("commit") or {}).get("author") or {}).get("date"))},
                                                    ents=_ents(("username", au.get("login"), "alias"), ("url", it.get("html_url"), "commit")), confidence=0.7))
        out.status = OK if out.findings else EMPTY
        return out

    def free(self, target, ttype, ctx):
        return self._go(target, ttype, ctx, None)

    def keyed(self, target, ttype, ctx, key):
        return self._go(target, ttype, ctx, key)

    def selftest(self):
        a = parse_github_user({"login": "octocat", "name": "The Octocat", "html_url": "https://github.com/octocat"})
        b = parse_github_events([{"payload": {"commits": [{"author": {"name": "A", "email": "a@x.com"}}, {"author": {"email": "1+b@users.noreply.github.com"}}]}}])
        return [] if a and len(b) == 1 else ["GitHub parsers failed"]


# =============================================================================== Hudson Rock
def parse_hudsonrock(j: dict, ttype: str, target: str) -> list[Finding]:
    stealers = as_list(j.get("stealers"))
    out = []
    if stealers:
        out.append(Finding("infostealer", f"{len(stealers)} infostealer infection record(s) linked to this {ttype}", str(len(stealers)),
                           data={"message": _s(j.get("message"), 400), "corporate_services": j.get("total_corporate_services"), "user_services": j.get("total_user_services")},
                           ents=_ents((ttype, target, "compromised")), sensitive=True, confidence=0.8))
        for s in stealers[:10]:
            out.append(Finding("infostealer", f"{_s(s.get('stealer_family')) or 'unknown family'}, {_s(s.get('date_compromised'))[:10]}", _s(s.get("date_compromised"))[:10],
                               data={"operating_system": _s(s.get("operating_system")), "computer_name_masked": mask_secret(_s(s.get("computer_name"))) if s.get("computer_name") else "",
                                     "ip_masked": ".".join(_s(s.get("ip")).split(".")[:2] + ["*", "*"]) if s.get("ip") else "", "antiviruses": as_list(s.get("antiviruses"))[:5],
                                     "credentials_in_log": len(as_list(s.get("top_passwords")))}, sensitive=True, confidence=0.8))
    elif ttype == "domain" and any(k in j for k in ("total", "employees", "users", "third_parties")):
        out.append(Finding("infostealer", f"{target}: exposure statistics from infostealer logs", _s(j.get("total")),
                           data={k: j.get(k) for k in ("total", "employees", "users", "third_parties", "totalStealers") if k in j}, ents=_ents(("domain", target, "exposed")), sensitive=True, confidence=0.7))
    elif isinstance(j, dict) and j and "stealers" not in j and not any(k in j for k in ("message", "error")):
        flat = flat_scalars(j)  # unknown layout: show it rather than silently dropping it
        if flat:
            out.append(Finding("infostealer", "Hudson Rock returned data in an unrecognised layout (shown as-is)", "", data=flat, sensitive=True, confidence=0.3))
    return out


@register
class HudsonRock(Connector):
    meta = Meta(id="hudsonrock", name="Hudson Rock Cavalier", category="Dark web & leaks", kind="api", targets=("email", "username", "domain", "ip"),
                free_mode="Free keyless OSINT endpoints (infostealer exposure)", site="https://www.hudsonrock.com", key_url="",
                docs_url="https://docs.hudsonrock.com/", route="vpn", min_interval=1.0, canary=("domain", "example.com"),
                note="Uses the free, keyless OSINT endpoints. Hudson Rock also documents a keyed v3 API (POST api.hudsonrock.com/json/v3/...), but the name of its key header is shown only after login, "
                     "so it is not implemented: Research required. The free response layout was not verified against a live reply (unknown layouts are shown as-is).")

    def free(self, target, ttype, ctx):
        name = {"email": "email", "username": "username", "domain": "domain", "ip": "ip"}[ttype]
        r = ctx.request(self.meta, "GET", f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-{name}", params={name: target})
        bad = self.http_status(r)
        if bad:
            return bad
        try:
            f = parse_hudsonrock(r.json(), ttype, target)
        except ValueError:
            return self.res(ERROR, "free", error="Hudson Rock returned a non-JSON response.")
        return self.res(OK if f else EMPTY, "free", findings=f, notes=[] if f else ["No infostealer records found."])

    def selftest(self):
        f = parse_hudsonrock({"stealers": [{"stealer_family": "Raccoon", "date_compromised": "2023-05-01T00:00:00", "computer_name": "DESKTOP-1", "top_passwords": ["a*****"]}]}, "email", "a@b.com")
        g = parse_hudsonrock({"weird": "layout", "n": 3}, "email", "a@b.com")
        return [] if len(f) == 2 and "DESKTOP-1" not in str(f[1].to_dict()) and len(g) == 1 else ["Hudson Rock parser failed"]


# =============================================================================== Wayback
INTERESTING = re.compile(r"(?i)(admin|login|signin|backup|\.bak|\.old|\.sql|\.zip|\.tar|\.gz|\.env|\.git|config|phpinfo|wp-admin|wp-login|dashboard|staging|swagger|api/|\.pdf|\.xls|\.doc)")


def parse_wayback(rows: list, target: str) -> list[Finding]:
    rows = rows[1:] if rows and isinstance(rows[0], list) and rows[0] and rows[0][0] == "timestamp" else rows
    rows = [r for r in rows if isinstance(r, list) and len(r) >= 2]
    if not rows:
        return []
    ts = sorted(r[0] for r in rows)
    hosts = sorted({re.sub(r"^https?://([^/:]+).*$", r"\1", r[1]).lower() for r in rows if r[1].startswith("http")})
    out = [Finding("archive", f"{len(rows)} archived URL(s); first seen {ts[0][:8]}, last {ts[-1][:8]}", str(len(rows)),
                   data={"first": ts[0], "last": ts[-1], "hosts": hosts[:60]}, ents=[("hostname", h, "archived_host") for h in hosts[:50]], confidence=0.8)]
    for r in rows:
        if INTERESTING.search(r[1]) and len(out) < 41:
            out.append(Finding("url", r[1][:200], r[1][:200], url=f"https://web.archive.org/web/{r[0]}/{r[1]}", data={"timestamp": r[0], "status": r[3] if len(r) > 3 else ""},
                               ents=[("url", r[1][:200], "archived")], confidence=0.5))
    return out


@register
class Wayback(Connector):
    meta = Meta(id="wayback", name="Wayback Machine", category="Web history", kind="api", targets=("domain", "url"), free_mode="Free CDX API, no key",
                site="https://web.archive.org", docs_url="https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server", route="tor", min_interval=1.0,
                canary=("domain", "example.com"))

    def free(self, target, ttype, ctx):
        p = {"url": target, "output": "json", "fl": "timestamp,original,mimetype,statuscode", "collapse": "urlkey", "limit": 500}
        if ttype == "domain":
            p["matchType"] = "domain"
        r = ctx.request(self.meta, "GET", "https://web.archive.org/cdx/search/cdx", params=p, timeout=(10, 60), pref="tor")
        bad = self.http_status(r)
        if bad:
            return bad
        try:
            rows = r.json() if r.text.strip() else []
        except ValueError:
            return self.res(ERROR, error="Unexpected CDX response.")
        f = parse_wayback(rows, target)
        return self.res(OK if f else EMPTY, "free", findings=f, notes=["Snapshot links open archive.org copies, not the live site."])

    def selftest(self):
        f = parse_wayback([["timestamp", "original", "mimetype", "statuscode"], ["20200101000000", "https://x.com/admin/login", "text/html", "200"]], "x.com")
        return [] if len(f) == 2 else ["Wayback parser failed"]
