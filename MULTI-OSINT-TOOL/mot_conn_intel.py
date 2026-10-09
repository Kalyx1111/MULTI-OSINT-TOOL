"""MULTI-OSINT-TOOL :: registry and reputation connectors: RDAP, AbuseIPDB, GreyNoise Community.

What was checked during development (see each Meta.docs_url):
- RDAP: the IANA bootstrap file (data.iana.org/rdap/dns.json) was read; it lists the registry server
  for each TLD (for example .com -> rdap.verisign.com, .org -> rdap.publicinterestregistry.org).
  Domain records are fetched as {base}domain/{name}, which follows the RDAP object model.
- AbuseIPDB: docs.abuseipdb.com was read: endpoint https://api.abuseipdb.com/api/v2/check, key sent
  in the "Key" header, maxAgeInDays 1-365 (default 30).
- GreyNoise Community: docs.greynoise.io was read: endpoint https://api.greynoise.io/v3/community/{ip},
  key sent in the "key" header; unauthenticated lookups are allowed with a small daily limit.

Not yet checked against a live response in development: the AbuseIPDB and GreyNoise response field
names. The parsers keep every field they find and show unknown scalar fields rather than dropping
them, so a field-name difference shows up in the result instead of disappearing. The self-checks use
fixtures with example.com names only.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Optional

from mot_connectors_base import (EMPTY, ERROR, NO_KEY, OK, Connector, Ctx, Finding, Meta, NetError, Result, as_list, register)

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
DOMAIN_RX = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{1,59}|[a-z]{2,63})$")
_BOOT: dict = {"at": 0.0, "map": {}}  # TLD -> RDAP base URL, refreshed at most once a day
UNKNOWN_SCALARS = 12


def valid_domain(text: str) -> Optional[str]:
    d = (text or "").strip().lower().rstrip(".")
    return d if DOMAIN_RX.match(d) else None


def valid_ip(text: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address((text or "").strip()))
    except ValueError:
        return None


def parse_bootstrap(j: dict) -> dict:
    """IANA RDAP bootstrap (RFC 9224): {"services": [[[tlds], [base urls]], ...]} -> {tld: https base with trailing slash}."""
    out: dict = {}
    for svc in as_list(j.get("services") if isinstance(j, dict) else None):
        if not isinstance(svc, list) or len(svc) != 2:
            continue
        tlds, bases = svc
        https = [b for b in as_list(bases) if isinstance(b, str) and b.startswith("https://")]
        if not https:
            continue
        base = https[0] if https[0].endswith("/") else https[0] + "/"
        for t in as_list(tlds):
            if isinstance(t, str) and t:
                out[t.lower()] = base
    return out


def _walk_entities(ents, depth: int = 0):
    for e in as_list(ents):
        if isinstance(e, dict) and depth < 4:
            yield e
            yield from _walk_entities(e.get("entities"), depth + 1)


def vcard_fields(v) -> tuple:
    """RFC 9083 vcardArray: ["vcard", [[name, params, type, value], ...]] -> (display name, email)."""
    label, mail = "", ""
    if isinstance(v, list) and len(v) == 2 and isinstance(v[1], list):
        for row in v[1]:
            if not isinstance(row, list) or len(row) < 4:
                continue
            key, val = str(row[0]).lower(), row[3]
            if isinstance(val, list):
                val = " ".join(str(x) for x in val if isinstance(x, str))
            if key in ("fn", "org") and not label:
                label = str(val)[:200]
            elif key == "email" and not mail:
                mail = str(val)[:200]
    return label, mail


def parse_rdap(j: dict, domain: str) -> list:
    if not isinstance(j, dict):
        return []
    name = str(j.get("ldhName") or domain).lower().rstrip(".")[:253]
    events = {}
    for e in as_list(j.get("events")):
        if isinstance(e, dict) and e.get("eventAction"):
            events[str(e["eventAction"])[:40]] = str(e.get("eventDate", ""))[:40]
    status = [str(s)[:60] for s in as_list(j.get("status"))][:12]
    ns = [str(n.get("ldhName", "")).lower().rstrip(".")[:253] for n in as_list(j.get("nameservers"))
          if isinstance(n, dict) and n.get("ldhName")][:20]
    roles: dict = {}
    for ent in _walk_entities(j.get("entities")):
        label, mail = vcard_fields(ent.get("vcardArray"))
        for role in as_list(ent.get("roles")):
            roles.setdefault(str(role)[:30], []).append((label, mail))
    sec = j.get("secureDNS") if isinstance(j.get("secureDNS"), dict) else {}
    registrar = next((lab for lab, _m in roles.get("registrar", []) if lab), "")
    out = [Finding("registration", f"{name}: registered, {len(ns)} nameserver(s)", name,
                   data={"status": status, "events": events, "registrar": registrar, "dnssec_signed": sec.get("delegationSigned")},
                   ents=[("domain", name, "subject")] + [("hostname", n, "nameserver") for n in ns], confidence=0.9)]
    out += [Finding("nameserver", n, n, ents=[("hostname", n, "nameserver")], confidence=0.9) for n in ns]
    for lab, mail in (m for m in roles.get("abuse", []) if m[1]):
        out.append(Finding("contact", f"Abuse contact published by the registrar{(': ' + lab) if lab else ''}", mail,
                           ents=[("email", mail.lower(), "abuse_contact")], confidence=0.9))
    return out


def parse_abuseipdb(j: dict) -> list:
    d = j.get("data") if isinstance(j, dict) else None
    if not isinstance(d, dict):
        return []
    ip = str(d.get("ipAddress") or "")[:64]
    score, reports = d.get("abuseConfidenceScore"), d.get("totalReports")
    dom = str(d.get("domain") or "").lower()[:253]
    ents = [("ip", ip, "subject")] if ip else []
    if dom:
        ents.append(("domain", dom, "reported_domain"))
    keep = ("countryCode", "usageType", "isp", "domain", "isWhitelisted", "isTor", "totalReports", "numDistinctUsers", "lastReportedAt")
    data = {k: d[k] for k in keep if k in d}
    title = f"Abuse confidence {score}% · {reports} report(s) in the look-back window"
    return [Finding("reputation", title, ip, data=data, ents=ents, confidence=0.7)]


def parse_greynoise(j: dict, ip: str) -> list:
    if not isinstance(j, dict) or not j:
        return []
    known = ("ip", "noise", "riot", "classification", "name", "last_seen", "message", "link")
    data = {k: j[k] for k in known if k in j and j[k] is not None and not isinstance(j[k], (dict, list))}
    extra = [k for k in j if k not in known and isinstance(j[k], (str, int, float, bool))][:UNKNOWN_SCALARS]
    for k in extra:
        data[str(k)[:40]] = str(j[k])[:200]
    cls, name = str(j.get("classification") or "unclassified")[:40], str(j.get("name") or "")[:120]
    title = f"GreyNoise: classification {cls}" + (f" ({name})" if name else "") + f" · noise={j.get('noise')} · riot={j.get('riot')}"
    return [Finding("reputation", title, ip, data=data, ents=[("ip", ip, "subject")], confidence=0.6)]


@register
class RdapDomain(Connector):
    meta = Meta(id="rdap", name="RDAP registration record", category="Domain & DNS", kind="api", targets=("domain",),
                free_mode="Free, no key: registrar, dates, status and nameservers from the registry that holds the domain",
                site="https://www.iana.org/assignments/rdap-dns/rdap-dns.xml", docs_url="https://www.rfc-editor.org/rfc/rfc9224",
                route="vpn", min_interval=1.0, canary=("domain", "example.com"))

    def _bootstrap(self, ctx: Ctx) -> dict:
        if _BOOT["map"] and time.time() - _BOOT["at"] < 86400:
            return _BOOT["map"]
        r = ctx.request(self.meta, "GET", BOOTSTRAP_URL, timeout=(10, 30), max_bytes=4_000_000)
        if not r.ok:
            raise NetError(f"The RDAP registry directory returned HTTP {r.status}.")
        try:
            mp = parse_bootstrap(r.json())
        except ValueError:
            raise NetError("The RDAP registry directory was not valid JSON.") from None
        if not mp:
            raise NetError("The RDAP registry directory listed no servers.")
        _BOOT.update(at=time.time(), map=mp)
        return mp

    def free(self, target, ttype, ctx):
        dom = valid_domain(target)
        if not dom:
            return self.res(ERROR, "free", error="Enter a domain such as example.com, without http:// or a path.")
        tld = dom.rsplit(".", 1)[1]
        base = self._bootstrap(ctx).get(tld)
        if not base:
            return self.res(EMPTY, "free", notes=[f"No RDAP server is listed for .{tld} in the registry directory."])
        r = ctx.request(self.meta, "GET", f"{base}domain/{dom}", headers={"accept": "application/rdap+json, application/json;q=0.5"},
                        timeout=(10, 30), max_bytes=2_000_000)
        if r.status == 404:
            return self.res(EMPTY, "free", notes=["The registry returned no record for this domain."])
        bad = self.http_status(r)
        if bad:
            return bad
        try:
            j = r.json()
        except ValueError:
            return self.res(ERROR, "free", error="The registry answered, but not with JSON.")
        f = parse_rdap(j, dom)
        return self.res(OK if f else EMPTY, "free", findings=f, notes=[f"Answered by the registry for .{tld}."])

    def selftest(self):
        probs = []
        if valid_domain("Example.COM.") != "example.com":
            probs.append("domain normalisation failed")
        if valid_domain("a/b.com") is not None or valid_domain("http://x.com") is not None:
            probs.append("a URL or path was accepted as a domain")
        if parse_bootstrap({"services": [[["com", "net"], ["https://rdap.verisign.com/com/v1"]]]}).get("com") != "https://rdap.verisign.com/com/v1/":
            probs.append("bootstrap parse failed")
        f = parse_rdap(RDAP_FIXTURE, "example.com")
        if sum(x.kind == "nameserver" for x in f) != 2 or not any(x.kind == "contact" for x in f):
            probs.append("RDAP parse failed")
        return probs


RDAP_FIXTURE = {"objectClassName": "domain", "ldhName": "EXAMPLE.COM", "status": ["client delete prohibited"],
                "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                           {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}],
                "nameservers": [{"objectClassName": "nameserver", "ldhName": "a.iana-servers.net"},
                                {"objectClassName": "nameserver", "ldhName": "b.iana-servers.net"}],
                "entities": [{"objectClassName": "entity", "roles": ["registrar"],
                              "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]},
                             {"objectClassName": "entity", "roles": ["abuse"],
                              "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Abuse desk"],
                                                       ["email", {}, "text", "abuse@registrar.example"]]]}]}


@register
class AbuseIPDB(Connector):
    meta = Meta(id="abuseipdb", name="AbuseIPDB", category="Reputation", kind="api", targets=("ip",), key_fields=("api_key",),
                free_mode="", site="https://docs.abuseipdb.com/", docs_url="https://docs.abuseipdb.com/", route="vpn",
                min_interval=1.0, canary=("ip", "8.8.8.8"), canary_cost=True,
                note="Needs a free AbuseIPDB account key. The daily check allowance on the key is the limit.")

    def keyed(self, target, ttype, ctx, key):
        ip = valid_ip(target)
        secret = (key or {}).get("api_key", "")
        if not ip:
            return self.res(ERROR, error="Enter an IP address.")
        if not secret:
            return self.res(NO_KEY, mode="none", notes=["Add an AbuseIPDB key in Settings."])
        r = ctx.request(self.meta, "GET", "https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 30},
                        headers={"Key": secret, "Accept": "application/json"}, timeout=(10, 30))
        bad = self.http_status(r)
        if bad:
            return bad
        try:
            j = r.json()
        except ValueError:
            return self.res(ERROR, error="The service answered, but not with JSON.")
        f = parse_abuseipdb(j)
        return self.res(OK if f else EMPTY, "keyed", findings=f, notes=["Reports are submitted by users. A score is a signal to weigh, not proof."])

    def selftest(self):
        f = parse_abuseipdb({"data": {"ipAddress": "203.0.113.9", "abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "XX"}})
        probs = [] if f and f[0].kind == "reputation" else ["AbuseIPDB parse failed"]
        if valid_ip("2001:db8::1") is None or valid_ip("999.1.1.1") is not None:
            probs.append("IP validation failed")
        return probs


@register
class GreyNoise(Connector):
    meta = Meta(id="greynoise", name="GreyNoise Community", category="Reputation", kind="api", targets=("ip",), key_fields=("api_key",),
                free_mode="Unauthenticated community lookup, with a small daily allowance (per GreyNoise docs)",
                site="https://www.greynoise.io", docs_url="https://docs.greynoise.io/docs/using-the-greynoise-community-api",
                route="vpn", min_interval=1.0, canary=("ip", "8.8.8.8"), canary_cost=True)

    def _lookup(self, ctx: Ctx, ip: str, headers: dict, mode: str) -> Result:
        r = ctx.request(self.meta, "GET", f"https://api.greynoise.io/v3/community/{ip}", headers=headers, timeout=(10, 30))
        if r.status == 404:
            return self.res(EMPTY, mode, notes=["GreyNoise has no record of this address."])
        bad = self.http_status(r)
        if bad:
            return bad
        try:
            j = r.json()
        except ValueError:
            return self.res(ERROR, mode, error="The service answered, but not with JSON.")
        f = parse_greynoise(j, ip)
        return self.res(OK if f else EMPTY, mode, findings=f, notes=["Community data: use it to triage, not to convict."])

    def free(self, target, ttype, ctx):
        ip = valid_ip(target)
        if not ip:
            return self.res(ERROR, "free", error="Enter an IP address.")
        return self._lookup(ctx, ip, {"accept": "application/json"}, "free")

    def keyed(self, target, ttype, ctx, key):
        ip = valid_ip(target)
        secret = (key or {}).get("api_key", "")
        if not ip:
            return self.res(ERROR, error="Enter an IP address.")
        if not secret:
            return self.free(target, ttype, ctx)
        return self._lookup(ctx, ip, {"key": secret, "accept": "application/json"}, "keyed")

    def selftest(self):
        f = parse_greynoise({"ip": "203.0.113.9", "noise": False, "riot": False, "classification": "unknown", "message": "ok", "extra_flag": True}, "203.0.113.9")
        probs = [] if f and "extra_flag" in f[0].data else ["GreyNoise parse failed"]
        return probs
