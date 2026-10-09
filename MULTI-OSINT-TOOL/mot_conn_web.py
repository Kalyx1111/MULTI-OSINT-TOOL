"""MULTI-OSINT-TOOL :: connectors that are NOT plain APIs. Each states plainly what it can and cannot do.

PimEyes  : vendor policy says "no API access for individuals or entities" and permits searching
           only yourself / consenting people. MOT therefore never automates it: guided hand-off only.
Epieos   : API access is listed on the Custom plan only, with no public documentation (verified on
           epieos.com/pricing). MOT will not guess the contract; with a key it uses the base URL, header
           and paths YOU copy from what Epieos gives you.
Maltego  : no public headless API to run transforms from outside. MOT exports Maltego-importable
           CSV (Import Graph from Table). Research required for a native .mtgx writer.
Ahmia    : Tor hidden-service search index, queried via Tor. Titles/URLs only; MOT never fetches
           or renders onion pages. Ahmia asks users not to enter personal identifiers: MOT only
           sends domains and keywords there.
"""
from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import parse_qs, quote, urlparse

from mot_connectors_base import (EMPTY, ERROR, EXPORT, HANDOFF, KEY_INVALID, NO_KEY, OK, SKIPPED, Connector, Ctx, Finding,
                                 Meta, NetError, Result, as_list, register)


def _s(x, n: int = 300) -> str:
    return "" if x is None else str(x)[:n]


# =============================================================================== PimEyes
@register
class PimEyes(Connector):
    meta = Meta(id="pimeyes", name="PimEyes", category="Face search", kind="handoff", targets=("image",), free_mode="Manual use on the website (limited free searches)",
                site="https://pimeyes.com/en", key_url="https://pimeyes.com/en", docs_url="https://pimeyes.com/en/privacy-policy", route="tor",
                note="No API exists by vendor policy; MOT does not scrape or automate it. Only search your own face or someone who has consented.")

    def run(self, target, ttype, ctx):
        return self.res(HANDOFF, "handoff", handoff_url=self.meta.site, notes=[
            "PimEyes states it provides no API access, so MOT cannot run this search for you.",
            "Rules of the service: search only your own face, or a person who has given consent.",
            "Open the site in Tor Browser (or with your VPN on), upload the photo there, and keep results out of shared folders.",
            "Strip photo metadata first (EXIF/GPS) before uploading anywhere."])


# =============================================================================== Epieos
FLAT_MAX = 60


def flatten(obj, prefix: str = "", depth: int = 0, out: dict | None = None) -> dict:
    out = {} if out is None else out
    if len(out) >= FLAT_MAX or depth > 4:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), depth + 1, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:15]):
            flatten(v, f"{prefix}[{i}]", depth + 1, out)
    else:
        out[prefix or "value"] = _s(obj, 200)
    return out


def safe_base_url(u: str) -> str:
    p = urlparse(u.strip())
    host = (p.hostname or "").lower()
    if p.scheme != "https" or not host or host == "localhost" or host.endswith((".local", ".internal", ".lan")):
        return ""
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return ""
    except ValueError:
        pass
    return f"https://{p.netloc}".rstrip("/")


@register
class Epieos(Connector):
    meta = Meta(id="epieos", name="Epieos", category="Email intelligence", kind="api", targets=("email", "phone"),
                key_fields=("api_key", "base_url"), optional_fields=("auth_header", "email_path", "phone_path"),
                free_mode="Website: free Member tier (Google, e-mail checker and Skype modules), used by hand", site="https://epieos.com", key_url="https://epieos.com/pricing",
                docs_url="", route="vpn", min_interval=2.0,
                note="Research required: Epieos lists API access only on its Custom plan (contact Epieos) and publishes no API documentation. "
                     "Enter the base URL, auth header name and path templates (with {q}) exactly as Epieos gives them to you. Nothing is guessed. "
                     "Without those details this tool is not searched; use the Epieos website by hand.")

    # No free() on purpose: Epieos has no open API, so this connector is never reported as "will search" without
    # your contract details. The website (free Member tier) is used by hand; the program never sends it the target.
    def keyed(self, target, ttype, ctx, key):
        base = safe_base_url(key.get("base_url", ""))
        path = key.get("email_path" if ttype == "email" else "phone_path", "")
        if not base or "{q}" not in path or not path.startswith("/") or ".." in path:
            return self.res(ERROR, "keyed", error="Epieos adapter not configured: set an https base URL and a path template like /your/path?x={q} from your private docs.")
        hdr = key.get("auth_header", "X-API-Key")
        if not re.fullmatch(r"[A-Za-z0-9-]{1,40}", hdr):
            return self.res(ERROR, error="Invalid auth header name.")
        r = ctx.request(self.meta, "GET", base + path.replace("{q}", quote(target, safe="")), headers={hdr: key["api_key"], "Accept": "application/json"})
        bad = self.http_status(r)
        if bad:
            return bad
        try:
            flat = flatten(r.json())
        except ValueError:
            return self.res(ERROR, error="Epieos response was not JSON.")
        return self.res(OK if flat else EMPTY, "keyed", findings=[Finding("osint", f"Epieos result for {target}", target, data=flat, ents=[(ttype, target, "subject")], confidence=0.6)] if flat else [],
                        notes=["Fields are shown as returned (flattened); no field names were assumed."])

    def selftest(self):
        ok = safe_base_url("https://api.example.com/") and not safe_base_url("http://x.com") and not safe_base_url("https://127.0.0.1") and not safe_base_url("https://localhost")
        return [] if ok and flatten({"a": {"b": [1, 2]}}) == {"a.b[0]": "1", "a.b[1]": "2"} else ["Epieos adapter guards failed"]


# =============================================================================== Maltego
@register
class Maltego(Connector):
    meta = Meta(id="maltego", name="Maltego", category="Graph & analysis", kind="export", targets=("username", "email", "domain", "ip", "phone", "url", "hash", "keyword"),
                free_mode="Maltego CE is free; MOT exports an importable graph (CSV)", site="https://www.maltego.com", key_url="https://www.maltego.com/pricing/",
                docs_url="https://docs.maltego.com", route="vpn",
                note="Maltego has no public headless API for running transforms. Use Export > Maltego CSV, then Maltego: Import Graph from Table. A transform server (so Maltego can call MOT) is on the roadmap.")

    def run(self, target, ttype, ctx):
        return self.res(EXPORT, "export", notes=[
            "Graph bridge: after a search finishes, use 'Maltego CSV' in the results to download entities and links.",
            "In Maltego: Import | Import Graph from Table, then map 'entity_type' and 'value'."])


# =============================================================================== Ahmia
ONION = re.compile(r"(?:https?://)?((?:[a-z2-7]{16}|[a-z2-7]{56})\.onion)(/[^\s\"'<>]*)?", re.I)
STRIP = re.compile(r"<[^>]+>")
AHMIA_ONION = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"


def parse_ahmia(page: str) -> list[dict]:
    out, seen = [], set()
    for m in re.finditer(r"<a\b[^>]*?href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", page, re.S | re.I):
        href, label = html.unescape(m.group(1)), html.unescape(STRIP.sub("", m.group(2))).strip()
        q = parse_qs(urlparse(href).query).get("redirect_url")
        cand = q[0] if q else href
        o = ONION.search(cand)
        if not o or o.group(1).lower() in seen:
            continue
        if o.group(1).lower().startswith("juhanurmihxlp77"):  # skip Ahmia's own address
            continue
        seen.add(o.group(1).lower())
        out.append({"onion": o.group(1).lower(), "url": ("http://" + o.group(1).lower() + (o.group(2) or ""))[:200], "title": re.sub(r"\s+", " ", label)[:140] or "(no title)"})
    return out


@register
class Ahmia(Connector):
    meta = Meta(id="ahmia", name="Ahmia (Tor index)", category="Dark web & leaks", kind="api", targets=("domain", "keyword"), free_mode="Free, no key (via Tor only)",
                site="https://ahmia.fi", key_url="https://ahmia.fi", docs_url="https://ahmia.fi/documentation/", route="tor", needs_tor=True, min_interval=6.0,
                canary=("keyword", "privacy"),
                note="No documented API: HTML is parsed defensively. Only domains/keywords are sent (Ahmia asks users not to submit personal identifiers). Onion pages are never opened by MOT.")

    def free(self, target, ttype, ctx):
        if ttype not in ("domain", "keyword"):
            return self.res(SKIPPED, notes=["Ahmia is only queried with domains/keywords, never with personal identifiers."])
        q = quote(target, safe="")
        err = ""
        for base in (AHMIA_ONION, "https://ahmia.fi"):
            try:
                r = ctx.request(self.meta, "GET", f"{base}/search/?q={q}", timeout=(30, 60), retries=1)
            except NetError as exc:
                err = str(exc)
                continue
            if r.ok:
                rows = parse_ahmia(r.text)
                f = [Finding("darkweb", x["title"], x["onion"], data={"onion_url": x["url"], "never_opened": True}, ents=[("onion", x["onion"], "indexed_mention")], sensitive=True, confidence=0.4) for x in rows[:30]]
                notes = ["Index entries only; content is not fetched. Do not open onion links outside Tor Browser."]
                if not f and "ahmia" not in r.text.lower():
                    notes.append("Page layout not recognised: Ahmia may have changed its HTML (run Diagnostics).")
                return self.res(OK if f else EMPTY, "free", findings=f, notes=notes)
            err = f"HTTP {r.status}"
        return self.res(ERROR, "free", error=f"Ahmia unreachable via Tor ({err}).")

    def selftest(self):
        sample = ('<li><a href="/search/redirect?search_term=x&redirect_url=http://abcdefghijklmnop.onion/page">Example &amp; Title</a></li>'
                  '<a href="http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/">self</a>')
        r = parse_ahmia(sample)
        return [] if len(r) == 1 and r[0]["title"] == "Example & Title" else ["Ahmia parser failed"]
