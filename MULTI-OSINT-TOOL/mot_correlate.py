"""MULTI-OSINT-TOOL :: correlation engine.

Turns many tools' findings into ONE entity graph: duplicates merge, entities seen by several
independent sources gain confidence, and a transparent rule-based exposure score is produced
(no black box: every point is listed with its reason). All exports neutralise spreadsheet
formula injection and never include raw credentials.
"""
from __future__ import annotations

import csv
import io
import json
import time

MALTEGO_TYPES = {
    "email": "maltego.EmailAddress", "domain": "maltego.Domain", "hostname": "maltego.DNSName", "ip": "maltego.IPv4Address",
    "username": "maltego.Alias", "alias": "maltego.Alias", "url": "maltego.URL", "phone": "maltego.PhoneNumber", "person": "maltego.Person",
    "asn": "maltego.AS", "onion": "maltego.Website", "hash": "maltego.Hash", "location": "maltego.Location",
}
DEFAULT_MALTEGO = "maltego.Phrase"


def strip_secrets(o):
    """Remove every `_`-prefixed field (raw credentials/secrets) from any nested structure."""
    if isinstance(o, dict):
        return {k: strip_secrets(v) for k, v in o.items() if not str(k).startswith("_")}
    if isinstance(o, list):
        return [strip_secrets(x) for x in o]
    return o


_MD_SPECIAL = str.maketrans({"\\": "\\\\", "`": "'", "<": "&lt;", ">": "&gt;", "[": "(", "]": ")", "|": "/", "*": "\\*", "_": "\\_", "#": "\\#", "\n": " ", "\r": " ", "\t": " "})


def md_safe(v, n: int = 240) -> str:
    """Findings contain third-party text: neutralise Markdown/HTML so a hostile profile name cannot inject links or markup."""
    return ("" if v is None else str(v))[:n].translate(_MD_SPECIAL)


def md_url(u) -> str:
    """URLs are shown as inert code (never auto-linked): an accidental click on an OSINT lead can de-anonymise you."""
    return "`" + ("" if u is None else str(u))[:300].replace("`", "").replace("\n", "").replace("\r", "") + "`"


def csv_safe(v) -> str:
    """OWASP CSV-injection defence: neutralise cells that spreadsheets would execute."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


_CASEFOLD_TYPES = {"email", "domain", "hostname", "ip", "onion", "hash", "url_host"}


def norm_entity(et: str, ev) -> str:
    v = str(ev).strip()[:300]
    return v.lower().rstrip(".") if et in _CASEFOLD_TYPES else v


def confidence_from_sources(n: int) -> float:
    return {0: 0.0, 1: 0.4, 2: 0.7}.get(n, 0.9)


def build_graph(target: str, ttype: str, results: list) -> dict:
    root = (ttype, norm_entity(ttype, target))
    nodes: dict[tuple, dict] = {root: {"type": ttype, "value": target, "sources": set(), "relations": set(), "root": True}}
    edges: dict[tuple, dict] = {}
    for res in results:
        for f in res.findings:
            for et, ev, rel in f.ents:
                ev = norm_entity(et, ev)
                if not ev or (et, ev) == root:
                    continue
                n = nodes.setdefault((et, ev), {"type": et, "value": ev, "sources": set(), "relations": set()})
                n["sources"].add(res.connector)
                n["relations"].add(rel)
                e = edges.setdefault((root, (et, ev), rel), {"label": rel, "sources": set()})
                e["sources"].add(res.connector)
    idx = {k: i for i, k in enumerate(nodes)}
    out_nodes = [{"id": idx[k], "type": v["type"], "value": v["value"], "sources": sorted(v["sources"]), "relations": sorted(v["relations"]),
                  "confidence": 1.0 if v.get("root") else confidence_from_sources(len(v["sources"]))} for k, v in nodes.items()]
    out_edges = [{"source": idx[a], "target": idx[b], "label": lab, "sources": sorted(v["sources"])} for (a, b, lab), v in edges.items()]
    by_type: dict[str, int] = {}
    for n in out_nodes:
        by_type[n["type"]] = by_type.get(n["type"], 0) + 1
    multi = sorted((n for n in out_nodes if len(n["sources"]) >= 2), key=lambda n: -len(n["sources"]))[:15]
    return {"nodes": out_nodes, "edges": out_edges, "stats": {"entities": len(out_nodes) - 1, "by_type": by_type}, "corroborated": multi}


def exposure_score(results: list) -> dict:
    pts, why = 0, []

    def add(n: int, text: str, cap: int) -> None:
        nonlocal pts
        n = min(n, cap)
        if n > 0:
            pts += n
            why.append({"points": n, "reason": text})

    kinds: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            kinds[f.kind] = kinds.get(f.kind, 0) + 1
    breaches = kinds.get("breach", 0)
    add(breaches * 6, f"{breaches} known data breach(es)", 30)
    add(kinds.get("credential", 0) * 5, f"{kinds.get('credential', 0)} credential record(s) in breach databases", 25)
    add(25 if kinds.get("infostealer") else 0, "Appears in infostealer malware logs (device compromise indicator)", 25)
    add(kinds.get("password_exposure", 0) * 30, "Password found in breach corpora", 30)
    add(10 if kinds.get("darkweb") else 0, "Mentioned in Tor/dark-web indexes", 10)
    add(kinds.get("paste", 0) * 3, f"{kinds.get('paste', 0)} public paste(s)", 9)
    add(kinds.get("vuln", 0) * 2, f"{kinds.get('vuln', 0)} possible vulnerabilities on exposed hosts", 12)
    for r in results:
        for f in r.findings:
            if f.kind == "reputation":
                mal = (f.data.get("stats") or {}).get("malicious", 0)
                if isinstance(mal, int) and mal > 0:
                    add(mal * 2, f"{mal} security engine(s) flag it as malicious (VirusTotal)", 15)
    accounts = kinds.get("account", 0)
    add(accounts // 5, f"{accounts} public account(s) found (footprint size)", 8)
    score = min(100, pts)
    level = "critical" if score >= 70 else "high" if score >= 45 else "moderate" if score >= 20 else "low"
    return {"score": score, "level": level, "factors": sorted(why, key=lambda w: -w["points"]),
            "disclaimer": "Heuristic exposure indicator, not a verdict. Corroborate before acting."}


def summarize(target: str, ttype: str, results: list, graph: dict, score: dict) -> str:
    ok = [r for r in results if r.status in ("ok",)]
    parts = [f"{len(ok)} of {len(results)} tools returned findings for {ttype} '{target}'.",
             f"{graph['stats']['entities']} unique related entities; exposure {score['score']}/100 ({score['level']})."]
    if graph["corroborated"]:
        c = graph["corroborated"][0]
        parts.append(f"Most corroborated: {c['type']} {c['value']} ({len(c['sources'])} sources).")
    return " ".join(parts)


# ----------------------------------------------------------------------------- exports
def export_json(case: dict) -> bytes:
    return json.dumps(strip_secrets(case), indent=2, sort_keys=True, default=str).encode("utf-8")


def export_csv(case: dict) -> bytes:
    case = strip_secrets(case)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["connector", "mode", "kind", "title", "value", "url", "confidence", "sensitive"])
    for r in case["results"]:
        for f in r["findings"]:
            w.writerow([csv_safe(x) for x in (r["connector"], r["mode"], f["kind"], f["title"], f["value"], f["url"], f["confidence"], f["sensitive"])])
    return buf.getvalue().encode("utf-8")


def export_markdown(case: dict) -> bytes:
    case = strip_secrets(case)
    L = ["# MULTI-OSINT-TOOL report", "", f"- Target: {md_url(case.get('target', ''))} ({md_safe(case.get('ttype', ''), 20)})",
         f"- Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(case.get('created', 0)))}",
         f"- Exposure: {case['score']['score']}/100 ({md_safe(case['score']['level'], 20)})", "", md_safe(case.get("summary", ""), 600), "", "## Exposure factors"]
    L += [f"- +{int(f['points'])}: {md_safe(f['reason'])}" for f in case["score"]["factors"]] or ["- none"]
    L += ["", "## Findings by tool"]
    for r in case["results"]:
        L.append(f"### {md_safe(r['connector'], 40)}: {md_safe(r['status'], 20)} ({md_safe(r.get('mode') or 'n/a', 20)})")
        for n in r.get("notes", []):
            L.append(f"- _{md_safe(n)}_")
        if r.get("error"):
            L.append(f"- error: {md_safe(r['error'])}")
        for f in r.get("findings", [])[:50]:
            L.append(f"- **{md_safe(f['kind'], 30)}**: {md_safe(f['title'])}" + (f" {md_url(f['url'])}" if f.get("url") else ""))
        L.append("")
    L += ["---", "Generated by MULTI-OSINT-TOOL. Findings are leads, not proof. URLs are shown as inert text on purpose. Passwords/credentials are never exported."]
    return "\n".join(L).encode("utf-8")


def export_maltego(case: dict) -> tuple[bytes, bytes]:
    """Two CSVs for Maltego 'Import Graph from Table': entities and links."""
    g = strip_secrets(case)["graph"]
    ent, lnk = io.StringIO(), io.StringIO()
    we, wl = csv.writer(ent), csv.writer(lnk)
    we.writerow(["entity_type", "value", "label", "sources", "confidence"])
    wl.writerow(["source_value", "target_value", "label", "sources"])
    by_id = {n["id"]: n for n in g["nodes"]}
    for n in g["nodes"]:
        we.writerow([MALTEGO_TYPES.get(n["type"], DEFAULT_MALTEGO), csv_safe(n["value"]), csv_safe(f"{n['type']}"), csv_safe("|".join(n["sources"])), n["confidence"]])
    for e in g["edges"]:
        wl.writerow([csv_safe(by_id[e["source"]]["value"]), csv_safe(by_id[e["target"]]["value"]), csv_safe(e["label"]), csv_safe("|".join(e["sources"]))])
    return ent.getvalue().encode("utf-8"), lnk.getvalue().encode("utf-8")
