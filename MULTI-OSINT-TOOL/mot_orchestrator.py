"""MULTI-OSINT-TOOL :: unified search orchestrator.

One query -> every compatible connector in parallel -> one correlated result.
Properties: strict input validation (allow-lists, no shell, no argument injection), per-connector
isolation (a crash or timeout in one tool never affects another), fail-closed shield checks,
circuit breaker, cancellation, per-connector journaling for crash recovery.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import threading
import time
import unicodedata
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FutTimeout
from pathlib import Path
from typing import Callable, Optional

import mot_config as C
import mot_connectors_base as B
import mot_catalog as K
import mot_correlate as X
from mot_netguard import NetGuard, NetworkUnsafe
from mot_vault import Redactor

log = logging.getLogger("mot.orch")

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,38}$")
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
KEYWORD_RE = re.compile(r"^[\w][\w .&'-]{2,59}$", re.UNICODE)
LABEL_RE = re.compile(r"^[\w .-]{1,60}$", re.UNICODE)
CTRL_RE = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
TYPES = ("username", "email", "domain", "ip", "phone", "url", "hash", "keyword", "password", "image")
COMMON_TLDS = set("com net org io co ai app dev info biz us uk de fr es it nl ru cn jp in br au ca ch se no fi dk pl cz at be eu me tv cc xyz online site tech store shop cloud "
                  "security gov edu mil int mobi name pro asia africa london nyc berlin tokyo ie nz za mx ar cl pt gr tr il ae sa kr tw hk sg my id ph th vn ua ro hu bg rs hr sk si lt lv ee "
                  "is lu li mt cy ge am az by kz uz pk bd lk np ng ke gh tz et eg ma dz tn".split())


class InputError(ValueError):
    pass


def clean_text(raw: str) -> str:
    s = unicodedata.normalize("NFKC", str(raw)).strip()
    if CTRL_RE.search(s):
        raise InputError("Input contains control or invisible characters.")
    return s


def detect_type(raw: str) -> str:
    t = clean_text(raw)
    if re.match(r"^https?://", t, re.I):
        return "url"
    if EMAIL_RE.match(t):
        return "email"
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(t):
        return "hash"
    if re.match(r"^\+[0-9 ().-]{6,22}$", t):
        return "phone"
    if DOMAIN_RE.match(t.lower().rstrip(".")) and t.lower().rstrip(".").rsplit(".", 1)[-1] in COMMON_TLDS:
        return "domain"
    if USER_RE.match(t):
        return "username"
    if KEYWORD_RE.match(t):
        return "keyword"
    raise InputError("Could not recognise this input. Choose the type manually.")


def normalize(ttype: str, raw: str) -> str:
    if ttype not in TYPES:
        raise InputError("Unknown target type.")
    if ttype == "password":
        if not (1 <= len(raw) <= 128) or CTRL_RE.search(raw):
            raise InputError("Password must be 1-128 printable characters.")
        return raw
    t = clean_text(raw)
    if not t or len(t) > 500:
        raise InputError("Input is empty or too long.")
    if t.startswith("-"):
        raise InputError("Input may not start with '-'.")
    if ttype == "email":
        t = t.lower()
        if not EMAIL_RE.match(t):
            raise InputError("Invalid email address.")
    elif ttype == "domain":
        t = t.lower().rstrip(".")
        try:
            t = t.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise InputError("Invalid domain.") from exc
        if not DOMAIN_RE.match(t):
            raise InputError("Invalid domain.")
    elif ttype == "ip":
        try:
            ip = ipaddress.ip_address(t)
        except ValueError as exc:
            raise InputError("Invalid IP address.") from exc
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise InputError("Only public IP addresses can be investigated.")
        t = str(ip)
    elif ttype == "username":
        t = t.lstrip("@")
        if not USER_RE.match(t):
            raise InputError("Username: 2-39 letters, digits, dot, dash, underscore.")
    elif ttype == "hash":
        if not HASH_RE.match(t):
            raise InputError("Hash must be MD5, SHA-1 or SHA-256 hex.")
        t = t.lower()
    elif ttype == "phone":
        try:
            import phonenumbers

            n = phonenumbers.parse(t, None)
            if not phonenumbers.is_possible_number(n):
                raise InputError("Phone number is not possible. Use international format (+CC...).")
            t = phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164)
        except InputError:
            raise
        except Exception as exc:
            raise InputError("Phone number must be in international format, e.g. +14155552671.") from exc
    elif ttype == "url":
        from urllib.parse import urlparse

        u = urlparse(t)
        if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or re.search(r"\s", t):
            raise InputError("URL must be http(s) without credentials or spaces.")
        t = t[:500]
    elif ttype == "keyword":
        if not KEYWORD_RE.match(t):
            raise InputError("Keyword: 3-60 letters, digits, spaces, . & ' -")
    elif ttype == "image":
        if not LABEL_RE.match(t):
            raise InputError("Use a short label (no file path).")
    return t


class Job:
    def __init__(self, target: str, ttype: str, plan: list, save: bool, purpose: str, prior: Optional[dict] = None):
        self.id = uuid.uuid4().hex[:12]
        self.target, self.ttype, self.save, self.purpose = target, ttype, save, purpose
        self.created = time.time()
        self.finished = 0.0
        self.status = "running"
        self.plan = [c.id for c in plan]
        self.results: dict[str, B.Result] = dict(prior or {})
        self.state = {c.id: ("done" if c.id in self.results else "queued") for c in plan}
        self.cancel = threading.Event()
        self.case: Optional[dict] = None
        self.error = ""
        self.lock = threading.Lock()

    def public(self, with_case: bool = True, skip: frozenset = frozenset()) -> dict:
        """JSON-safe view. `skip` = connector ids whose full results the client already holds (incremental polling)."""
        with self.lock:
            res = {}
            for k, v in self.results.items():
                if k in skip:
                    res[k] = {"connector": k, "status": v.status, "mode": v.mode, "elapsed": v.elapsed, "findings": [], "notes": [], "error": "", "delivered": True}
                else:
                    res[k] = v.to_dict(True)
            for k, v in res.items():  # every result says which source it came from and what that source is used for
                ent = K.BY_ID.get(k)
                if ent:
                    v["name"], v["use"], v["category"] = ent.name, ent.use, ent.category
            d = {"id": self.id, "target": self.target if self.ttype != "password" else "(password not shown)", "ttype": self.ttype, "status": self.status,
                 "created": self.created, "finished": self.finished, "state": dict(self.state), "plan": self.plan, "error": self.error, "results": res, "saved": bool(self.save)}
            if with_case and self.case:
                d["case"] = {k: self.case[k] for k in ("id", "summary", "score", "graph") if k in self.case}
            return d


class Orchestrator:
    def __init__(self, cfg: C.Config, guard: NetGuard, key_getter: Callable[[str], Optional[dict]], audit, store, journal, tune: dict):
        self.cfg, self.guard, self.key_getter, self.audit, self.store, self.journal = cfg, guard, key_getter, audit, store, journal
        self.jobs: dict[str, Job] = {}
        self.workers = cfg.get("search", "max_workers", default=0) or tune.get("max_workers", 8)
        self.cli_sem = threading.Semaphore(tune.get("cli_parallel", 2))
        self.fail_count: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()
        self.tmp_dir = C.DATA / "tmp"

    # ---- planning
    def connectors_for(self, ttype: str, selected: Optional[list] = None) -> list:
        out = []
        for cid, c in B.REGISTRY.items():
            if not c.supports(ttype):
                continue
            if selected is not None and cid not in selected:
                continue
            if not self.cfg.connector(cid).get("enabled", True):
                continue  # a disabled tool is authoritative: never run, even when selected explicitly
            out.append(c)
        return out

    def start(self, raw_target: str, ttype: Optional[str] = None, selected: Optional[list] = None, save: bool = True,
              face_consent: bool = False, purpose: str = "", prior: Optional[dict] = None) -> Job:
        ttype = ttype or detect_type(raw_target)
        target = normalize(ttype, raw_target)
        if ttype == "image" and not face_consent:
            raise InputError("Face search requires you to confirm it is your own face or that the person consented.")
        plan = self.connectors_for(ttype, selected)
        if not plan:
            raise InputError("No enabled tool supports this target type.")
        job = Job(target, ttype, plan, save and ttype != "password", purpose, prior)
        with self._lock:
            self.jobs[job.id] = job
            for old in sorted(self.jobs.values(), key=lambda j: j.created)[:-30]:
                if old.status != "running":
                    self.jobs.pop(old.id, None)
        if ttype == "password":
            Redactor.register(target)  # never let a searched password reach logs or error text
        self.audit.append("search_started", job=job.id, type=ttype, target_h="" if ttype == "password" else self.audit.hash_target(target), tools=job.plan, purpose=purpose[:80], face_consent=bool(face_consent and ttype == "image"))
        self._journal(job)
        threading.Thread(target=self._run, args=(job,), name=f"mot-job-{job.id}", daemon=True).start()
        return job

    def get(self, jid: str) -> Optional[Job]:
        return self.jobs.get(jid)

    def cancel(self, jid: str) -> bool:
        j = self.jobs.get(jid)
        if j and j.status == "running":
            j.cancel.set()
            return True
        return False

    # ---- execution
    def _breaker_open(self, cid: str) -> bool:
        n, ts = self.fail_count.get(cid, (0, 0.0))
        return n >= 3 and time.time() - ts < 60

    def _run_one(self, job: Job, conn: B.Connector, ctx: B.Ctx) -> None:
        cid = conn.id
        with job.lock:
            job.state[cid] = "running"
        res: B.Result
        try:
            if job.cancel.is_set():
                res = conn.res(B.CANCELLED)
            elif self._breaker_open(cid):
                res = conn.res(B.SKIPPED, notes=["Skipped: this tool failed 3 times in a row; retry in about a minute."])
            elif self.guard.state.offline and conn.meta.kind in ("api", "cli"):
                res = conn.res(B.OFFLINE, notes=["No connectivity. Open the Cases tab for earlier results."])
            else:
                sem = self.cli_sem if conn.meta.kind in ("cli", "local") else None
                if sem:
                    sem.acquire()
                try:
                    res = conn.run(job.target, job.ttype, ctx)
                finally:
                    if sem:
                        sem.release()
        except Exception as exc:  # absolute last line of defence
            log.exception("connector wrapper failure: %s", cid)
            res = conn.res(B.ERROR, error=f"Internal error: {type(exc).__name__}")
        n, ts = self.fail_count.get(cid, (0, 0.0))
        self.fail_count[cid] = ((n + 1, time.time()) if res.status == B.ERROR else (0, 0.0))
        with job.lock:
            job.results[cid] = res
            job.state[cid] = "done"
        self._journal(job)

    def _run(self, job: Job) -> None:
        t0 = time.time()
        deadline = t0 + self.cfg.get("search", "job_timeout", default=300)
        ctx = B.Ctx(self.guard, self.key_getter, self.cfg, job.id, job.cancel, deadline, self.tmp_dir)
        conns = [B.REGISTRY[c] for c in job.plan if c not in job.results]
        try:
            with ThreadPoolExecutor(max_workers=max(2, self.workers), thread_name_prefix="mot-conn") as pool:
                futs = {pool.submit(self._run_one, job, c, ctx): c for c in conns}
                try:
                    for _ in as_completed(futs, timeout=max(5, deadline - time.time() + 15)):
                        pass
                except FutTimeout:
                    job.cancel.set()
                    log.warning("job %s hit its deadline", job.id)
                    for f in futs:
                        f.cancel()
            with job.lock:
                for c in conns:
                    if c.id not in job.results:
                        job.results[c.id] = c.res(B.TIMEOUT, error="Did not finish before the job deadline.")
                        job.state[c.id] = "done"
            self._finish(job)
        except Exception as exc:
            log.exception("job crashed")
            job.error = f"{type(exc).__name__}"
            job.status = "error"
        finally:
            job.finished = time.time()
            for d in self.tmp_dir.glob(f"*-{job.id}"):  # scratch folders of the CLI tools (reports, per-run homes)
                shutil.rmtree(d, ignore_errors=True)

    def _finish(self, job: Job) -> None:
        results = [job.results[c] for c in job.plan if c in job.results]
        graph = X.build_graph(job.target, job.ttype, results)
        score = X.exposure_score(results)
        summary = X.summarize(job.target, job.ttype, results, graph, score)
        persist_secrets = bool(self.cfg.get("privacy", "persist_secrets", default=False))
        shown = job.target if job.ttype != "password" else "(password)"
        case = {"id": self.store.new_id(), "created": job.created, "title": f"{job.ttype}: {shown}", "target": shown, "ttype": job.ttype, "summary": summary, "score": score,
                "graph": graph, "results": [r.to_dict(public=not persist_secrets) for r in results], "job": job.id, "purpose": job.purpose[:200],
                "tools_ok": sum(1 for r in results if r.status == B.OK)}
        job.case = case
        if job.save:
            try:
                self.store.save(case)
            except Exception:
                log.exception("case save failed")
                job.case["notes"] = ["Case could not be saved; results are still available in this session."]
        counts: dict[str, int] = {}
        for r in results:
            counts[r.status] = counts.get(r.status, 0) + 1
        self.audit.append("search_finished", job=job.id, statuses=counts, score=score["score"], saved=job.save)
        job.status = "cancelled" if job.cancel.is_set() and not any(r.status == B.OK for r in results) else "done"
        self.journal.clear(job.id)

    def _journal(self, job: Job) -> None:
        try:
            with job.lock:
                snap = {"id": job.id, "target": job.target, "ttype": job.ttype, "created": job.created, "plan": job.plan, "state": dict(job.state),
                        "results": {k: v.to_dict(True) for k, v in job.results.items()}, "purpose": job.purpose}
            if job.ttype != "password":
                self.journal.write(job.id, snap)
        except Exception:
            log.exception("journal write failed")

    # ---- reveal (audited)
    def reveal(self, jid: str, fid: str) -> dict:
        j = self.jobs.get(jid)
        if not j:
            raise InputError("Reveal is only possible for searches from this session.")
        for r in j.results.values():
            for f in r.findings:
                if f.fid == fid:
                    secret = {k: v for k, v in f.data.items() if str(k).startswith("_")}
                    if not secret:
                        raise InputError("Nothing to reveal.")
                    self.audit.append("secret_revealed", job=jid, connector=r.connector, fid=fid)
                    return {k.lstrip("_"): v for k, v in secret.items()}
        raise InputError("Finding not found.")

    @staticmethod
    def _prior_from_snap(snap: dict) -> dict:
        prior = {}
        for cid, rd in (snap.get("results") or {}).items():
            if cid in B.REGISTRY and snap.get("state", {}).get(cid) == "done":
                try:
                    prior[cid] = B.Result.from_dict(rd)
                except (TypeError, ValueError):
                    continue
        return prior

    def resume(self, snap: dict) -> Job:
        """Re-run only the tools that had not finished when the app crashed; keep the finished results."""
        plan = [c for c in snap["plan"] if c in B.REGISTRY]
        return self.start(snap["target"], snap["ttype"], selected=plan, save=True, face_consent=True, purpose="resumed after crash", prior=self._prior_from_snap(snap))

    def recover_case(self, snap: dict) -> dict:
        """Turn the tools that DID finish before the crash into a saved case (no new network traffic)."""
        prior = self._prior_from_snap(snap)
        plan = [B.REGISTRY[c] for c in snap["plan"] if c in B.REGISTRY]
        if not prior or not plan:
            raise InputError("Nothing finished before the crash, so there is nothing to recover. Use Resume instead.")
        job = Job(snap["target"], snap["ttype"], plan, True, "recovered after crash", prior)
        job.id = str(snap.get("id", job.id))[:24]
        self._finish(job)
        done, total = len(prior), len(snap["plan"])
        if job.case is not None:
            job.case["notes"] = [f"Recovered after a crash: {done} of {total} tools had finished. Run the rest with Resume."]
            if job.save:
                self.store.save(job.case)
        self.audit.append("job_recovered", job=job.id, finished=done, planned=total)
        return job.case
