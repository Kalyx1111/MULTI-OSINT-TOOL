"""End-to-end tests of the search pipeline with deterministic fake connectors (no network)."""
import json
import logging
import os
import secrets
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mot_testlib as T  # noqa: E402  (must be first: isolates MOT_DATA)

import mot_connectors_base as B
import mot_correlate as X
from mot_orchestrator import InputError, detect_type, normalize
from mot_vault import Redactor

CALLS = {"ok": 0, "slow": 0, "crash": 0}
PW = secrets.token_urlsafe(24)
FAKE_KEY = secrets.token_hex(12)


class FakeOK(B.Connector):
    meta = B.Meta(id="fake_ok", name="Fake OK", category="Test", kind="local", targets=("email", "username", "domain", "password"))

    def free(self, target, ttype, ctx):
        CALLS["ok"] += 1
        return self.res(B.OK, "free", findings=[
            B.Finding("breach", "Breach A", target, ents=[("domain", "A.Example", "breached_in")]),
            B.Finding("account", '=HYPERLINK("http://evil.example","click")', target, url="https://x.example/u", ents=[("alias", "=cmd|' /C calc'!A0", "alias")]),
            B.Finding("credential", "Credential record", target, data={"_password": PW, "user": "x"}, sensitive=True)])


class FakeOK2(B.Connector):
    meta = B.Meta(id="fake_ok2", name="Fake OK 2", category="Test", kind="local", targets=("email", "username", "domain"))

    def free(self, target, ttype, ctx):
        return self.res(B.OK, "free", findings=[B.Finding("breach", "Breach A again", target, ents=[("domain", "a.example", "breached_in")])])


class FakeSlow(B.Connector):
    meta = B.Meta(id="fake_slow", name="Fake Slow", category="Test", kind="local", targets=("email", "username", "domain"))

    def free(self, target, ttype, ctx):
        CALLS["slow"] += 1
        for _ in range(300):
            ctx.sleep(0.1)
        return self.res(B.OK, "free")


class FakeCrash(B.Connector):
    meta = B.Meta(id="fake_crash", name="Fake Crash", category="Test", kind="local", targets=("email", "username", "domain"))

    def free(self, target, ttype, ctx):
        CALLS["crash"] += 1
        raise RuntimeError(f"boom {PW}")


class FakeKeyed(B.Connector):
    meta = B.Meta(id="fake_keyed", name="Fake Keyed", category="Test", kind="local", targets=("email",), key_fields=("api_key",))

    def keyed(self, target, ttype, ctx, key):
        return self.res(B.KEY_INVALID, error="bad key")

    def free(self, target, ttype, ctx):
        return self.res(B.OK, "free", findings=[B.Finding("breach", "free tier hit", target)])


FAKES = [FakeOK(), FakeOK2(), FakeSlow(), FakeCrash(), FakeKeyed()]


def setUpModule():
    logging.disable(logging.CRITICAL)  # the crash fixture logs tracebacks on purpose; keep test output readable


def tearDownModule():
    logging.disable(logging.NOTSET)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        for f in FAKES:
            B.REGISTRY[f.id] = f
        for k in CALLS:
            CALLS[k] = 0
        self.s = T.Stack("direct", keys={"fake_keyed": {"api_key": FAKE_KEY}})

    def tearDown(self):
        for f in FAKES:
            B.REGISTRY.pop(f.id, None)

    def run_job(self, target="victim@example.com", ttype="email", sel=("fake_ok", "fake_ok2", "fake_crash", "fake_keyed"), **kw):
        job = self.s.orch.start(target, ttype, selected=list(sel), **kw)
        return self.s.wait(job)

    # ------------------------------------------------------------------ isolation + correlation
    def test_crash_in_one_tool_does_not_affect_others(self):
        j = self.run_job()
        self.assertEqual(j.status, "done")
        st = {k: v.status for k, v in j.results.items()}
        self.assertEqual(st["fake_ok"], B.OK)
        self.assertEqual(st["fake_ok2"], B.OK)
        self.assertEqual(st["fake_crash"], B.ERROR)
        self.assertNotIn(PW, j.results["fake_crash"].error)  # no secret/stack detail in the error shown to the user
        self.assertEqual(j.results["fake_keyed"].mode, "free")  # bad key -> automatic free-tier fallback
        self.assertTrue(any("fell back" in n for n in j.results["fake_keyed"].notes))

    def test_correlation_merges_and_scores(self):
        j = self.run_job()
        g = j.case["graph"]
        a = [n for n in g["nodes"] if n["value"] == "a.example"]
        self.assertEqual(len(a), 1, "A.Example and a.example must merge")
        self.assertEqual(sorted(a[0]["sources"]), ["fake_ok", "fake_ok2"])
        self.assertGreaterEqual(a[0]["confidence"], 0.7)
        self.assertGreater(j.case["score"]["score"], 0)
        self.assertTrue(j.case["score"]["factors"], "score must list its reasons")

    # ------------------------------------------------------------------ secrets
    def test_secrets_never_reach_public_view_case_or_exports(self):
        j = self.run_job()
        pub = json.dumps(j.public())
        self.assertNotIn(PW, pub)
        blob = json.dumps(j.case)
        self.assertNotIn(PW, blob)
        for fn in (X.export_json, X.export_csv, X.export_markdown):
            self.assertNotIn(PW.encode(), fn(j.case), fn.__name__)
        ent, lnk = X.export_maltego(j.case)
        self.assertNotIn(PW.encode(), ent + lnk)
        # raw reveal exists only in memory and is audited
        fid = next(f.fid for f in j.results["fake_ok"].findings if f.kind == "credential")
        self.assertEqual(self.s.orch.reveal(j.id, fid)["password"], PW)
        self.assertTrue(any(r["event"] == "secret_revealed" for r in self.s.audit.tail()))

    def test_secrets_stripped_even_if_case_was_built_with_persist_secrets(self):
        self.s.cfg.set("privacy", "persist_secrets", True)
        j = self.run_job()
        self.assertIn(PW, json.dumps(j.case))  # opt-in persistence really contains it ...
        for fn in (X.export_json, X.export_csv, X.export_markdown):
            self.assertNotIn(PW.encode(), fn(j.case))  # ... but exports ALWAYS strip it

    # ------------------------------------------------------------------ exports
    def test_csv_and_markdown_injection_neutralised(self):
        j = self.run_job()
        csv_text = X.export_csv(j.case).decode()
        for line in csv_text.splitlines()[1:]:
            for cell in line.split(","):
                self.assertFalse(cell.startswith(("=", "+", "@")) and not cell.startswith("'"), cell)
        self.assertIn("'=HYPERLINK", csv_text)
        md = X.export_markdown(j.case).decode()
        self.assertNotIn("[click]", md)
        self.assertNotIn("<", md.replace("&lt;", ""))
        ent, _ = X.export_maltego(j.case)
        self.assertIn("'=cmd", ent.decode())

    # ------------------------------------------------------------------ persistence
    def test_case_is_encrypted_at_rest_and_roundtrips(self):
        j = self.run_job(target="very.unique.target@example.com")
        cid = j.case["id"]
        raw = (self.s.store.dir / f"{cid}.motc").read_bytes()
        self.assertNotIn(b"very.unique.target", raw)
        self.assertEqual(self.s.store.load(cid)["target"], "very.unique.target@example.com")
        data = bytearray(raw)
        data[-5] ^= 1
        (self.s.store.dir / f"{cid}.motc").write_bytes(bytes(data))
        with self.assertRaises(Exception):
            self.s.store.load(cid)
        listing = self.s.store.list()
        self.assertTrue(listing[0].get("damaged"))

    def test_password_search_is_never_stored_or_logged(self):
        j = self.run_job(target=PW, ttype="password", sel=("fake_ok",))
        self.assertEqual(j.status, "done")
        self.assertEqual(list(self.s.store.dir.glob("*.motc")), [], "password searches must not create a case")
        self.assertEqual(j.public()["target"], "(password not shown)")
        self.assertNotIn(PW, json.dumps(self.s.audit.tail(100)))
        self.assertNotIn(PW, Redactor.redact(f"error while checking {PW} now"))
        self.assertEqual(list(self.s.journal.dir.glob("job-*.motj")), [])

    # ------------------------------------------------------------------ control
    def test_cancel_stops_a_slow_tool_quickly(self):
        job = self.s.orch.start("who@example.com", "email", selected=["fake_slow", "fake_ok"])
        time.sleep(0.5)
        t0 = time.time()
        self.assertTrue(self.s.orch.cancel(job.id))
        self.s.wait(job, 10)
        self.assertLess(time.time() - t0, 5)
        self.assertEqual(job.results["fake_slow"].status, B.CANCELLED)
        self.assertIn(job.results["fake_ok"].status, (B.OK, B.CANCELLED))

    def test_job_deadline_times_out_slow_tool(self):
        self.s.cfg.data["search"]["job_timeout"] = 30
        orig = self.s.cfg.get

        def fast_deadline(*k, default=None):
            return 2 if k == ("search", "job_timeout") else orig(*k, default=default)

        self.s.cfg.get = fast_deadline
        job = self.s.orch.start("who@example.com", "email", selected=["fake_slow", "fake_ok"])
        self.s.wait(job, 25)
        self.assertEqual(job.status, "done")
        self.assertIn(job.results["fake_slow"].status, (B.TIMEOUT, B.CANCELLED))
        self.assertEqual(job.results["fake_ok"].status, B.OK)

    def test_circuit_breaker_skips_a_repeatedly_failing_tool(self):
        for _ in range(3):
            self.run_job(sel=("fake_crash",))
        self.assertEqual(CALLS["crash"], 3)
        j = self.run_job(sel=("fake_crash",))
        self.assertEqual(j.results["fake_crash"].status, B.SKIPPED)
        self.assertEqual(CALLS["crash"], 3, "tripped breaker must not call the tool again")

    def test_disabled_connector_never_runs_even_if_selected(self):
        self.s.cfg.set("connectors", "fake_ok", {"enabled": False, "route": "auto"})
        with self.assertRaises(InputError):
            self.s.orch.start("who@example.com", "email", selected=["fake_ok"])
        self.assertEqual(CALLS["ok"], 0)

    # ------------------------------------------------------------------ crash recovery
    def test_resume_reruns_only_unfinished_tools_and_keeps_finished_ones(self):
        first = self.run_job(sel=("fake_ok", "fake_ok2"))
        snap = {"id": "abc", "target": first.target, "ttype": "email", "plan": ["fake_ok", "fake_ok2"], "state": {"fake_ok": "done", "fake_ok2": "running"},
                "results": {"fake_ok": first.results["fake_ok"].to_dict(True)}}
        CALLS["ok"] = 0
        j = self.s.wait(self.s.orch.resume(snap))
        self.assertEqual(CALLS["ok"], 0, "finished tool must not be re-run")
        self.assertEqual(j.results["fake_ok2"].status, B.OK)
        self.assertEqual(j.results["fake_ok"].status, B.OK)
        self.assertEqual(len(j.results["fake_ok"].findings), 3)

    def test_journal_is_written_encrypted_and_cleared_on_completion(self):
        job = self.s.orch.start("who@example.com", "email", selected=["fake_slow"])
        time.sleep(0.6)
        files = list(self.s.journal.dir.glob("job-*.motj"))
        self.assertEqual(len(files), 1)
        self.assertNotIn(b"who@example.com", files[0].read_bytes())
        pend = self.s.journal.pending()
        self.assertEqual(pend[0]["target"], "who@example.com")
        self.s.orch.cancel(job.id)
        self.s.wait(job, 10)
        self.assertEqual(list(self.s.journal.dir.glob("job-*.motj")), [])

    # ------------------------------------------------------------------ shield
    def test_shield_down_blocks_every_network_tool_fail_closed(self):
        s = T.Stack("vpn")  # no VPN adapter + no baseline in the sandbox => unsafe
        calls = {"n": 0}

        class NetTool(B.Connector):
            meta = B.Meta(id="fake_net", name="Net", category="Test", kind="api", targets=("domain",))

            def free(self, target, ttype, ctx):
                calls["n"] += 1
                ctx.request(self.meta, "GET", "https://example.com/")
                return self.res(B.OK)

        B.REGISTRY["fake_net"] = NetTool()
        try:
            j = s.wait(s.orch.start("example.com", "domain", selected=["fake_net"]))
        finally:
            B.REGISTRY.pop("fake_net", None)
        r = j.results["fake_net"]
        self.assertEqual(r.status, B.BLOCKED, r.error)
        self.assertIn("VPN", r.error)


class InputValidationTests(unittest.TestCase):
    EVIL = ["a; rm -rf /", "$(id)", "`id`", "x' OR '1'='1", "../../etc/passwd", "--help", "-h", "a\x00b", "a\nb", "a b|c", "<script>alert(1)</script>",
            "x" * 600, "user@exa mple.com", "javascript:alert(1)", "file:///etc/passwd", "\u202eevil", "\u200bzero"]

    def test_username_domain_email_hash_reject_every_hostile_string(self):
        for ttype in ("username", "domain", "email", "hash", "ip", "phone", "url"):
            for e in self.EVIL:
                with self.assertRaises(InputError, msg=f"{ttype}: {e!r}"):
                    normalize(ttype, e)

    def test_valid_inputs_are_normalised(self):
        self.assertEqual(normalize("email", " Alice@Example.COM "), "alice@example.com")
        self.assertEqual(normalize("domain", "Example.COM."), "example.com")
        self.assertEqual(normalize("domain", "münchen.de"), "xn--mnchen-3ya.de")
        self.assertEqual(normalize("username", "@some_user"), "some_user")
        self.assertEqual(normalize("ip", "8.8.8.8"), "8.8.8.8")
        self.assertEqual(normalize("phone", "+1 415 555 2671"), "+14155552671")
        self.assertEqual(normalize("hash", "D41D8CD98F00B204E9800998ECF8427E"), "d41d8cd98f00b204e9800998ecf8427e")

    def test_private_and_special_ips_are_refused(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "0.0.0.0", "224.0.0.1", "fe80::1"):
            with self.assertRaises(InputError, msg=ip):
                normalize("ip", ip)

    def test_url_with_credentials_is_refused(self):
        for u in ("https://user:pw@example.com/", "ftp://example.com/", "http://example.com/a b"):
            with self.assertRaises(InputError):
                normalize("url", u)

    def test_type_detection(self):
        self.assertEqual(detect_type("a@b.com"), "email")
        self.assertEqual(detect_type("8.8.8.8"), "ip")
        self.assertEqual(detect_type("example.com"), "domain")
        self.assertEqual(detect_type("+14155552671"), "phone")
        self.assertEqual(detect_type("https://example.com/x"), "url")
        self.assertEqual(detect_type("d41d8cd98f00b204e9800998ecf8427e"), "hash")
        self.assertEqual(detect_type("some_user"), "username")

    def test_face_search_requires_consent(self):
        s = T.Stack("direct")
        with self.assertRaises(InputError):
            s.orch.start("my photo", "image", selected=["pimeyes"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
