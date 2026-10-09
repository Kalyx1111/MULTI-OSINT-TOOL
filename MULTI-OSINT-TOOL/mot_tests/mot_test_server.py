"""Security and behaviour tests for the hardened local server (real sockets, real HTTP)."""
import http.client
import json
import os
import secrets
import socket
import sys
import threading
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mot_testlib as T  # noqa: E402

import mot_app as A  # noqa: E402
import mot_config as C  # noqa: E402
import mot_connectors_base as B  # noqa: E402
import mot_server as S  # noqa: E402

PW = secrets.token_urlsafe(24)
SECRET_FIELD = "probe-" + secrets.token_hex(8)
WRONG_PW = "wrong-" + secrets.token_hex(8)
SHODAN_TEST_KEY = secrets.token_hex(12)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeOK(B.Connector):
    meta = B.Meta(id="fake_ok", name="Fake OK", category="Test", kind="local", targets=("email", "username", "domain"))

    def free(self, target, ttype, ctx):
        return self.res(B.OK, "free", findings=[B.Finding("breach", "Breach A", target, ents=[("domain", "a.example", "breached_in")]),
                                                B.Finding("credential", "Credential record", target, data={"_password": SECRET_FIELD, "user": "x"}, sensitive=True)])


class Client:
    def __init__(self, port):
        self.port, self.cookie, self.csrf = port, "", ""

    def raw(self, method, path, body=None, headers=None, host=None, ctype="application/json"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if self.cookie:
            h["Cookie"] = f"mot_sid={self.cookie}"
        if body is not None:
            h["Content-Type"] = ctype
        h.update(headers or {})
        data = body if isinstance(body, (bytes, type(None))) else (body if isinstance(body, str) else json.dumps(body)).encode()
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for k, v in h.items():
            c.putheader(k, v)
        c.putheader("Content-Length", str(len(data or b"")) if data is not None else "0")
        c.endheaders(data)
        r = c.getresponse()
        payload = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        c.close()
        return r.status, hdrs, payload

    def api(self, method, path, body=None, csrf=True, **kw):
        h = dict(kw.pop("headers", {}) or {})
        if csrf and method != "GET":
            h["X-MOT-CSRF"] = self.csrf
        st, hd, pl = self.raw(method, path, body, headers=h, **kw)
        try:
            return st, hd, json.loads(pl)
        except ValueError:
            return st, hd, pl


class ServerCase(unittest.TestCase):
    secret = os.urandom(32)

    @classmethod
    def setUpClass(cls):
        import shutil

        for sub in ("vault", "cases", "recovery", "logs"):  # every test class starts from a pristine first run
            shutil.rmtree(C.DATA / sub, ignore_errors=True)
        C.ensure_dirs()
        B.REGISTRY["fake_ok"] = FakeOK()
        cls.app = A.App()
        cls.app.tune["kdf"] = T.FAST_KDF
        cls.app.boot()
        cls.port = free_port()
        cls.srv = S.MotServer(cls.app, cls.port, cls.secret)
        cls.thr = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thr.start()

    @classmethod
    def tearDownClass(cls):
        B.REGISTRY.pop("fake_ok", None)
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.app.shutdown()

    def session(self, secret=None) -> Client:
        self.srv.limiter._hits.clear()  # tests open many sessions quickly; the limiter itself is tested separately
        c = Client(self.port)
        tok = S.Sessions(secret or self.secret).mint_launch()
        st, hd, _ = c.raw("POST", "/mot-launch", f"t={urllib.parse.quote(tok)}", ctype="application/x-www-form-urlencoded")
        self.assertEqual(st, 200)
        c.cookie = hd["set-cookie"].split(";")[0].split("=", 1)[1]
        st, _, j = c.api("GET", "/api/session")
        self.assertEqual(st, 200)
        c.csrf = j["data"]["csrf"]
        return c


class TestLaunchAndSession(ServerCase):
    def test_launch_cookie_flags_and_single_use(self):
        tok = S.Sessions(self.secret).mint_launch()
        c = Client(self.port)
        body = f"t={urllib.parse.quote(tok)}"
        st, hd, _ = c.raw("POST", "/mot-launch", body, ctype="application/x-www-form-urlencoded")
        self.assertEqual(st, 200)
        sc = hd["set-cookie"]
        self.assertIn("HttpOnly", sc)
        self.assertIn("SameSite=Strict", sc)
        self.assertIn("Path=/", sc)
        st2, _, _ = c.raw("POST", "/mot-launch", body, ctype="application/x-www-form-urlencoded")
        self.assertEqual(st2, 403, "launch token must be single-use")

    def test_forged_expired_and_foreign_tokens_are_refused(self):
        c = Client(self.port)
        good = S.Sessions(self.secret).mint_launch()
        forged = good[:-4] + ("0000" if not good.endswith("0000") else "1111")
        other = S.Sessions(os.urandom(32)).mint_launch()
        s = S.Sessions(self.secret)
        expired = s._make("L", -5, "ab" * 12)
        for bad in (forged, other, expired, "x", "L.9999999999.aa.bb", "S." + good[2:]):
            st, _, _ = c.raw("POST", "/mot-launch", f"t={urllib.parse.quote(bad)}", ctype="application/x-www-form-urlencoded")
            self.assertEqual(st, 403, bad[:30])

    def test_api_requires_session(self):
        c = Client(self.port)
        st, _, j = c.api("GET", "/api/session")
        self.assertEqual(st, 401)
        self.assertEqual(j["code"], "no_session")
        c.cookie = "S.9999999999." + "a" * 32 + "." + "0" * 64
        self.assertEqual(c.api("GET", "/api/ping")[0], 401)

    def test_sessions_survive_a_server_restart_with_same_secret(self):
        c = self.session()
        s2 = S.MotServer(self.app, free_port(), self.secret)  # a restarted server shares the supervisor's secret
        try:
            self.assertIsNotNone(s2.sessions.session_id(c.cookie))
            self.assertEqual(s2.sessions.csrf_for(s2.sessions.session_id(c.cookie)), c.csrf)
        finally:
            s2.server_close()

    def test_logout_revokes_session(self):
        c = self.session()
        self.assertEqual(c.api("POST", "/api/logout", {})[0], 200)
        self.assertEqual(c.api("GET", "/api/ping")[0], 401)


class TestRequestGuards(ServerCase):
    def test_host_header_allowlist_blocks_dns_rebinding(self):
        c = self.session()
        for h in ("evil.example", f"evil.example:{self.port}", f"127.0.0.1.evil.example:{self.port}", "127.0.0.1", ""):
            st, _, _ = c.raw("GET", "/api/ping", host=h or "x")
            self.assertEqual(st, 421, h)
        self.assertEqual(c.raw("GET", "/api/ping", host=f"localhost:{self.port}")[0], 200)

    def test_csrf_origin_and_fetch_metadata(self):
        c = self.session()
        self.assertEqual(c.api("POST", "/api/touch", {}, csrf=False)[0], 403)
        self.assertEqual(c.api("POST", "/api/touch", {}, headers={"X-MOT-CSRF": "0" * 32}, csrf=False)[0], 403)
        self.assertEqual(c.api("POST", "/api/touch", {})[0], 200)
        st, _, j = c.api("POST", "/api/touch", {}, headers={"Origin": "http://evil.example"})
        self.assertEqual(st, 403)
        self.assertEqual(c.api("POST", "/api/touch", {}, headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)
        self.assertEqual(c.api("GET", "/api/ping", headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(c.api("GET", "/api/ping", headers={"Sec-Fetch-Site": "same-origin"})[0], 200)

    def test_body_rules(self):
        c = self.session()
        self.assertEqual(c.api("POST", "/api/detect", "target=a", ctype="text/plain")[0], 415)
        self.assertEqual(c.api("POST", "/api/detect", "{not json")[0], 400)
        self.assertEqual(c.api("POST", "/api/detect", "[1,2]")[0], 400)
        self.assertEqual(c.api("POST", "/api/detect", {})[0], 400)  # required field
        st, _, j = c.api("POST", "/api/detect", {"target": "a@b.com", "role": "admin"})
        self.assertEqual(st, 400)
        self.assertIn("Unexpected", j["error"])  # mass-assignment defence
        self.assertEqual(c.api("POST", "/api/detect", {"target": "x" * 501})[0], 400)
        self.assertEqual(c.api("POST", "/api/detect", {"target": "a\x00b"})[0], 400)
        st, _, _ = c.raw("POST", "/api/detect", b"", headers={"X-MOT-CSRF": c.csrf, "Content-Length": "3000000"})
        self.assertEqual(st, 413)

    def test_methods_and_no_cors(self):
        c = self.session()
        for m in ("PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"):
            st, hd, _ = c.raw(m, "/api/ping")
            self.assertEqual(st, 405, m)
            self.assertNotIn("access-control-allow-origin", hd)
        st, hd, _ = c.raw("GET", "/api/ping")
        self.assertNotIn("access-control-allow-origin", hd)
        self.assertEqual(c.raw("POST", "/api/ping", b"{}", headers={"X-MOT-CSRF": c.csrf})[0], 405)
        self.assertEqual(c.api("GET", "/api/nope")[0], 404)

    def test_security_headers_everywhere(self):
        c = self.session()
        for path in ("/api/ping", "/nonexistent", "/mot-health"):
            st, hd, _ = c.raw("GET", path)
            self.assertEqual(hd["x-content-type-options"], "nosniff", path)
            self.assertEqual(hd["x-frame-options"], "DENY")
            self.assertIn("default-src 'none'", hd["content-security-policy"])
            self.assertIn("frame-ancestors 'none'", hd["content-security-policy"])
            self.assertNotIn("unsafe-inline", hd["content-security-policy"])
            self.assertNotIn("unsafe-eval", hd["content-security-policy"])
            self.assertEqual(hd["cache-control"], "no-store")
            self.assertEqual(hd["referrer-policy"], "no-referrer")
            self.assertNotIn("server", {k: v for k, v in hd.items() if "python" in v.lower()}, "no interpreter version banner")

    def test_static_path_traversal_and_allowlist(self):
        c = self.session()
        evil = ["/../mot_vault.py", "/%2e%2e/mot_app.py", "/mot_fonts/../../mot_app.py", "/.env", "/..%2fmot_app.py", "//etc/passwd", "/mot_ui/../mot_app.py", "/mot_index.html%00.js",
                "/mot_app.py", "/mot_data/vault/mot_vault.motv", "/%5c..%5cmot_app.py", "/mot_fonts/", "/mot_fonts"]
        for p in evil:
            st, _, body = c.raw("GET", p)
            self.assertIn(st, (400, 404), p)
            self.assertNotIn(b"import ", body, p)

    def test_unhandled_exception_is_generic_with_correlation_id(self):
        c = self.session()
        if self.app.state == "no_vault":
            c.api("POST", "/api/vault/create", {"password": PW, "confirm": PW})
        orig = self.app.overview
        self.app.overview = lambda: (_ for _ in ()).throw(RuntimeError(f"/home/secret/path password={SECRET_FIELD}"))
        try:
            st, _, j = c.api("GET", "/api/overview")
        finally:
            self.app.overview = orig
        self.assertEqual(st, 500)
        self.assertNotIn("secret", json.dumps(j))
        self.assertNotIn(SECRET_FIELD, json.dumps(j))
        self.assertTrue(j["cid"])

    def test_rate_limit_on_sensitive_endpoint(self):
        c = self.session()
        codes = [c.api("POST", "/api/vault/unlock", {"password": WRONG_PW})[0] for _ in range(12)]
        self.assertIn(429, codes)
        st, hd, j = c.api("POST", "/api/vault/unlock", {"password": WRONG_PW})
        self.assertEqual(st, 429)
        self.assertIn("retry-after", hd)


class TestFullWorkflow(ServerCase):
    def test_vault_search_cases_exports_reveal_and_lock(self):
        c = self.session()
        # first run: weak password refused, strong one accepted (a 6-character value is always below the 12-character minimum)
        weak = secrets.token_hex(3)
        st, _, j = c.api("POST", "/api/vault/create", {"password": weak, "confirm": weak})
        self.assertEqual((st, j["code"]), (400, "weak_password"))
        st, _, j = c.api("POST", "/api/vault/create", {"password": PW, "confirm": PW})
        self.assertEqual(st, 200, j)
        self.assertEqual(j["data"]["state"], "unlocked")
        # data routes work, ack is enforced
        st, _, j = c.api("POST", "/api/search", {"target": "who@example.com", "tools": ["fake_ok"]})
        self.assertEqual((st, j["code"]), (409, "ack_required"))
        self.assertEqual(c.api("POST", "/api/ack", {})[0], 200)
        st, _, j = c.api("POST", "/api/search", {"target": "who@example.com", "tools": ["fake_ok"], "purpose": "authorised test"})
        self.assertEqual(st, 200, j)
        jid = j["data"]["id"]
        for _ in range(100):
            st, _, j = c.api("GET", f"/api/jobs/{jid}")
            if j["data"]["status"] != "running":
                break
            time.sleep(0.1)
        d = j["data"]
        self.assertEqual(d["status"], "done")
        self.assertNotIn(SECRET_FIELD, json.dumps(d))
        fid = next(f["fid"] for f in d["results"]["fake_ok"]["findings"] if f["kind"] == "credential")
        self.assertTrue(next(f for f in d["results"]["fake_ok"]["findings"] if f["fid"] == fid)["has_secret"])
        # incremental polling: already-delivered tools are not resent
        st, _, j2 = c.api("GET", f"/api/jobs/{jid}?have=fake_ok")
        self.assertEqual(j2["data"]["results"]["fake_ok"]["findings"], [])
        # reveal needs the master password again
        st, _, j = c.api("POST", "/api/reveal", {"job": jid, "finding": fid, "password": WRONG_PW})
        self.assertEqual((st, j["code"]), (401, "reauth_failed"))
        st, _, j = c.api("POST", "/api/reveal", {"job": jid, "finding": fid, "password": PW})
        self.assertEqual(j["data"]["password"], SECRET_FIELD)
        # case + exports (secrets never present)
        st, _, j = c.api("GET", "/api/cases")
        cid = j["data"]["cases"][0]["id"]
        for fmt in ("json", "csv", "md", "maltego"):
            st, hd, body = c.raw("GET", f"/api/cases/{cid}/export?fmt={fmt}")
            self.assertEqual(st, 200, fmt)
            self.assertIn("attachment", hd["content-disposition"])
            self.assertNotIn(SECRET_FIELD.encode(), body)
        self.assertEqual(c.api("GET", "/api/cases/" + "0" * 16)[0], 404)
        self.assertEqual(c.api("GET", "/api/cases/../../etc/passwd")[0], 404)
        self.assertEqual(c.api("POST", f"/api/cases/{cid}/update", {"title": "My case", "notes": "line1\nline2"})[0], 200)
        # key storage: masked previews, never plaintext
        self.assertEqual(c.api("POST", "/api/connections/shodan/key", {"fields": {"api_key": SHODAN_TEST_KEY}})[0], 200)
        st, hd, body = c.raw("GET", "/api/connections")
        self.assertNotIn(SHODAN_TEST_KEY.encode(), body)
        row = next(r for r in json.loads(body)["data"]["connections"] if r["id"] == "shodan")
        self.assertEqual(row["mode"], "paid")
        self.assertEqual(c.api("POST", "/api/connections/not_a_tool/key", {"fields": {"api_key": "x" * 10}})[0], 404)
        self.assertEqual(c.api("POST", "/api/connections/shodan/key", {"fields": {"evil": "x"}})[0], 400)
        # audit log intact and free of secrets
        st, _, j = c.api("GET", "/api/audit?limit=100")
        self.assertTrue(j["data"]["verify"]["ok"])
        blob = json.dumps(j["data"]["rows"])
        for s in (SECRET_FIELD, SHODAN_TEST_KEY, PW, "who@example.com"):
            self.assertNotIn(s, blob)
        # lock: every data route now says locked
        self.assertEqual(c.api("POST", "/api/vault/lock", {})[0], 200)
        for p in ("/api/overview", "/api/cases", "/api/connections", "/api/shield"):
            st, _, j = c.api("GET", p)
            self.assertEqual((st, j["code"]), (423, "locked"), p)
        st, _, j = c.api("POST", "/api/vault/unlock", {"password": PW})
        self.assertEqual((st, j["data"]["state"]), (200, "unlocked"))


class TestIdleLock(ServerCase):
    def test_idle_lock_locks_only_when_no_job_is_running(self):
        c = self.session()
        if self.app.state == "no_vault":
            c.api("POST", "/api/vault/create", {"password": PW, "confirm": PW})
        elif self.app.state == "locked":
            c.api("POST", "/api/vault/unlock", {"password": PW})
        self.app.last_activity = time.time() - 99999
        self.assertTrue(self.app.idle_check())
        self.assertEqual(self.app.state, "locked")
        c.api("POST", "/api/vault/unlock", {"password": PW})


class TestExternalLinks(ServerCase):
    """Vendor links leave the shield, so the server resolves them itself and insists on a confirmation."""

    def _ready(self, c):
        if self.app.state == "no_vault":
            c.api("POST", "/api/vault/create", {"password": PW, "confirm": PW})
        elif self.app.state == "locked":
            c.api("POST", "/api/vault/unlock", {"password": PW})

    def test_links_are_resolved_server_side_and_https_only(self):
        c = self.session()
        self._ready(c)
        st, _, j = c.api("POST", "/api/external/link", {"kind": "vendor", "id": "shodan", "which": "key"})
        self.assertEqual((st, j["data"]["url"], j["data"]["host"]), (200, "https://account.shodan.io", "account.shodan.io"))
        # the page can never supply a URL: it is just another unexpected field
        self.assertEqual(c.api("POST", "/api/external/link", {"kind": "vendor", "id": "shodan", "which": "key", "url": "https://evil.example"})[0], 400)
        self.assertEqual(c.api("POST", "/api/external/link", {"kind": "vendor", "id": "not_a_tool", "which": "key"})[0], 404)
        self.assertEqual(c.api("POST", "/api/external/link", {"kind": "vendor", "id": "wayback", "which": "key"})[0], 404)  # no key page exists
        self.assertEqual(c.api("POST", "/api/external/link", {"kind": "guide", "id": "vpn", "which": "9"})[0], 404)
        self.assertEqual(c.api("POST", "/api/external/link", {"kind": "javascript", "id": "vpn", "which": "0"})[0], 400)
        self.assertEqual(c.api("POST", "/api/external/link", {"kind": "vendor", "id": "shodan", "which": "../x"})[0], 400)
        st, _, j = c.api("POST", "/api/external/link", {"kind": "guide", "id": "mail", "which": "0"})
        self.assertEqual(j["data"]["host"], "proton.me")

    def test_every_published_link_is_clean_https(self):
        from urllib.parse import urlsplit

        urls = [u for c in B.REGISTRY.values() for u in (c.meta.site, c.meta.key_url, c.meta.docs_url) if u]
        urls += [l["url"] for g in A.GUIDANCE for l in g["links"]]
        self.assertGreater(len(urls), 40)
        for u in urls:
            p = urlsplit(u)
            self.assertEqual(p.scheme, "https", u)
            self.assertTrue(p.hostname and "." in p.hostname, u)
            self.assertFalse(p.username or p.password or any(ch.isspace() for ch in u), u)

    def test_open_needs_explicit_confirmation_and_is_audited(self):
        c = self.session()
        self._ready(c)
        calls = []
        orig = A.webbrowser.open
        A.webbrowser.open = lambda url, new=0, **kw: calls.append(url) or True
        try:
            st, _, j = c.api("POST", "/api/external/open", {"kind": "vendor", "id": "hibp", "which": "key"})
            self.assertEqual((st, j["code"]), (409, "confirm_outside_shield"))
            self.assertEqual(calls, [])
            st, _, j = c.api("POST", "/api/external/open", {"kind": "vendor", "id": "hibp", "which": "key", "confirm": True})
        finally:
            A.webbrowser.open = orig
        self.assertEqual((st, j["data"]["opened"]), (200, True))
        self.assertEqual(calls, ["https://haveibeenpwned.com/API/Key"])
        st, _, a = c.api("GET", "/api/audit?limit=20")
        row = [r for r in a["data"]["rows"] if r["event"] == "external_opened"][-1]
        self.assertEqual(row["d"]["host"], "haveibeenpwned.com")
        self.assertNotIn("/API/Key", json.dumps(row))  # only the host is logged, never the path

    def test_open_reports_failure_when_no_browser_exists(self):
        c = self.session()
        self._ready(c)
        orig = A.webbrowser.open
        A.webbrowser.open = lambda *a, **k: (_ for _ in ()).throw(OSError("no display"))
        try:
            st, _, j = c.api("POST", "/api/external/open", {"kind": "guide", "id": "tor", "which": "0", "confirm": True})
        finally:
            A.webbrowser.open = orig
        self.assertEqual((st, j["data"]["opened"]), (200, False))
        self.assertEqual(j["data"]["host"], "www.torproject.org")


if __name__ == "__main__":
    unittest.main(verbosity=2)
