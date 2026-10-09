"""Tool catalogue and the RDAP, AbuseIPDB and GreyNoise parsers. Offline: fixtures only, no network."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mot_testlib as T  # noqa: E402,F401  (points the program's data folder at a throw-away folder)

import mot_conn_api, mot_conn_cli, mot_conn_web, mot_conn_intel  # noqa: E402,F401  (registers the connectors)
import mot_connectors_base as B  # noqa: E402
import mot_catalog as K  # noqa: E402

MI = mot_conn_intel


class CatalogCase(unittest.TestCase):
    def test_catalogue_matches_registered_connectors(self):
        self.assertEqual(K.validate(set(B.REGISTRY)), [])

    def test_every_tool_says_what_it_is_used_for(self):
        for e in K.ENTRIES:
            self.assertTrue(e.use.strip(), e.id)
            self.assertLessEqual(len(e.use), 240, e.id)

    def test_handoff_entries_have_an_address(self):
        for e in K.OTHER_ENTRIES:
            if e.status == "handoff":
                self.assertTrue(e.official, e.id)

    def test_only_api_cli_and_local_connectors_are_automated(self):
        expected = {cid for cid, c in B.REGISTRY.items() if c.meta.kind in ("api", "cli", "local")}
        auto = {e.id for e in K.ENTRIES if K.status_for(e, B.REGISTRY[e.id].meta.kind if e.id in B.REGISTRY else None) == "automated"}
        self.assertEqual(auto, expected)

    def test_every_search_type_has_at_least_one_tool(self):
        for t in K.TYPE_INFO:
            self.assertTrue(K.for_type(t, B.REGISTRY), t)

    def test_connector_self_checks_pass(self):
        for cid, c in B.REGISTRY.items():
            self.assertEqual(c.selftest(), [], cid)


class IntelParsers(unittest.TestCase):
    def test_domain_and_ip_validation(self):
        self.assertEqual(MI.valid_domain("Example.COM."), "example.com")
        for bad in ("a/b.com", "http://x.com", "x.com?q=1", "x y.com", "-x.com", ""):
            self.assertIsNone(MI.valid_domain(bad), bad)
        self.assertEqual(MI.valid_domain("example.xn--p1ai"), "example.xn--p1ai")
        self.assertEqual(MI.valid_ip("2001:db8::1"), "2001:db8::1")
        self.assertIsNone(MI.valid_ip("999.1.1.1"))

    def test_bootstrap_maps_each_tld_to_an_https_base(self):
        m = MI.parse_bootstrap({"services": [[["com", "net"], ["http://insecure.example/", "https://rdap.verisign.com/com/v1"]],
                                             [["org"], ["https://rdap.publicinterestregistry.org/rdap"]]]})
        self.assertEqual(m["com"], "https://rdap.verisign.com/com/v1/")
        self.assertEqual(m["org"], "https://rdap.publicinterestregistry.org/rdap/")
        self.assertNotIn("bogus", m)

    def test_rdap_record_is_parsed(self):
        f = MI.parse_rdap(MI.RDAP_FIXTURE, "example.com")
        reg = [x for x in f if x.kind == "registration"][0]
        self.assertEqual(reg.data["registrar"], "Example Registrar, Inc.")
        self.assertIn("registration", reg.data["events"])
        self.assertEqual(sorted(x.value for x in f if x.kind == "nameserver"), ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertTrue(any(x.kind == "contact" and x.value == "abuse@registrar.example" for x in f))

    def test_abuseipdb_score_is_shown_with_its_window(self):
        f = MI.parse_abuseipdb({"data": {"ipAddress": "203.0.113.9", "abuseConfidenceScore": 87, "totalReports": 12, "countryCode": "XX", "isp": "Example ISP"}})
        self.assertEqual(len(f), 1)
        self.assertIn("87%", f[0].title)
        self.assertEqual(f[0].data["isp"], "Example ISP")

    def test_greynoise_keeps_fields_it_does_not_know(self):
        f = MI.parse_greynoise({"ip": "203.0.113.9", "classification": "unknown", "new_field": "kept"}, "203.0.113.9")
        self.assertEqual(f[0].data["new_field"], "kept")

    def test_unexpected_shapes_give_no_findings(self):
        self.assertEqual(MI.parse_rdap([], "example.com"), [])
        self.assertEqual(MI.parse_abuseipdb({"data": "nope"}), [])
        self.assertEqual(MI.parse_greynoise({}, "203.0.113.9"), [])


if __name__ == "__main__":
    unittest.main()
