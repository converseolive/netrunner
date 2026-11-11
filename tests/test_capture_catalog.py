"""Tests for the recommended-capture catalog."""

import unittest

from app import create_app
from app.core import capture_catalog
from app.core.detection_match import SCENARIOS


class CatalogTests(unittest.TestCase):
    def test_entries_are_well_formed(self):
        ids = set()
        for e in capture_catalog.CATALOG:
            self.assertNotIn(e["id"], ids, f"duplicate id {e['id']}")
            ids.add(e["id"])
            self.assertIn(e["source"], capture_catalog.SOURCES)
            for key in ("title", "page_url", "file_url", "size", "format", "summary"):
                self.assertTrue(e.get(key), f"{e['id']} missing {key}")
            self.assertTrue(e["page_url"].startswith("https://"), e["id"])
            self.assertTrue(e["file_url"].startswith("https://"), e["id"])
            for s in e["scenarios"]:
                self.assertIn(s, SCENARIOS, f"{e['id']} has unknown scenario {s}")

    def test_coverage_lists_every_scenario(self):
        cov = capture_catalog.coverage()
        self.assertEqual({c["scenario"] for c in cov}, set(SCENARIOS))
        covered = {c["scenario"] for c in cov if c["covered"]}
        for key in ("c2_beacon", "dga", "port_scan", "lateral_movement",
                    "http_exfil", "dcsync"):
            self.assertIn(key, covered)
        # no clean public capture was found for these; the generator covers them
        for key in ("kerberoast", "llmnr_poison", "ntlm_relay", "arp_spoof"):
            self.assertNotIn(key, covered)

    def test_catalog_route(self):
        client = create_app().test_client()
        data = client.get("/captures/catalog").get_json()
        self.assertEqual(len(data["captures"]), len(capture_catalog.CATALOG))
        self.assertIn("source_info", data["captures"][0])
        self.assertEqual(len(data["coverage"]), len(SCENARIOS))


if __name__ == "__main__":
    unittest.main()
