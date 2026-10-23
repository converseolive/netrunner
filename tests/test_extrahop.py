"""Unit tests for app.core.extrahop (HTTP isolated behind an injected fetch)."""

import unittest

from app.core import extrahop


class NormalizeTests(unittest.TestCase):
    def test_maps_core_fields(self):
        raw = {
            "id": 42, "title": "Port Scan", "risk_score": 55,
            "mitre_techniques": [{"id": "T1046"}],
            "mitre_tactics": [{"id": "TA0007"}],
            "participants": [
                {"role": "offender", "object_type": "device", "object_value": "10.0.0.5"},
                {"role": "victim", "object_type": "device", "object_value": "10.0.0.9"},
            ],
            "start_time": 1000, "update_time": 2000,
        }
        d = extrahop.normalize_detection(raw)
        self.assertEqual(d["title"], "Port Scan")
        self.assertEqual(d["techniques"], ["T1046"])
        self.assertEqual({p["ip"] for p in d["participants"]}, {"10.0.0.5", "10.0.0.9"})
        self.assertEqual(d["start_ms"], 1000)
        self.assertEqual(d["end_ms"], 2000)


class ConfiguredTests(unittest.TestCase):
    def test_is_configured(self):
        self.assertTrue(extrahop.is_configured({"base_url": "https://x", "api_key": "k"}))
        self.assertFalse(extrahop.is_configured({"base_url": "https://x"}))
        self.assertFalse(extrahop.is_configured({"api_key": "k"}))


class TestConnectionTests(unittest.TestCase):
    def test_missing_base_url(self):
        r = extrahop.test_connection({"api_key": "k"})
        self.assertFalse(r["ok"])

    def test_ok_response(self):
        def fake(url, method, headers, body, verify, timeout=15):
            assert url.endswith("/api/v1/extrahop")
            assert headers["Authorization"] == "ExtraHop apikey=secret"
            return 200, {"display_name": "lab-rx", "version": "9.6"}
        r = extrahop.test_connection(
            {"base_url": "https://rx.lab", "api_key": "secret"}, fetch=fake)
        self.assertTrue(r["ok"])
        self.assertEqual(r["appliance"], "lab-rx")

    def test_non_200(self):
        def fake(url, method, headers, body, verify, timeout=15):
            return 503, None
        r = extrahop.test_connection(
            {"base_url": "https://rx.lab", "api_key": "secret"}, fetch=fake)
        self.assertFalse(r["ok"])


class SearchTests(unittest.TestCase):
    def test_search_normalizes_list_payload(self):
        raw = [{"id": 1, "title": "Beacon", "risk_score": 80,
                "mitre_techniques": [{"id": "T1071"}],
                "participants": [{"role": "offender", "object_type": "device",
                                  "object_value": "10.0.0.5"}],
                "start_time": 100}]

        def fake(url, method, headers, body, verify, timeout=15):
            assert url.endswith("/api/v1/detections/search")
            assert method == "POST"
            assert body["from"] == 100 and body["until"] == 200
            return 200, raw
        out = extrahop.search_detections(
            {"base_url": "https://rx.lab", "api_key": "k"}, 100, 200, fetch=fake)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["techniques"], ["T1071"])

    def test_search_reads_detections_key(self):
        def fake(url, method, headers, body, verify, timeout=15):
            return 200, {"detections": [{"id": 1, "title": "X", "participants": []}]}
        out = extrahop.search_detections(
            {"base_url": "https://rx.lab", "api_key": "k"}, 0, 1, fetch=fake)
        self.assertEqual(len(out), 1)

    def test_search_raises_on_error_status(self):
        def fake(url, method, headers, body, verify, timeout=15):
            return 500, None
        with self.assertRaises(RuntimeError):
            extrahop.search_detections(
                {"base_url": "https://rx.lab", "api_key": "k"}, 0, 1, fetch=fake)


if __name__ == "__main__":
    unittest.main()
