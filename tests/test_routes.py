"""
Flask route/integration tests via the test client - no root, no appliance.

All on-disk state (uploads, settings, runs, profiles, addresses) is redirected to
a temp directory so the suite never touches the repo. Packet-sending routes are
only exercised on their reject/validation paths, so nothing goes on the wire.
"""

import io
import os
import shutil
import tempfile
import unittest

from scapy.all import Ether, IP, TCP, UDP, ARP, wrpcap

from app import create_app
from app.core import settings, runs, profiles, addresses


def _sample_pcap_bytes():
    a, b, gw = "aa:aa:aa:00:00:10", "aa:aa:aa:00:00:20", "de:ad:be:ef:00:01"
    pkts = [
        Ether(src=a, dst=gw) / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(dport=443, flags="S"),
        Ether(src=gw, dst=a) / IP(src="8.8.8.8", dst="192.168.1.10") / TCP(sport=443, flags="SA"),
        Ether(src=a, dst=b) / IP(src="192.168.1.10", dst="192.168.1.20") / UDP(dport=53),
    ]
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.close()
    wrpcap(tmp.name, pkts)
    with open(tmp.name, "rb") as f:
        data = f.read()
    os.remove(tmp.name)
    return data


class RouteTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # Redirect every on-disk store into the temp dir.
        self._orig = {
            "settings": settings.SETTINGS_FILE,
            "runs": runs.RUNS_FILE,
            "profiles": profiles.PROFILES_DIR,
            "addresses": addresses.ADDRESSES_FILE,
        }
        settings.SETTINGS_FILE = os.path.join(self.tmp, "settings.json")
        runs.RUNS_FILE = os.path.join(self.tmp, "runs.json")
        profiles.PROFILES_DIR = os.path.join(self.tmp, "profiles")
        addresses.ADDRESSES_FILE = os.path.join(self.tmp, "addresses.json")
        runs.recent_runs.clear()

        self.app = create_app()
        self.app.config["UPLOAD_FOLDER"] = os.path.join(self.tmp, "uploads")
        os.makedirs(self.app.config["UPLOAD_FOLDER"], exist_ok=True)
        self.client = self.app.test_client()

    def tearDown(self):
        settings.SETTINGS_FILE = self._orig["settings"]
        runs.RUNS_FILE = self._orig["runs"]
        profiles.PROFILES_DIR = self._orig["profiles"]
        addresses.ADDRESSES_FILE = self._orig["addresses"]
        runs.recent_runs.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _analyze_sample(self):
        return self.client.post(
            "/analyze_pcap",
            data={"pcapFile": (io.BytesIO(_sample_pcap_bytes()), "sample.pcap")},
            content_type="multipart/form-data",
        )


class IndexAndAnalyzeTests(RouteTestBase):
    def test_index_serves(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_analyze_returns_full_shape(self):
        resp = self._analyze_sample()
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        for key in ("packets", "endpoints", "conversations", "threats",
                    "addressing", "audit", "hosts"):
            self.assertIn(key, data)
        # the capture's two internal hosts should be present
        self.assertEqual(data["addressing"]["internal_count"], 2)
        self.assertEqual(data["audit"]["summary"].get("rewrite", 0) >= 2, True)

    def test_analyze_capture_starting_with_arp(self):
        # Regression: a capture whose first packet has no IP layer (ARP) used to
        # raise UnboundLocalError on src_ip.
        pkts = [
            Ether(src="aa:aa:aa:00:00:10", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.10"),
            Ether(src="aa:aa:aa:00:00:20", dst="aa:aa:aa:00:00:10")
            / ARP(op=2, psrc="192.168.1.10", pdst="192.168.1.1", hwsrc="aa:aa:aa:00:00:20"),
            Ether(src="aa:aa:aa:00:00:10", dst="aa:aa:aa:00:00:20")
            / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(dport=443, flags="S"),
        ]
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp.close()
        wrpcap(tmp.name, pkts)
        with open(tmp.name, "rb") as f:
            data = f.read()
        os.remove(tmp.name)
        resp = self.client.post(
            "/analyze_pcap",
            data={"pcapFile": (io.BytesIO(data), "arp.pcap")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(len(resp.get_json()["timeline"]), 1)

    def test_analyze_missing_file_is_400(self):
        resp = self.client.post("/analyze_pcap", data={}, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 400)

    def test_rewrite_uses_last_pcap(self):
        self._analyze_sample()  # sets LAST_PCAP
        resp = self.client.post("/rewrite_pcap", json={"ip_map": {"192.168.1.10": "10.99.0.10"}})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(resp.data) > 0)


class SuggestPlanTests(RouteTestBase):
    def test_plan_from_hosts(self):
        resp = self.client.post("/suggest_plan", json={
            "hosts": [{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01"}],
            "lab_subnet": "10.99.0.0/16",
        })
        self.assertEqual(resp.status_code, 200)
        plan = resp.get_json()["plan"]
        self.assertEqual(plan["ip_map"]["192.168.1.10"], "10.99.0.10")

    def test_missing_lab_subnet_is_400(self):
        resp = self.client.post("/suggest_plan", json={"hosts": []})
        self.assertEqual(resp.status_code, 400)


class SettingsRouteTests(RouteTestBase):
    def test_get_defaults(self):
        data = self.client.get("/settings").get_json()
        self.assertIn("extrahop", data)
        self.assertEqual(data["extrahop"]["internal_networks"], [])

    def test_save_and_mask_key(self):
        resp = self.client.post("/settings", json={"extrahop": {
            "base_url": "https://rx.lab", "api_key": "secret",
            "internal_networks": ["10.20.0.0/16"],
        }})
        self.assertEqual(resp.status_code, 200)
        data = self.client.get("/settings").get_json()["extrahop"]
        self.assertEqual(data["api_key"], "")          # masked
        self.assertTrue(data["api_key_set"])
        self.assertEqual(data["internal_networks"], ["10.20.0.0/16"])

    def test_invalid_cidr_is_400(self):
        resp = self.client.post("/settings", json={"extrahop": {"internal_networks": ["nope"]}})
        self.assertEqual(resp.status_code, 400)


class DetectionAndJobRoutes(RouteTestBase):
    def test_validate_sample_when_unconfigured(self):
        data = self.client.post("/detections/validate", json={}).get_json()
        self.assertTrue(data["sample"])
        self.assertEqual(data["note"], "not_configured")

    def test_report_downloads_html(self):
        resp = self.client.get("/detections/report")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
        self.assertIn(b"NetRunner Detection Validation Report", resp.data)

    def test_runs_empty_then_clear(self):
        self.assertEqual(self.client.get("/runs").get_json()["runs"], [])
        self.assertEqual(self.client.delete("/runs").status_code, 200)

    def test_jobs_list_and_bad_stop(self):
        self.assertIn("jobs", self.client.get("/jobs").get_json())
        self.assertEqual(self.client.post("/jobs/no-such-id/stop").status_code, 404)
        self.assertEqual(self.client.post("/jobs/clear").status_code, 200)

    def test_interfaces_list(self):
        data = self.client.get("/interfaces").get_json()
        self.assertIn("interfaces", data)
        self.assertIsInstance(data["interfaces"], list)


class GeneratorPreflightTests(RouteTestBase):
    def test_bad_interface_rejected_protocol(self):
        resp = self.client.post("/generate/protocol",
                                json={"protocol": "dns", "interface": "nope-xyz0"})
        self.assertEqual(resp.status_code, 400)

    def test_bad_interface_rejected_adversary(self):
        resp = self.client.post("/generate/adversary",
                                json={"simulation": "port_scan", "interface": "nope-xyz0"})
        self.assertEqual(resp.status_code, 400)

    def test_replay_without_file_is_400(self):
        resp = self.client.post("/replay/start", json={"interface": "nope-xyz0"})
        self.assertEqual(resp.status_code, 400)


class AddressAndProfileRoutes(RouteTestBase):
    def test_address_crud(self):
        created = self.client.post("/addresses", json={
            "name": "Victim", "ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:01"})
        self.assertEqual(created.status_code, 201)
        aid = created.get_json()["id"]
        self.assertTrue(any(a["id"] == aid for a in self.client.get("/addresses").get_json()))
        self.assertEqual(self.client.delete(f"/addresses/{aid}").status_code, 200)

    def test_address_bad_ip_is_400(self):
        resp = self.client.post("/addresses", json={"name": "x", "ip": "999.1.1.1"})
        self.assertEqual(resp.status_code, 400)

    def test_profile_save_and_list(self):
        saved = self.client.post("/profiles", json={"name": "Lab A"}).get_json()
        self.assertIn("id", saved)
        names = [p["name"] for p in self.client.get("/profiles").get_json()]
        self.assertIn("Lab A", names)
        self.assertEqual(self.client.get(f"/profiles/{saved['id']}").status_code, 200)
        self.assertEqual(self.client.delete(f"/profiles/{saved['id']}").status_code, 200)


if __name__ == "__main__":
    unittest.main()
