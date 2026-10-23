"""Unit tests for app.core.rewrite_audit (pure stdlib, no scapy/root needed)."""

import unittest

from app.core.rewrite_planner import summarize_addressing
from app.core.rewrite_audit import audit_capture


def _bucket(audit, value):
    for f in audit["findings"]:
        if f["value"] == value:
            return f["bucket"]
    return None


def _by_category(audit, category):
    return [f for f in audit["findings"] if f["category"] == category]


class InternalIpTests(unittest.TestCase):
    def test_internal_ip_goes_to_rewrite(self):
        addressing = summarize_addressing([{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01"}])
        audit = audit_capture(addressing)
        self.assertEqual(_bucket(audit, "192.168.1.10"), "rewrite")

    def test_lab_subnet_adds_concrete_suggestion(self):
        addressing = summarize_addressing([{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01"}])
        audit = audit_capture(addressing, lab_subnet="10.99.0.0/16")
        host = next(f for f in audit["findings"] if f["value"] == "192.168.1.10")
        # Planner preserves the host octet (…1.10 -> …0.10).
        self.assertEqual(host["suggestion"], "10.99.0.10")

    def test_no_internal_hosts_needs_no_rewrite(self):
        addressing = summarize_addressing([{"ip": "8.8.8.8", "mac": "aa:bb:cc:dd:ee:01"}])
        audit = audit_capture(addressing)
        self.assertEqual(audit["summary"]["rewrite"], 0)


class ExternalIpTests(unittest.TestCase):
    def test_public_ip_is_protected(self):
        addressing = summarize_addressing([{"ip": "185.100.87.42", "mac": "aa:bb:cc:dd:ee:02"}])
        audit = audit_capture(addressing)
        self.assertEqual(_bucket(audit, "185.100.87.42"), "protect")

    def test_documentation_range_is_flagged_for_review(self):
        # RFC5737 TEST-NET addresses are an ambiguous-locality tell.
        addressing = {"internal": [], "external": ["192.0.2.55"], "other": [],
                      "subnets": [], "gateway_mac": None, "routed": False,
                      "protocol_mix": []}
        audit = audit_capture(addressing)
        self.assertEqual(_bucket(audit, "192.0.2.55"), "review")


class MacTests(unittest.TestCase):
    def test_locally_administered_mac_is_noted(self):
        # 0x02 bit set in first octet -> synthetic/VM MAC.
        addressing = summarize_addressing([{"ip": "10.10.0.5", "mac": "02:11:22:33:44:55"}])
        facts = {"hosts": [{"ip": "10.10.0.5", "mac": "02:11:22:33:44:55"}]}
        audit = audit_capture(addressing, facts)
        finding = next(f for f in audit["findings"] if f["value"] == "02:11:22:33:44:55")
        self.assertIn("locally-administered", finding["detail"])

    def test_gateway_mac_in_routed_capture_is_rewrite(self):
        # One MAC fronting several IPs -> inferred gateway, routed capture.
        hosts = [{"ip": f"10.0.0.{n}", "mac": "00:0c:29:ab:cd:ef"} for n in range(1, 5)]
        addressing = summarize_addressing(hosts)
        self.assertTrue(addressing["routed"])
        audit = audit_capture(addressing, {"hosts": hosts})
        gw = next(f for f in audit["findings"] if f["category"] == "Gateway MAC")
        self.assertEqual(gw["bucket"], "rewrite")


class VlanTests(unittest.TestCase):
    def test_tagged_vlan_is_rewrite(self):
        addressing = summarize_addressing([])
        audit = audit_capture(addressing, {"vlans": [20]})
        vlan = _by_category(audit, "VLAN tag")[0]
        self.assertEqual(vlan["bucket"], "rewrite")

    def test_untagged_vlan_is_review(self):
        addressing = summarize_addressing([])
        audit = audit_capture(addressing, {"vlans": []})
        vlan = _by_category(audit, "VLAN tag")[0]
        self.assertEqual(vlan["bucket"], "review")


class EmbeddedTests(unittest.TestCase):
    def test_dns_and_http_domains_collected_as_review(self):
        addressing = summarize_addressing([])
        facts = {"dns_qnames": ["www.corp.local", "mail.corp.local"],
                 "http_hosts": ["intranet.corp.local:8080"]}
        audit = audit_capture(addressing, facts)
        embedded = _by_category(audit, "Embedded domains")[0]
        self.assertEqual(embedded["bucket"], "review")
        self.assertIn("corp.local", embedded["value"])


class SummaryTests(unittest.TestCase):
    def test_ordering_rewrite_before_protect(self):
        addressing = summarize_addressing([
            {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01"},
            {"ip": "8.8.8.8", "mac": "aa:bb:cc:dd:ee:02"},
        ])
        audit = audit_capture(addressing)
        buckets = [f["bucket"] for f in audit["findings"]]
        self.assertLessEqual(buckets.index("rewrite"), buckets.index("protect"))

    def test_verdict_mentions_rewrite_count(self):
        addressing = summarize_addressing([{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01"}])
        audit = audit_capture(addressing)
        self.assertIn("rewrite", audit["summary"]["verdict"])


if __name__ == "__main__":
    unittest.main()
