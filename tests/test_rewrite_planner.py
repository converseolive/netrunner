"""Unit tests for app.core.rewrite_planner (pure stdlib, no scapy/root needed)."""

import unittest

from app.core.rewrite_planner import (
    classify_ip, summarize_addressing, suggest_plan,
    networks_contain, suggest_lab_subnet)


class ClassifyTests(unittest.TestCase):
    def test_private_is_internal(self):
        self.assertEqual(classify_ip("10.0.0.5"), "internal")
        self.assertEqual(classify_ip("192.168.1.1"), "internal")

    def test_public_is_external(self):
        self.assertEqual(classify_ip("8.8.8.8"), "external")

    def test_multicast_and_broadcast(self):
        self.assertEqual(classify_ip("224.0.0.252"), "multicast")
        self.assertEqual(classify_ip("255.255.255.255"), "other")

    def test_garbage_is_other(self):
        self.assertEqual(classify_ip("not-an-ip"), "other")


class SummarizeTests(unittest.TestCase):
    def test_internal_external_split(self):
        hosts = [{"ip": "10.0.0.5", "mac": "aa:aa:aa:aa:aa:01"},
                 {"ip": "8.8.8.8", "mac": "aa:aa:aa:aa:aa:02"}]
        summary = summarize_addressing(hosts)
        self.assertEqual(summary["internal_count"], 1)
        self.assertEqual(summary["external_count"], 1)

    def test_gateway_inferred_when_one_mac_fronts_many_ips(self):
        hosts = [{"ip": f"10.0.0.{n}", "mac": "00:0c:29:ab:cd:ef"} for n in range(1, 5)]
        summary = summarize_addressing(hosts)
        self.assertTrue(summary["routed"])
        self.assertEqual(summary["gateway_mac"], "00:0c:29:ab:cd:ef")

    def test_flat_segment_has_no_gateway(self):
        hosts = [{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:01"},
                 {"ip": "10.0.0.2", "mac": "bb:bb:bb:bb:bb:02"}]
        summary = summarize_addressing(hosts)
        self.assertFalse(summary["routed"])
        self.assertIsNone(summary["gateway_mac"])


class SuggestPlanTests(unittest.TestCase):
    def test_preserves_host_octet(self):
        hosts = [{"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:01"}]
        addressing = summarize_addressing(hosts)
        plan = suggest_plan(addressing, "10.99.0.0/16")
        self.assertEqual(plan["ip_map"]["192.168.1.10"], "10.99.0.10")

    def test_external_ips_left_untouched(self):
        hosts = [{"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:01"},
                 {"ip": "8.8.8.8", "mac": "aa:aa:aa:aa:aa:02"}]
        addressing = summarize_addressing(hosts)
        plan = suggest_plan(addressing, "10.99.0.0/16")
        self.assertNotIn("8.8.8.8", plan["ip_map"])

    def test_invalid_lab_subnet_returns_warning(self):
        addressing = summarize_addressing([{"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:01"}])
        plan = suggest_plan(addressing, "not-a-subnet")
        self.assertTrue(plan["warnings"])
        self.assertEqual(plan["ip_map"], {})

    def test_small_lab_range_warns_on_overflow(self):
        # Two distinct /24s into a single /24 lab range -> second overflows.
        hosts = [{"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:01"},
                 {"ip": "192.168.2.10", "mac": "bb:bb:bb:bb:bb:02"}]
        addressing = summarize_addressing(hosts)
        plan = suggest_plan(addressing, "10.99.0.0/24")
        self.assertTrue(plan["warnings"])


class LocalityTests(unittest.TestCase):
    def test_networks_contain_true(self):
        self.assertEqual(networks_contain("10.20.5.0/24", ["10.20.0.0/16"]),
                         "10.20.0.0/16")

    def test_networks_contain_false(self):
        self.assertIsNone(networks_contain("10.99.0.0/16", ["10.20.0.0/16"]))

    def test_networks_contain_ignores_bad_cidr(self):
        self.assertIsNone(networks_contain("10.20.5.0/24", ["not-a-cidr"]))

    def test_suggest_lab_subnet_picks_internal_network(self):
        addressing = summarize_addressing([{"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:01"}])
        self.assertEqual(suggest_lab_subnet(addressing, ["10.20.0.0/16"]), "10.20.0.0/16")

    def test_suggest_lab_subnet_prefers_smallest_that_fits(self):
        # One internal /24 to place; the /24 lab net fits, so it beats the /16.
        addressing = summarize_addressing([{"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:01"}])
        self.assertEqual(
            suggest_lab_subnet(addressing, ["10.20.0.0/16", "10.30.0.0/24"]),
            "10.30.0.0/24")

    def test_suggest_lab_subnet_none_when_unconfigured(self):
        self.assertIsNone(suggest_lab_subnet(summarize_addressing([]), []))

    def test_plan_warns_when_lab_outside_internal(self):
        addressing = summarize_addressing([{"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:01"}])
        plan = suggest_plan(addressing, "10.99.0.0/16", internal_networks=["10.20.0.0/16"])
        self.assertTrue(any("internal" in w for w in plan["warnings"]))

    def test_plan_no_locality_warning_when_inside(self):
        addressing = summarize_addressing([{"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:01"}])
        plan = suggest_plan(addressing, "10.20.5.0/24", internal_networks=["10.20.0.0/16"])
        self.assertFalse(any("outside the sensor" in w for w in plan["warnings"]))


if __name__ == "__main__":
    unittest.main()
