"""Unit tests for app.core.detection_match (pure, no appliance needed)."""

import time
import unittest

from app.core import detection_match as dm


def _now():
    return int(time.time() * 1000)


def _det(tech, ips, risk=70, start=None):
    now = _now()
    return {"id": "d", "title": f"det-{tech}", "risk_score": risk,
            "techniques": [tech], "tactics": [], "categories": [],
            "participants": [{"role": "offender", "ip": ips[0]},
                             {"role": "victim", "ip": ips[1]}],
            "start_ms": start or now, "end_ms": (start or now) + 1000}


class ScorecardTests(unittest.TestCase):
    def test_detected_when_ip_time_technique_match(self):
        now = _now()
        runs = [{"scenario": "c2_beacon", "adversary_ip": "10.0.0.5",
                 "c2_ip": "9.9.9.9", "start_ms": now - 1000, "end_ms": now}]
        dets = [_det("T1071", ["10.0.0.5", "9.9.9.9"])]
        card = dm.build_scorecard(runs, dets)
        self.assertEqual(card["rows"][0]["status"], "detected")
        self.assertEqual(card["summary"]["detected"], 1)
        self.assertEqual(card["summary"]["detection_rate"], 1.0)

    def test_missed_when_no_detection(self):
        now = _now()
        runs = [{"scenario": "dns_exfil", "adversary_ip": "10.0.0.7",
                 "victim_ip": "10.0.0.53", "start_ms": now - 1000, "end_ms": now}]
        card = dm.build_scorecard(runs, [])
        self.assertEqual(card["rows"][0]["status"], "missed")

    def test_partial_when_technique_differs(self):
        now = _now()
        runs = [{"scenario": "icmp_tunnel", "adversary_ip": "10.0.0.5",
                 "victim_ip": "10.0.0.1", "start_ms": now - 1000, "end_ms": now}]
        # a detection fires on the right hosts/time but a different technique
        dets = [_det("T1572", ["10.0.0.5", "10.0.0.1"])]
        card = dm.build_scorecard(runs, dets)
        self.assertEqual(card["rows"][0]["status"], "partial")

    def test_time_outside_window_is_missed(self):
        now = _now()
        runs = [{"scenario": "c2_beacon", "adversary_ip": "10.0.0.5",
                 "c2_ip": "9.9.9.9", "start_ms": now, "end_ms": now}]
        old = _det("T1071", ["10.0.0.5", "9.9.9.9"], start=now - 3_600_000)
        card = dm.build_scorecard(runs, [old])
        self.assertEqual(card["rows"][0]["status"], "missed")

    def test_ttd_is_non_negative(self):
        now = _now()
        runs = [{"scenario": "c2_beacon", "adversary_ip": "10.0.0.5",
                 "c2_ip": "9.9.9.9", "start_ms": now, "end_ms": now}]
        dets = [_det("T1071", ["10.0.0.5", "9.9.9.9"], start=now + 30_000)]
        card = dm.build_scorecard(runs, dets)
        self.assertEqual(card["rows"][0]["ttd_ms"], 30_000)


class CoverageTests(unittest.TestCase):
    def test_run_scenario_marked_detected(self):
        runs = [{"scenario": "port_scan", "_status": "detected"}]
        cov = dm.build_coverage(runs)
        cells = [c for col in cov for c in col["cells"] if c["scenario"] == "port_scan"]
        self.assertEqual(cells[0]["status"], "detected")

    def test_unrun_scenario_marked_not_run(self):
        cov = dm.build_coverage([])
        cells = [c for col in cov for c in col["cells"] if c["scenario"] == "dcsync"]
        self.assertEqual(cells[0]["status"], "not_run")

    def test_columns_follow_tactic_order(self):
        cov = dm.build_coverage([])
        tactics = [col["tactic"] for col in cov]
        self.assertEqual(tactics[0], "Discovery")


class ReplayTests(unittest.TestCase):
    def test_replay_detected_on_any_technique(self):
        now = _now()
        runs = [{"kind": "replay", "scenario": None, "label": "Replay: cap.pcap",
                 "ips": ["10.5.0.5", "10.5.0.9"], "start_ms": now - 1000, "end_ms": now}]
        # a replay has no expected technique, so any detection on its hosts counts
        dets = [_det("T9999", ["10.5.0.5", "10.5.0.9"])]
        card = dm.build_scorecard(runs, dets)
        self.assertEqual(card["rows"][0]["status"], "detected")
        self.assertEqual(card["rows"][0]["name"], "Replay: cap.pcap")

    def test_replay_missed_without_detection(self):
        now = _now()
        runs = [{"kind": "replay", "scenario": None, "ips": ["10.5.0.5"],
                 "start_ms": now - 1000, "end_ms": now}]
        card = dm.build_scorecard(runs, [])
        self.assertEqual(card["rows"][0]["status"], "missed")


class SampleTests(unittest.TestCase):
    def test_sample_is_flagged_and_populated(self):
        r = dm.sample_result()
        self.assertTrue(r["sample"])
        self.assertTrue(r["summary"]["detected"] >= 1)
        self.assertTrue(len(r["rows"]) >= 6)

    def test_sample_has_a_gap_and_a_partial(self):
        r = dm.sample_result()
        statuses = {row["scenario"]: row["status"] for row in r["rows"]}
        self.assertEqual(statuses.get("dns_exfil"), "missed")
        self.assertEqual(statuses.get("icmp_tunnel"), "partial")


if __name__ == "__main__":
    unittest.main()
