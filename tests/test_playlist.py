"""Unit tests for Play all: planner offset, playlist planning, library, runner."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from scapy.all import Ether, IP, TCP, wrpcap

from app.core import engine, playlist, runs
from app.core.rewrite_planner import summarize_addressing, suggest_plan


def _hosts(*ips):
    return [{"ip": ip, "mac": f"aa:aa:aa:00:00:{i:02x}"} for i, ip in enumerate(ips, 1)]


class BlockOffsetTests(unittest.TestCase):
    def test_offset_shifts_into_later_block(self):
        addressing = summarize_addressing(_hosts("192.168.1.10"))
        plan = suggest_plan(addressing, "10.99.0.0/16", block_offset=2)
        self.assertEqual(plan["ip_map"]["192.168.1.10"], "10.99.2.10")

    def test_offset_past_capacity_warns(self):
        addressing = summarize_addressing(_hosts("192.168.1.10"))
        plan = suggest_plan(addressing, "10.99.0.0/24", block_offset=1)
        self.assertTrue(plan["warnings"])


class PlaylistPlanTests(unittest.TestCase):
    def test_captures_get_non_overlapping_blocks(self):
        entries = [
            {"name": "a.pcap", "path": "/x/a", "hosts": _hosts("192.168.1.10", "8.8.8.8")},
            {"name": "b.pcap", "path": "/x/b", "hosts": _hosts("10.7.15.10", "10.7.16.20")},
        ]
        plans = playlist.build_playlist_plan(entries, "10.160.0.0/16")
        self.assertEqual(plans[0]["ip_map"]["192.168.1.10"], "10.160.0.10")
        # second capture's two /24s start after the first capture's single /24
        self.assertEqual(plans[1]["ip_map"]["10.7.15.10"], "10.160.1.10")
        self.assertEqual(plans[1]["ip_map"]["10.7.16.20"], "10.160.2.20")
        lab_a = set(plans[0]["ip_map"].values())
        lab_b = set(plans[1]["ip_map"].values())
        self.assertFalse(lab_a & lab_b)

    def test_wire_ips_include_untouched_externals(self):
        entries = [{"name": "a.pcap", "path": "/x/a",
                    "hosts": _hosts("192.168.1.10", "185.100.87.42")}]
        plan = playlist.build_playlist_plan(entries, "10.160.0.0/16")[0]
        self.assertIn("10.160.0.10", plan["wire_ips"])
        self.assertIn("185.100.87.42", plan["wire_ips"])
        self.assertNotIn("192.168.1.10", plan["wire_ips"])


class LibraryTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        for name in ("a.pcap", "b.pcapng", "c.pcap.gz", "rewritten_a.pcap", "notes.txt"):
            open(os.path.join(self.dir, name), "wb").close()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_list_excludes_outputs_and_non_captures(self):
        names = [c["name"] for c in playlist.list_captures(self.dir)]
        self.assertEqual(names, ["a.pcap", "b.pcapng", "c.pcap.gz"])

    def test_resolve_rejects_traversal_and_unknown(self):
        self.assertIsNotNone(playlist.resolve_capture(self.dir, "a.pcap"))
        self.assertIsNone(playlist.resolve_capture(self.dir, "../a.pcap"))
        self.assertIsNone(playlist.resolve_capture(self.dir, "sub/a.pcap"))
        self.assertIsNone(playlist.resolve_capture(self.dir, "notes.txt"))
        self.assertIsNone(playlist.resolve_capture(self.dir, "missing.pcap"))

    def test_capture_hosts_parses_ips(self):
        path = os.path.join(self.dir, "real.pcap")
        wrpcap(path, [Ether(src="aa:aa:aa:00:00:01", dst="aa:aa:aa:00:00:02")
                      / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(dport=443)])
        ips = {h["ip"] for h in playlist.capture_hosts(path)}
        self.assertEqual(ips, {"192.168.1.10", "8.8.8.8"})


class RunPlaylistTests(unittest.TestCase):
    def setUp(self):
        self._runs_file = runs.RUNS_FILE
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(path)
        runs.RUNS_FILE = path
        runs.recent_runs.clear()
        engine.active_task_status["is_running"] = True
        engine.active_task_status["error"] = None
        self.plans = [
            {"name": "a.pcap", "path": "/x/a", "ip_map": {}, "wire_ips": ["10.160.0.10"]},
            {"name": "b.pcap", "path": "/x/b", "ip_map": {}, "wire_ips": ["10.160.1.10"]},
        ]

    def tearDown(self):
        engine.active_task_status["is_running"] = False
        engine.active_task_status["error"] = None
        if os.path.exists(runs.RUNS_FILE):
            os.remove(runs.RUNS_FILE)
        runs.RUNS_FILE = self._runs_file
        runs.recent_runs.clear()

    def test_replays_each_and_records_finished_runs(self):
        with mock.patch.object(playlist, "replay_once") as rep:
            playlist.run_playlist(self.plans, {"interface": "lo0"})
        self.assertEqual(rep.call_count, 2)
        self.assertEqual([r["label"] for r in runs.recent_runs],
                         ["Replay: a.pcap", "Replay: b.pcap"])
        self.assertTrue(all(r["end_ms"] for r in runs.recent_runs))
        self.assertEqual(rep.call_args_list[0][0][0]["filepath"], "/x/a")

    def test_one_failure_does_not_stop_the_rest(self):
        def boom(params):
            if params["filepath"] == "/x/a":
                raise RuntimeError("send failed")
        with mock.patch.object(playlist, "replay_once", side_effect=boom) as rep:
            playlist.run_playlist(self.plans, {"interface": "lo0"})
        self.assertEqual(rep.call_count, 2)
        self.assertIn("a.pcap", engine.active_task_status["error"])

    def test_stopped_job_plays_nothing(self):
        engine.active_task_status["is_running"] = False
        with mock.patch.object(playlist, "replay_once") as rep:
            playlist.run_playlist(self.plans, {"interface": "lo0"})
        self.assertEqual(rep.call_count, 0)


if __name__ == "__main__":
    unittest.main()
