"""Unit tests for app.core.runs (persistent run store, isolated to a temp file)."""

import os
import tempfile
import unittest

from app.core import runs


class RunsTests(unittest.TestCase):
    def setUp(self):
        self._orig = runs.RUNS_FILE
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(self.path)  # start with no file
        runs.RUNS_FILE = self.path
        runs.recent_runs.clear()

    def tearDown(self):
        runs.RUNS_FILE = self._orig
        runs.recent_runs.clear()
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_register_persists_and_reloads(self):
        rid = runs.register_run({"scenario": "c2_beacon", "adversary_ip": "10.0.0.5"})
        self.assertTrue(os.path.exists(self.path))
        # simulate a restart: drop the in-memory list and reload from disk
        runs.recent_runs.clear()
        runs._load()
        self.assertEqual(len(runs.recent_runs), 1)
        self.assertEqual(runs.recent_runs[0]["id"], rid)
        self.assertEqual(runs.recent_runs[0]["scenario"], "c2_beacon")

    def test_finish_sets_end_and_persists(self):
        rid = runs.register_run({"scenario": "port_scan"})
        self.assertIsNone(runs.recent_runs[0]["end_ms"])
        runs.finish_run(rid)
        runs.recent_runs.clear()
        runs._load()
        self.assertIsNotNone(runs.recent_runs[0]["end_ms"])

    def test_clear_empties_memory_and_disk(self):
        runs.register_run({"scenario": "dga"})
        runs.clear_runs()
        self.assertEqual(runs.recent_runs, [])
        runs._load()
        self.assertEqual(runs.recent_runs, [])

    def test_cap_enforced(self):
        for _ in range(runs._MAX + 10):
            runs.register_run({"scenario": "dga"})
        self.assertEqual(len(runs.recent_runs), runs._MAX)


if __name__ == "__main__":
    unittest.main()
