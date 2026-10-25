"""Unit tests for app.core.validation (orchestration; appliance mocked)."""

import os
import tempfile
import time
import unittest
from unittest import mock

from app.core import validation, runs, settings, extrahop


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self._settings_file = settings.SETTINGS_FILE
        self._runs_file = runs.RUNS_FILE
        for mod, attr in ((settings, "SETTINGS_FILE"), (runs, "RUNS_FILE")):
            fd, path = tempfile.mkstemp(suffix=".json")
            os.close(fd)
            os.remove(path)
            setattr(mod, attr, path)
        runs.recent_runs.clear()

    def tearDown(self):
        for path in (settings.SETTINGS_FILE, runs.RUNS_FILE):
            if os.path.exists(path):
                os.remove(path)
        settings.SETTINGS_FILE = self._settings_file
        runs.RUNS_FILE = self._runs_file
        runs.recent_runs.clear()

    def _configure(self):
        settings.save_settings({"extrahop": {"base_url": "https://rx.lab", "api_key": "k"}})

    def test_sample_when_not_configured(self):
        result = validation.run_validation()
        self.assertTrue(result["sample"])
        self.assertEqual(result["note"], "not_configured")

    def test_no_runs_when_configured_but_empty(self):
        self._configure()
        result = validation.run_validation()
        self.assertEqual(result.get("note"), "no_runs")
        self.assertFalse(result.get("sample"))

    def test_real_validation_with_mocked_search(self):
        self._configure()
        now = int(time.time() * 1000)
        runs.register_run({"scenario": "port_scan", "adversary_ip": "10.0.0.5",
                           "victim_ip": "10.0.0.9"})
        detections = [{
            "id": 1, "title": "Port Scan", "risk_score": 55, "techniques": ["T1046"],
            "participants": [{"role": "offender", "ip": "10.0.0.5"},
                             {"role": "victim", "ip": "10.0.0.9"}],
            "start_ms": now, "end_ms": now + 1000,
        }]
        with mock.patch.object(extrahop, "search_detections", return_value=detections):
            result = validation.run_validation()
        self.assertFalse(result["sample"])
        self.assertEqual(result["summary"]["detected"], 1)
        self.assertEqual(result["detection_total"], 1)

    def test_appliance_error_falls_back_to_sample(self):
        self._configure()
        runs.register_run({"scenario": "port_scan", "adversary_ip": "10.0.0.5"})
        with mock.patch.object(extrahop, "search_detections",
                               side_effect=RuntimeError("boom")):
            result = validation.run_validation()
        self.assertTrue(result["sample"])
        self.assertEqual(result["note"], "appliance_error")
        self.assertIn("boom", result["error"])


if __name__ == "__main__":
    unittest.main()
