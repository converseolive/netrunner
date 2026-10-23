"""Unit tests for app.core.settings (isolated to a temp file, no repo writes)."""

import os
import tempfile
import unittest

from app.core import settings


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self._orig = settings.SETTINGS_FILE
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(self.path)  # let the store create it fresh
        settings.SETTINGS_FILE = self.path

    def tearDown(self):
        settings.SETTINGS_FILE = self._orig
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_defaults_when_missing(self):
        s = settings.get_settings()
        self.assertIn("extrahop", s)
        self.assertEqual(s["extrahop"]["internal_networks"], [])

    def test_save_valid_networks_roundtrip(self):
        settings.save_settings(
            {"extrahop": {"internal_networks": ["10.20.0.0/16", "10.21.0.0/24"]}})
        s = settings.get_settings()
        self.assertEqual(s["extrahop"]["internal_networks"],
                         ["10.20.0.0/16", "10.21.0.0/24"])

    def test_save_normalizes_and_drops_blanks(self):
        settings.save_settings(
            {"extrahop": {"internal_networks": ["10.20.1.5/16", "  "]}})
        s = settings.get_settings()
        # host bits cleared, blank dropped
        self.assertEqual(s["extrahop"]["internal_networks"], ["10.20.0.0/16"])

    def test_invalid_cidr_rejected(self):
        with self.assertRaises(ValueError):
            settings.save_settings({"extrahop": {"internal_networks": ["nope"]}})

    def test_other_fields_preserved(self):
        settings.save_settings({"extrahop": {"base_url": "https://rx.lab"}})
        settings.save_settings({"extrahop": {"internal_networks": ["10.0.0.0/8"]}})
        s = settings.get_settings()
        self.assertEqual(s["extrahop"]["base_url"], "https://rx.lab")
        self.assertEqual(s["extrahop"]["internal_networks"], ["10.0.0.0/8"])


if __name__ == "__main__":
    unittest.main()
