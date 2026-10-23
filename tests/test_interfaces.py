"""Unit tests for app.core.interfaces (enumeration + preflight validation)."""

import unittest

from app.core import interfaces


class InterfaceTests(unittest.TestCase):
    def test_list_returns_named_dicts(self):
        ifs = interfaces.list_interfaces()
        self.assertIsInstance(ifs, list)
        for i in ifs:
            self.assertIn("name", i)

    def test_host_has_at_least_one_interface(self):
        # any host running the tests has at least a loopback
        self.assertGreaterEqual(len(interfaces.interface_names()), 1)

    def test_known_interface_validates(self):
        names = interfaces.interface_names()
        self.assertTrue(names)  # guarded by the test above
        ok, err = interfaces.validate_interface(names[0])
        self.assertTrue(ok)
        self.assertEqual(err, "")

    def test_unknown_interface_rejected(self):
        ok, err = interfaces.validate_interface("definitely-not-real-xyz0")
        self.assertFalse(ok)
        self.assertIn("not found", err)

    def test_empty_interface_rejected(self):
        ok, err = interfaces.validate_interface("")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
