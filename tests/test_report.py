"""Unit tests for app.core.report (HTML detection report)."""

import unittest

from app.core import detection_match, report


class ReportTests(unittest.TestCase):
    def test_sample_report_renders(self):
        html = report.build_report_html(detection_match.sample_result())
        self.assertIn("NetRunner Detection Validation Report", html)
        self.assertIn("Detection rate", html)
        self.assertIn("Sample data", html)      # sample banner present
        self.assertIn("C2 Beaconing", html)     # a scenario row

    def test_live_report_has_no_sample_banner(self):
        res = detection_match.validate([], [])  # configured/live, just empty
        html = report.build_report_html(res)
        self.assertNotIn("Sample data", html)
        self.assertIn("live appliance", html)

    def test_report_escapes_html(self):
        res = {"summary": {}, "sample": False, "coverage": [],
               "rows": [{"name": "<script>", "technique": "T1", "flow": "a->b",
                         "status": "missed", "risk": None, "ttd_ms": None,
                         "detection": None}]}
        html = report.build_report_html(res)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)


if __name__ == "__main__":
    unittest.main()
