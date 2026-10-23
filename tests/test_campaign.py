"""Unit tests for app.core.campaign (orchestration; packet send is mocked out)."""

import unittest
from unittest import mock

from app.core import campaign
from app.core import engine


class CampaignPlanTests(unittest.TestCase):
    def test_default_plan_covers_all_scenarios(self):
        plan = campaign.campaign_plan({})
        self.assertEqual(len(plan), len(campaign.CAMPAIGN_ORDER))
        self.assertEqual([p["simulation"] for p in plan], campaign.CAMPAIGN_ORDER)

    def test_subset_keeps_canonical_order(self):
        plan = campaign.campaign_plan({}, ["port_scan", "c2_beacon"])
        sims = [p["simulation"] for p in plan]
        self.assertEqual(sims, ["c2_beacon", "port_scan"])  # canonical, not request order

    def test_unknown_scenarios_dropped(self):
        plan = campaign.campaign_plan({}, ["port_scan", "bogus"])
        self.assertEqual([p["simulation"] for p in plan], ["port_scan"])

    def test_settings_propagate_into_params(self):
        plan = campaign.campaign_plan({"src_ip": "10.1.1.1", "interface": "mon0"},
                                      ["c2_beacon"])
        self.assertEqual(plan[0]["src_ip"], "10.1.1.1")
        self.assertEqual(plan[0]["interface"], "mon0")


class RunCampaignTests(unittest.TestCase):
    def setUp(self):
        engine.recent_runs.clear()
        engine.active_task_status["is_running"] = True
        engine.active_task_status["error"] = None

    def tearDown(self):
        engine.active_task_status["is_running"] = False

    def test_registers_a_run_per_scenario_and_resets(self):
        with mock.patch("app.core.generators.adversary.run_one") as run_one:
            campaign.run_campaign({}, ["c2_beacon", "port_scan"])
        self.assertEqual(run_one.call_count, 2)
        self.assertEqual({r["scenario"] for r in engine.recent_runs},
                         {"c2_beacon", "port_scan"})
        self.assertFalse(engine.active_task_status["is_running"])

    def test_stopped_before_start_runs_nothing(self):
        engine.active_task_status["is_running"] = False
        with mock.patch("app.core.generators.adversary.run_one") as run_one:
            campaign.run_campaign({}, ["c2_beacon", "port_scan"])
        self.assertEqual(run_one.call_count, 0)

    def test_one_scenario_failure_does_not_abort_suite(self):
        def boom(params):
            if params["simulation"] == "c2_beacon":
                raise RuntimeError("send failed")
        with mock.patch("app.core.generators.adversary.run_one", side_effect=boom) as run_one:
            campaign.run_campaign({}, ["c2_beacon", "port_scan"])
        self.assertEqual(run_one.call_count, 2)  # continued past the failure


if __name__ == "__main__":
    unittest.main()
