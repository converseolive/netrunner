"""Unit tests for beacon scheduling and the timed C2 beacon simulation."""

import random
import unittest
from unittest import mock

from app.core.beacon import beacon_schedule, jittered_delay


class ScheduleTests(unittest.TestCase):
    def test_zero_interval_or_duration_is_empty(self):
        self.assertEqual(beacon_schedule(60, 0, 10), [])
        self.assertEqual(beacon_schedule(0, 5, 10), [])

    def test_no_jitter_is_regular(self):
        gaps = beacon_schedule(60, 5, 0)
        self.assertTrue(all(g == 5 for g in gaps))
        self.assertAlmostEqual(len(gaps), 12, delta=1)

    def test_jitter_within_bounds(self):
        rng = random.Random(1)
        gaps = beacon_schedule(300, 10, 40, rng=rng)
        self.assertTrue(all(6.0 <= g <= 14.0 for g in gaps))

    def test_duration_roughly_respected(self):
        rng = random.Random(7)
        gaps = beacon_schedule(120, 5, 20, rng=rng)
        # cumulative time lands within one interval of the duration
        self.assertLessEqual(sum(gaps) - gaps[-1], 120)
        self.assertGreaterEqual(sum(gaps), 120)

    def test_deterministic_with_seed(self):
        a = beacon_schedule(60, 5, 30, rng=random.Random(99))
        b = beacon_schedule(60, 5, 30, rng=random.Random(99))
        self.assertEqual(a, b)


class JitteredDelayTests(unittest.TestCase):
    def test_zero_jitter_returns_base(self):
        self.assertEqual(jittered_delay(0.5, 0), 0.5)

    def test_zero_base_returns_zero(self):
        self.assertEqual(jittered_delay(0, 50), 0.0)

    def test_within_bounds(self):
        rng = random.Random(3)
        for _ in range(50):
            d = jittered_delay(1.0, 40, rng=rng)
            self.assertTrue(0.6 <= d <= 1.4)

    def test_deterministic_with_seed(self):
        a = jittered_delay(2.0, 30, rng=random.Random(5))
        b = jittered_delay(2.0, 30, rng=random.Random(5))
        self.assertEqual(a, b)

    def test_never_negative(self):
        rng = random.Random(0)
        for _ in range(50):
            self.assertGreaterEqual(jittered_delay(0.1, 95, rng=rng), 0.0)


class BeaconSimTests(unittest.TestCase):
    def setUp(self):
        from app.core import engine
        self.engine = engine
        engine.active_task_status["is_running"] = True

    def tearDown(self):
        self.engine.active_task_status["is_running"] = False

    def _params(self, **extra):
        p = {"interface": "lo", "src_ip": "10.0.0.5", "c2_host": "9.9.9.9",
             "src_mac": "02:00:00:00:00:01", "dst_mac": "ff:ff:ff:ff:ff:ff",
             "delay": 1.0, "count": 5}
        p.update(extra)
        return p

    def test_sustained_campaign_sends_and_tracks(self):
        from app.core.generators import adversary
        with mock.patch.object(adversary, "sendp") as snd, \
                mock.patch.object(adversary.time, "sleep"):
            adversary._sim_c2_beacon(self._params(duration_min=0.2, jitter=20))
        self.assertGreater(snd.call_count, 0)
        self.assertGreater(self.engine.active_task_status["total"], 0)
        self.assertGreater(self.engine.active_task_status["progress"], 0)

    def test_stop_before_start_sends_nothing(self):
        from app.core.generators import adversary
        self.engine.active_task_status["is_running"] = False
        with mock.patch.object(adversary, "sendp") as snd, \
                mock.patch.object(adversary.time, "sleep"):
            adversary._sim_c2_beacon(self._params(duration_min=0.2))
        self.assertEqual(snd.call_count, 0)

    def test_burst_fallback_without_duration(self):
        from app.core.generators import adversary
        with mock.patch.object(adversary, "sendp") as snd, \
                mock.patch.object(adversary.time, "sleep"):
            adversary._sim_c2_beacon(self._params(duration_min=0, count=3))
        self.assertGreater(snd.call_count, 0)


if __name__ == "__main__":
    unittest.main()
