"""Unit tests for the engine job manager (concurrency + per-job isolation)."""

import threading
import time
import unittest

from app.core import engine


def _wait_done(jid, timeout=3):
    end = time.time() + timeout
    while time.time() < end:
        job = engine.get_job(jid)
        if job and not job['is_running']:
            return True
        time.sleep(0.01)
    return False


class JobManagerTests(unittest.TestCase):
    def setUp(self):
        engine.stop_all_jobs()
        engine._jobs.clear()

    def tearDown(self):
        engine.stop_all_jobs()
        engine._jobs.clear()

    def test_run_job_runs_target_and_marks_done(self):
        ran = threading.Event()

        def task():
            engine.active_task_status['message'] = 'hello'
            ran.set()

        jid = engine.run_job('generate', task, label='t')
        self.assertTrue(ran.wait(2))
        self.assertTrue(_wait_done(jid))
        job = engine.get_job(jid)
        self.assertEqual(job['message'], 'hello')
        self.assertFalse(job['is_running'])
        self.assertIsNotNone(job['ended_at'])

    def test_two_jobs_have_isolated_status(self):
        # The core correctness property: concurrent tasks must not share status.
        start = threading.Barrier(3)

        def make(name):
            def task():
                start.wait()
                for _ in range(100):
                    engine.active_task_status['message'] = name
                    engine.active_task_status['progress'] += 1
            return task

        j1 = engine.run_job('generate', make('alpha'), label='a')
        j2 = engine.run_job('generate', make('beta'), label='b')
        start.wait()  # release both at once so they interleave

        self.assertTrue(_wait_done(j1))
        self.assertTrue(_wait_done(j2))
        self.assertEqual(engine.get_job(j1)['message'], 'alpha')
        self.assertEqual(engine.get_job(j2)['message'], 'beta')
        self.assertEqual(engine.get_job(j1)['progress'], 100)
        self.assertEqual(engine.get_job(j2)['progress'], 100)

    def test_stop_job_signals_the_task(self):
        started = threading.Event()
        released = threading.Event()

        def task():
            started.set()
            while engine.active_task_status['is_running']:
                time.sleep(0.01)
            released.set()

        jid = engine.run_job('generate', task, label='loop')
        self.assertTrue(started.wait(2))
        self.assertTrue(engine.get_job(jid)['is_running'])
        self.assertTrue(engine.stop_job(jid))
        self.assertTrue(released.wait(2))

    def test_error_in_task_is_recorded_not_fatal(self):
        def task():
            raise RuntimeError("kaboom")

        jid = engine.run_job('generate', task, label='bad')
        self.assertTrue(_wait_done(jid))
        self.assertIn("kaboom", engine.get_job(jid)['error'])

    def test_list_and_clear_finished(self):
        done = threading.Event()
        jid = engine.run_job('generate', lambda: done.set(), label='x')
        self.assertTrue(done.wait(2))
        self.assertTrue(_wait_done(jid))
        self.assertTrue(any(j['id'] == jid for j in engine.list_jobs()))
        engine.clear_finished_jobs()
        self.assertIsNone(engine.get_job(jid))


if __name__ == "__main__":
    unittest.main()
