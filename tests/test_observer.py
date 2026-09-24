from pathlib import Path
import asyncio
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from maintenance_center.core import RemoteState, PROJECTS
from maintenance_center.observer import ShadowObserver


class ObserverTests(unittest.TestCase):
    def gateway(self):
        gateway = Mock()
        gateway.catalog = {p: {"active": True} for p in PROJECTS}
        gateway.release_check.side_effect = lambda p: {"project": p, "current_images": self.images(p), "target_images": self.images(p), "current_version": "1.2.3", "update_available": False}
        gateway.query.side_effect = lambda p, action="status", *args: ({"overall": "healthy"} if action == "health" else {"containers": [{"service": s, "image_id": d} for s, d in self.images(p).items()]})
        gateway.operation_status.return_value = RemoteState("idle")
        return gateway

    @staticmethod
    def images(project):
        return {s: "sha256:" + "a" * 64 for s in (("config-flow", "sub-store") if project == "CONFIGFLOW" else (project,))}

    def test_full_day_restart_failure_and_gap_do_not_authorize_switch(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = [1000]
            gateway = self.gateway()
            observer = ShadowObserver(tmp, gateway, clock=lambda: now[0], monotonic=lambda: now[0])
            for sample in range(25):
                data = observer.sample()
                self.assertEqual(data["ready_for_review"], sample == 24)
                now[0] += 3600
            gateway.apply_update.assert_not_called()
            restarted = ShadowObserver(tmp, gateway, clock=lambda: now[0], monotonic=lambda: now[0])
            self.assertEqual(restarted.sample()["sample_count"], 1)
            gateway.release_check.side_effect = RuntimeError("secret must not persist")
            failed = restarted.sample()
            self.assertEqual(failed["sample_count"], 0)
            self.assertNotIn("secret", str(failed))
            gateway = self.gateway()
            observer.gateway = gateway
            now[0] += 5000
            self.assertEqual(observer.sample()["sample_count"], 1)

    def test_active_samples_never_qualify_as_shadow(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = [1000]
            observer = ShadowObserver(tmp, self.gateway(), lambda: now[0], lambda: now[0], mode="active")
            for _ in range(26):
                result = observer.sample()
                now[0] += 3600
            self.assertFalse(result["ready_for_review"])
            self.assertEqual(result["mode"], "active")
            self.assertEqual(observer.path.name, "monitor.sqlite3")
            self.assertFalse((Path(tmp) / "shadow.sqlite3").exists())

    def test_mismatched_image_and_clock_jump_reset(self):
        with tempfile.TemporaryDirectory() as tmp:
            now, mono = [1000], [1000]
            gateway = self.gateway()
            observer = ShadowObserver(tmp, gateway, lambda: now[0], lambda: mono[0])
            observer.sample()
            now[0] += 86400
            mono[0] += 1800
            self.assertEqual(observer.sample()["sample_count"], 1)
            gateway.release_check.side_effect = lambda p: {"project": p, "current_images": {s: "sha256:" + "b" * 64 for s in self.images(p)}, "target_images": self.images(p), "current_version": None, "update_available": True}
            self.assertEqual(observer.sample()["sample_count"], 0)

    def test_small_clock_adjustments_cannot_accumulate_fake_elapsed_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            now, mono = [1000], [1000]
            observer = ShadowObserver(tmp, self.gateway(), lambda: now[0], lambda: mono[0])
            for _ in range(25):
                data = observer.sample()
                now[0] += 3600
                mono[0] += 3541
            self.assertEqual(data["elapsed_seconds"], 3541 * 24)
            self.assertFalse(data["ready_for_review"])

    def test_only_four_managed_projects_are_observed(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = self.gateway()
            observer = ShadowObserver(tmp, gateway)
            result = observer.sample()
            self.assertEqual([row["project"] for row in result["projects"]],
                             ["MOVIEPILOT2", "EMBY", "PLEX", "CONFIGFLOW"])
            self.assertNotIn("MEDIAVAULT3", [call.args[0] for call in gateway.mock_calls if call.args])


class ObserverLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_database_failure_resets_window_before_next_sample(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = [1000]
            observer = ShadowObserver(tmp, ObserverTests().gateway(), lambda: now[0], lambda: now[0])
            observer.sample()
            now[0] += 1800
            original = observer.sample
            loop = asyncio.get_running_loop()

            def failing_sample():
                try:
                    return original()
                finally:
                    loop.call_soon_threadsafe(observer.stop_event.set)

            with patch.object(observer, "sample", side_effect=failing_sample), patch.object(observer, "connect", side_effect=sqlite3.OperationalError("disk full")):
                await asyncio.wait_for(observer.run(), timeout=2)
            self.assertIsNone(observer.window_start)
            self.assertIsNone(observer.window_start_mono)
            self.assertEqual(observer.count, 0)
            now[0] += 1800
            recovered = observer.sample()
            self.assertEqual(recovered["sample_count"], 1)
            self.assertEqual(recovered["elapsed_seconds"], 0)
            self.assertFalse(recovered["ready_for_review"])

    async def test_stop_waits_for_inflight_sample_without_repeating_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            observer = ShadowObserver(tmp, ObserverTests().gateway())
            started, release = threading.Event(), threading.Event()

            def blocked_sample():
                started.set()
                if not release.wait(timeout=2):
                    raise RuntimeError("test worker timed out")

            with patch.object(observer, "sample", side_effect=blocked_sample) as sample:
                task = asyncio.create_task(observer.run())
                self.assertTrue(await asyncio.to_thread(started.wait, 1))
                stopping = asyncio.create_task(observer.stop(task))
                try:
                    await asyncio.sleep(0)
                    self.assertFalse(stopping.done())
                finally:
                    release.set()
                    await asyncio.wait_for(stopping, timeout=2)
                sample.assert_called_once()
