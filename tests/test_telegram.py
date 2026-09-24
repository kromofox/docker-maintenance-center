import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from maintenance_center.core import Core, MaintenanceError, Outcome
from maintenance_center.demo import DemoGateway
from maintenance_center.notices import Notices
from maintenance_center.telegram_control import TelegramControl
from maintenance_center.telegram_runtime import TelegramRuntime
from maintenance_center.telegram_store import TelegramStore
from maintenance_center.web import create_demo_app
from test_auth_web import Inputs


# Deliberately fake values used only with an in-process transport.
TOKEN = "123456:" + "a" * 35
OTHER = "123456:" + "b" * 35


class Fixture:
    def setup_files(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.directory = self.base / "state"
        self.directory.mkdir()
        self.key = self.base / "secret"
        self.key.write_bytes(Fernet.generate_key())
        self.key.chmod(0o600)
        self.now = 10000
        self.store = TelegramStore(self.directory, self.key, clock=lambda: self.now)

    def configured(self):
        self.store.replace_verified(TOKEN, 123456, "fixture_bot", self.store.state()["revision"])

    def bound(self):
        self.configured()
        code = self.store.begin_binding(self.store.state()["revision"])
        self.store.bind(code, 42, 42, "private")


class StoreTests(Fixture, unittest.TestCase):
    def setUp(self):
        self.setup_files()

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_ciphertext_only_and_state_has_no_token_fragment(self):
        self.configured()
        self.assertEqual(self.store.token(), TOKEN)
        raw = (self.directory / "telegram.sqlite3").read_bytes()
        self.assertNotIn(TOKEN.encode(), raw)
        self.assertNotIn(TOKEN[-5:], json.dumps(self.store.state()))
        self.assertNotIn(self.key.read_bytes(), raw)

    def test_missing_wrong_or_insecure_key_fails_closed_and_can_reconfigure(self):
        self.configured()
        self.key.unlink()
        self.assertEqual(self.store.state()["error"], "telegram_key_unavailable")
        self.key.write_bytes(Fernet.generate_key())
        self.key.chmod(0o600)
        self.assertTrue(self.store.state()["key_ready"])
        with self.assertRaises(MaintenanceError):
            self.store.token()
        self.store.replace_verified(OTHER, 123456, "fixture_bot", self.store.state()["revision"])
        self.assertEqual(self.store.token(), OTHER)
        self.key.chmod(0o644)
        self.assertFalse(self.store.state()["key_ready"])

    def test_key_cannot_be_in_state_or_symlink(self):
        self.store.key_file = self.directory / "secret"
        self.store.key_file.write_bytes(self.key.read_bytes())
        self.store.key_file.chmod(0o600)
        self.assertFalse(self.store.state()["key_ready"])
        link = self.base / "link"
        link.symlink_to(self.key)
        self.store.key_file = link
        self.assertFalse(self.store.state()["key_ready"])

    def test_binding_private_only_single_use_and_expires(self):
        self.configured()
        code = self.store.begin_binding(self.store.state()["revision"])
        with self.assertRaises(MaintenanceError):
            self.store.bind(code, 42, -42, "group")
        self.store.bind(code, 42, 42, "private")
        self.assertTrue(self.store.authorized(42, 42, "private"))
        self.assertFalse(self.store.authorized(43, 43, "private"))
        self.assertFalse(self.store.authorized(42, 42, "group"))
        with self.assertRaises(MaintenanceError):
            self.store.bind(code, 43, 43, "private")
        code = self.store.begin_binding(self.store.state()["revision"])
        self.assertFalse(self.store.authorized(42, 42, "private"))
        self.now += 600
        with self.assertRaises(MaintenanceError):
            self.store.bind(code, 42, 42, "private")

    def test_restart_invalidates_binding_code(self):
        self.configured()
        code = self.store.begin_binding(self.store.state()["revision"])
        self.store.close()
        self.store = TelegramStore(self.directory, self.key)
        with self.assertRaises(MaintenanceError):
            self.store.bind(code, 42, 42, "private")

    def test_token_change_identity_and_delete_revoke_access(self):
        self.bound()
        stale = self.store.state()["revision"]
        self.store.replace_verified(OTHER, 654321, "another_bot", stale)
        self.assertFalse(self.store.authorized(42, 42, "private"))
        with self.assertRaisesRegex(MaintenanceError, "stale"):
            self.store.delete(stale)
        self.store.delete(self.store.state()["revision"])
        self.assertIsNone(self.store.token())


class ControlTests(Fixture, unittest.TestCase):
    def setUp(self):
        self.setup_files()
        self.bound()
        self.core = Core(self.directory, DemoGateway())
        self.core.reconcile()
        self.control = TelegramControl(self.core, self.store, clock=lambda: self.now)

    def tearDown(self):
        self.core.close()
        self.store.close()
        self.tmp.cleanup()

    def command(self, text):
        return self.control.command(text, 42, 42, "private")

    def click(self, reply, label):
        handle = next(value for title, value in reply.buttons if title == label)
        return self.control.callback(handle, 42, 42, "private")

    def test_resume_requires_bound_admin_confirmation_and_rejects_stale_event(self):
        with self.core._transaction() as db:
            db.execute("INSERT INTO project_pause(project,code,event_ref,retry_used) VALUES('PLEX','failed','event1',1)")
        for ids in [(43,43,"private"), (42,42,"group")]:
            with self.assertRaises(MaintenanceError):
                self.control.command("/resume PLEX", *ids)
        reply = self.command("/resume PLEX")
        self.assertIn("PLEX", self.core.state()["paused_projects"])
        handle = reply.buttons[0][1]
        with self.core._transaction() as db:
            db.execute("UPDATE project_pause SET event_ref='event2'")
        with self.assertRaisesRegex(MaintenanceError, "stale_recovery"):
            self.control.callback(handle, 42, 42, "private")
        reply = self.command("/resume PLEX")
        self.control.callback(reply.buttons[0][1], 42, 42, "private")
        self.assertNotIn("PLEX", self.core.state()["paused_projects"])
        with self.assertRaises(MaintenanceError):
            self.control.callback(reply.buttons[0][1], 42, 42, "private")

    def test_unauthorized_commands_never_reach_core(self):
        for ids in [(43, 43, "private"), (42, -42, "group")]:
            with self.assertRaisesRegex(MaintenanceError, "access_denied"):
                self.control.command("/check PLEX", *ids)
        self.assertFalse(self.core._plans)

    def test_schedule_requires_confirmation_and_old_web_revision_fails(self):
        reply = self.command("/set 2 EMBY,PLEX")
        self.assertFalse(self.core.state()["enabled"])
        self.click(reply, "确认保存")
        self.assertEqual(self.core.state()["targets"], ["EMBY", "PLEX"])
        stale = self.command("/set")
        self.core.configure(["PLEX"], 4, False, self.core.state()["revision"], "web")
        with self.assertRaisesRegex(MaintenanceError, "stale_schedule"):
            self.click(stale, "确认保存")

    def test_toggle_and_delete_are_drafts_until_confirmed(self):
        self.click(self.command("/set 2 PLEX"), "确认保存")
        draft = self.click(self.command("/set"), "删除计划")
        self.assertTrue(self.core.state()["enabled"])
        self.click(draft, "确认保存")
        self.assertFalse(self.core.state()["enabled"])
        self.assertEqual(self.core.state()["targets"], [])

    def test_manual_update_reject_and_cross_web_consumption(self):
        reply = self.command("/check PLEX")
        self.click(reply, "拒绝")
        with self.assertRaises(MaintenanceError):
            self.click(reply, "批准")
        reply = self.command("/check PLEX")
        ref = next(iter(self.core._plans))
        self.core.approve(ref, "web")
        with self.assertRaises(MaintenanceError):
            self.click(reply, "批准")

    def test_rebind_and_timeout_invalidate_buttons(self):
        reply = self.command("/check PLEX")
        code = self.store.begin_binding(self.store.state()["revision"])
        self.store.bind(code, 42, 42, "private")
        with self.assertRaisesRegex(MaintenanceError, "menu_expired"):
            self.click(reply, "批准")
        reply = self.command("/set")
        self.now += 300
        with self.assertRaisesRegex(MaintenanceError, "menu_expired"):
            self.click(reply, "确认保存")

    def test_special_actions_and_invalid_schedule_are_restricted(self):
        for text in ["/check NADEX", "/set 721 PLEX", "/set 2 NADEX",
                     "/check MEDIAVAULT3", "/resume MEDIAVAULT3", "/set 2 MEDIAVAULT3"]:
            with self.assertRaises(MaintenanceError):
                self.command(text)

    def test_removed_restart_command_creates_no_plan_or_buttons(self):
        for project in self.core.projects:
            reply = self.command("/restart " + project)
            self.assertEqual(reply.buttons, [])
        self.assertEqual(self.core._plans, {})
        self.assertEqual(self.core.db.execute("SELECT count(*) FROM operations").fetchone()[0], 0)


class FakeBot:
    fail = False
    sends = []
    updates = []
    polls = []

    def __init__(self, token):
        self.token = token

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, *args):
        await self.shutdown()

    async def initialize(self):
        if self.fail:
            raise RuntimeError("sensitive URL " + self.token)

    async def shutdown(self):
        pass

    async def get_me(self):
        return SimpleNamespace(id=123456, username="fixture_bot", is_bot=True)

    async def get_updates(self, offset=None, **kwargs):
        self.polls.append(offset)
        if offset == -1:
            return [SimpleNamespace(update_id=90)]
        result, self.__class__.updates = self.updates, []
        return result

    async def send_message(self, chat_id, text, **kwargs):
        self.sends.append((chat_id, text))


class RuntimeTests(Fixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.setup_files()
        self.core = Core(self.directory, DemoGateway())
        self.core.reconcile()
        FakeBot.fail, FakeBot.sends, FakeBot.updates, FakeBot.polls = False, [], [], []
        self.runtime = TelegramRuntime(self.core, self.store, self.directory, FakeBot)

    async def asyncTearDown(self):
        await self.runtime.stop()
        self.core.close()
        self.store.close()
        self.tmp.cleanup()

    async def test_failed_verification_preserves_old_token_and_redacts_error(self):
        self.configured()
        FakeBot.fail = True
        with self.assertRaisesRegex(MaintenanceError, "telegram_verification_failed") as error:
            await self.runtime.replace(OTHER, self.store.state()["revision"])
        self.assertNotIn(OTHER, str(error.exception))
        self.assertEqual(self.store.token(), TOKEN)

    async def test_verified_replacement_and_stale_revision(self):
        await self.runtime.replace(TOKEN, 0)
        with self.assertRaisesRegex(MaintenanceError, "stale"):
            await self.runtime.replace(OTHER, 0)
        self.assertEqual(self.store.token(), TOKEN)

    async def test_polling_discards_backlog_and_delete_stops_delivery(self):
        self.bound()
        await self.runtime.tick()
        self.assertEqual(FakeBot.polls, [-1, 91])
        await self.runtime.change_binding("delete", self.store.state()["revision"])
        await self.runtime.tick()
        self.assertIsNone(self.runtime.bot)
        self.assertEqual(len(FakeBot.polls), 2)

    async def test_unknown_sender_receives_no_project_state(self):
        self.bound()
        FakeBot.updates = [SimpleNamespace(update_id=91, effective_user=SimpleNamespace(id=43),
                            effective_chat=SimpleNamespace(id=43, type="private"),
                            callback_query=None, message=SimpleNamespace(text="/status"))]
        await self.runtime.tick()
        self.assertEqual(len(FakeBot.sends), 1)
        self.assertNotIn("PLEX", FakeBot.sends[0][1])


    async def test_plan_source_failure_is_actionable_and_does_not_lock_checks(self):
        self.bound()
        def fail_plan(_project):
            raise TimeoutError("secret transport detail")
        self.core.gateway.plan_update = fail_plan
        FakeBot.updates = [SimpleNamespace(update_id=91, effective_user=SimpleNamespace(id=42),
                            effective_chat=SimpleNamespace(id=42, type="private"),
                            callback_query=None, message=SimpleNamespace(text="/check PLEX"))]
        await self.runtime.tick()
        self.assertIn("更新源或宿主网关暂时不可用", FakeBot.sends[-1][1])
        self.assertEqual(self.core.state()["gate"], "ready")
        self.assertNotIn("secret transport detail", str(FakeBot.sends))
    async def test_shutdown_waits_for_inflight_work(self):
        started, finish = asyncio.Event(), asyncio.Event()
        async def tick():
            started.set()
            await finish.wait()
        self.runtime.tick = tick
        self.runtime.start()
        await started.wait()
        stopping = asyncio.create_task(self.runtime.stop())
        await asyncio.sleep(0)
        self.assertFalse(stopping.done())
        finish.set()
        await stopping
        # Avoid closing the same test resource twice.
        self.runtime.stop = lambda: asyncio.sleep(0)


class NoticeTests(Fixture, unittest.TestCase):
    def setUp(self):
        self.setup_files()
        self.core = Core(self.directory, DemoGateway())
        self.core.reconcile()
        self.notices = Notices(self.directory, clock=lambda: self.now)

    def tearDown(self):
        self.notices.close()
        self.core.close()
        self.store.close()
        self.tmp.cleanup()

    def result(self, status, code, request_id, collect=True):
        with self.core._transaction() as db:
            db.execute("INSERT OR IGNORE INTO operations(request_id,project,actor,status,code,created,action) VALUES(?,?,?,?,?,?,?)", (request_id, "PLEX", "schedule", "running", "ok", self.now, "update"))
            self.core._finish(db, request_id, "PLEX", "schedule", Outcome(status, code))
        if collect:
            self.notices.collect(self.core)

    def test_persistent_queue_deduplicates_and_replaces_obsolete_failure(self):
        self.result("failed", "health_failed", "a" * 32)
        self.result("failed", "health_failed", "b" * 32)
        self.assertEqual(len(self.notices.pending()), 1)
        self.notices.close()
        self.notices = Notices(self.directory, clock=lambda: self.now)
        self.assertEqual(len(self.notices.pending()), 1)
        self.result("succeeded", "ok", "c" * 32)
        pending = self.notices.pending()
        self.assertEqual(len(pending), 1)
        self.assertTrue(pending[0][1]["recovered"])
        self.notices.sent(pending[0][0])
        self.notices.collect(self.core)
        self.assertEqual(self.notices.pending(), [])

    def test_changed_code_and_daily_repeat_create_immediate_notice(self):
        self.result("failed", "health_failed", "a" * 32)
        self.notices.sent(self.notices.pending()[0][0])
        self.result("failed", "image_missing", "b" * 32)
        self.assertEqual(self.notices.pending()[0][1]["code"], "image_missing")
        self.notices.sent(self.notices.pending()[0][0])
        self.now += 86400
        self.result("failed", "image_missing", "c" * 32)
        self.assertEqual(len(self.notices.pending()), 1)

    def test_effective_fault_survives_offline_and_success_notices_expire(self):
        self.result("failed", "health_failed", "a" * 32)
        self.now += 90000
        self.notices.collect(self.core)
        self.assertEqual(len(self.notices.pending()), 1)
        self.result("succeeded", "ok", "b" * 32)
        self.now += 90000
        self.notices.collect(self.core)
        self.assertEqual(self.notices.pending(), [])

    def test_system_gate_failure_deduplicates_and_reconciled_sends_recovery(self):
        self.notices.collect(self.core)
        self.assertEqual(self.notices.pending(), [])
        self.core._pause_all("planning_unavailable")
        self.notices.collect(self.core)
        self.core._pause_all("planning_unavailable")
        self.notices.collect(self.core)
        self.assertEqual(len(self.notices.pending()), 1)
        self.assertEqual(self.notices.pending()[0][1]["project"], "SYSTEM")
        self.assertIn("全局写操作门禁", self.notices.text(self.notices.pending()[0][1]))
        self.now += 90000
        self.assertEqual(len(self.notices.pending()), 1)
        self.core.reconcile()
        self.notices.collect(self.core)
        pending = self.notices.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0][1]["code"], "writes_resumed")
        self.assertTrue(pending[0][1]["recovered"])

    def test_offline_reconciliation_emits_only_latest_operation_result(self):
        self.result("unknown", "transport_uncertain", "a" * 32, collect=False)
        self.result("succeeded", "ok", "a" * 32, collect=False)
        self.notices.collect(self.core)
        self.assertEqual(len(self.notices.pending()), 1)
        self.assertEqual(self.notices.pending()[0][1]["code"], "ok")


class TelegramWebTests(unittest.TestCase):
    def test_settings_are_authenticated_and_missing_key_is_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            with TestClient(create_demo_app(Path(tmp))) as client:
                self.assertEqual(client.get("/telegram", follow_redirects=False).status_code, 303)
                auth = client.app.state.auth
                auth.set_password(auth.issue_code("initialize"), "admin", "test-only-password")
                data = Inputs(client.get("/login").text).fields
                data.update(name="admin", password="test-only-password")
                client.post("/login", data=data, headers={"Origin": "http://testserver"})
                page = client.get("/telegram")
                self.assertIn("telegram_key_unavailable", page.text)
                self.assertIn("disabled", page.text)
                self.assertNotIn(TOKEN, page.text)


if __name__ == "__main__":
    unittest.main()
