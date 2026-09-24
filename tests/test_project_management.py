import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from maintenance_center.core import Core, MaintenanceError, Outcome, PlanUnavailable
from maintenance_center.demo import DemoGateway
from maintenance_center.notices import Notices


class ProjectManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.gateway = DemoGateway()
        self.core = Core(self.directory, self.gateway)
        self.assertTrue(self.core.reconcile())
        self.core.configure(list(self.core.projects), 2, True, self.core.state()["revision"], "web")
        self.next_run = self.core.state()["next_run"]

    def tearDown(self):
        self.core.close()
        self.tmp.cleanup()

    def enroll(self, policy="auto"):
        definition = self.gateway.definition("MEDIAVAULT3")
        preview = self.core.management.preview(definition["compose_path"], definition["services"])
        return self.core.management.change("enroll", "MEDIAVAULT3", "web", self.gateway.registry_revision,
                                           token=preview["token"], name="MediaVault3", policy=policy,
                                           backup_exempt=True, backup_paths=[], health={"mode": "running"})

    def test_enrollment_runs_once_while_periodic_schedule_paused_and_preserves_due_time(self):
        self.core.configure(list(self.core.projects), 2, False, self.core.state()["revision"], "web")
        before = self.core.state()["next_run"]
        self.enroll()
        self.assertEqual(self.gateway.versions["MEDIAVAULT3"], 1)
        self.assertEqual(self.core.management.run_initial(), [("MEDIAVAULT3", "succeeded", "ok")])
        self.assertEqual(self.gateway.versions["MEDIAVAULT3"], 2)
        self.assertEqual(self.core.management.run_initial(), [])
        self.assertEqual(self.core.state()["next_run"], before)
        self.assertFalse(self.core.state()["enabled"])

    def test_busy_lock_and_hard_gate_leave_first_check_queued(self):
        self.enroll()
        self.core._execution.acquire()
        try:
            self.assertEqual(self.core.management.run_initial(), [])
        finally:
            self.core._execution.release()
        self.core._pause_all("registry_change_unknown")
        self.assertEqual(self.core.management.run_initial(), [])
        self.assertEqual(self.gateway.versions["MEDIAVAULT3"], 1)
        self.assertEqual(self.core.management.initial_checks()[0]["status"], "pending")
        self.assertTrue(self.core.reconcile())
        self.assertEqual(self.core.management.run_initial()[0][1], "succeeded")
        self.assertEqual(self.core.state()["next_run"], self.next_run)

    def test_remove_revokes_approval_and_cancels_first_check_without_changing_business(self):
        self.enroll()
        ref = self.core.prepare_manual("MEDIAVAULT3", "web")
        self.core.management.change("remove", "MEDIAVAULT3", "web", self.gateway.registry_revision)
        with self.assertRaises(MaintenanceError):
            self.core.approve(ref, "web")
        self.assertEqual(self.core.management.run_initial(), [])
        self.assertEqual(self.gateway.versions["MEDIAVAULT3"], 1)
        self.assertNotIn("MEDIAVAULT3", self.core.projects)
        self.assertIn("MEDIAVAULT3", self.core.history_projects)
        self.assertEqual(self.core.management.initial_checks()[0]["status"], "cancelled")
        self.assertEqual(self.core.state()["next_run"], self.next_run)

    def test_lost_enrollment_response_uses_receipt_without_repeating_change(self):
        original = self.gateway.request
        calls = []
        def lost(action, **kwargs):
            result = original(action, **kwargs)
            if action == "enroll":
                calls.append(action)
                raise MaintenanceError("registry_unavailable")
            return result
        with patch.object(self.gateway, "request", side_effect=lost):
            self.enroll()
        self.assertEqual(calls, ["enroll"])
        self.assertEqual(len(self.core.management.initial_checks()), 1)
        self.core.close()
        self.core = Core(self.directory, self.gateway)
        self.assertTrue(self.core.reconcile())
        self.assertEqual(self.core.management.run_initial()[0][1], "succeeded")
        self.assertEqual(self.core.state()["next_run"], self.next_run)

    def test_unknown_dispatch_survives_restart_without_second_apply(self):
        self.enroll()
        with patch.object(self.gateway, "apply_update", side_effect=TimeoutError) as apply:
            result = self.core.management.run_initial()
        self.assertEqual(apply.call_count, 1)
        self.assertEqual(result[0][1], "unknown")
        self.core.close()
        self.core = Core(self.directory, self.gateway)
        self.assertFalse(self.core.reconcile())
        with patch.object(self.gateway, "apply_update") as apply:
            self.assertEqual(self.core.management.run_initial(), [])
        apply.assert_not_called()
        self.assertEqual(self.core.state()["next_run"], self.next_run)

    def test_notify_enrollment_reports_update_without_authorizing_mutation(self):
        self.enroll("notify")
        self.assertEqual(self.core.management.run_initial(), [("MEDIAVAULT3", "succeeded", "update_available")])
        with self.assertRaisesRegex(MaintenanceError, "policy_notify_only"):
            self.core.prepare_manual("MEDIAVAULT3", "web")
        self.assertEqual(self.gateway.versions["MEDIAVAULT3"], 1)
        self.assertEqual(self.core.state()["next_run"], self.next_run)

    def test_failed_initial_execution_does_not_change_next_round(self):
        self.enroll()
        with patch.object(self.gateway, "apply_update", return_value=Outcome("failed", "update_failed", recovery="rolled_back")):
            self.assertEqual(self.core.management.run_initial(), [("MEDIAVAULT3", "failed", "update_failed")])
        self.assertEqual(self.core.state()["next_run"], self.next_run)
        self.assertEqual(self.core.management.run_initial(), [])

    def test_wakeup_failure_does_not_report_successful_registration_as_failed(self):
        self.core.management.wake = lambda: (_ for _ in ()).throw(RuntimeError("scheduler unavailable"))
        self.enroll()
        self.assertIn("MEDIAVAULT3", self.core.projects)
        self.assertEqual(self.core.management.run_initial()[0][1], "succeeded")

    def test_initial_notice_waits_for_completion_and_survives_collector_restart(self):
        self.enroll()
        notices = Notices(self.directory)
        original = self.core._apply

        def collect_between_results(*args, **kwargs):
            outcome = original(*args, **kwargs)
            notices.collect(self.core)
            self.assertEqual(notices.pending(), [])
            return outcome

        try:
            with patch.object(self.core, "_apply", side_effect=collect_between_results):
                self.core.management.run_initial()
            notices.close()
            notices = Notices(self.directory)
            notices.collect(self.core)
            pending = notices.pending()
            self.assertEqual([item["action"] for _, item in pending], ["initial_check"])
            item = pending[0][1]
            self.assertEqual(item["status"], "succeeded")
            self.assertEqual(item["details"]["current_version"], "1.0.0-demo")
            self.assertEqual(item["details"]["target_version"], "2.0.0-demo")
            notices.sent(pending[0][0])
            notices.close()
            notices = Notices(self.directory)
            notices.collect(self.core)
            self.assertEqual(notices.pending(), [])
        finally:
            notices.close()

    def test_unknown_initial_notice_is_followed_by_one_reconciled_result(self):
        self.enroll()
        notices = Notices(self.directory)
        try:
            with patch.object(self.gateway, "apply_update", side_effect=TimeoutError):
                self.core.management.run_initial()
            notices.collect(self.core)
            pending = notices.pending()
            initial = [(key, item) for key, item in pending if item["action"] == "initial_check"]
            self.assertEqual([item["status"] for _, item in initial], ["unknown"])
            self.assertNotIn("状态：成功", notices.text(initial[0][1]))
            for key, _ in pending:
                notices.sent(key)
            job = self.core.management.initial_checks()[0]
            with self.core._transaction() as db:
                self.core._finish(db, job["operation_request"], job["project"], job["actor"],
                                  Outcome("failed", "update_failed", recovery="rolled_back"))
            notices.collect(self.core)
            self.assertEqual(notices.pending(), [])
            self.core.management.reconcile_checks()
            notices.close()
            notices = Notices(self.directory)
            notices.collect(self.core)
            pending = notices.pending()
            self.assertEqual([item["action"] for _, item in pending], ["initial_check"])
            self.assertEqual(pending[0][1]["status"], "failed")
            self.assertEqual(pending[0][1]["recovery"], "rolled_back")
            notices.sent(pending[0][0])
            self.core.management.reconcile_checks()
            notices.collect(self.core)
            self.assertEqual(notices.pending(), [])
        finally:
            notices.close()

    def test_initial_check_without_dispatch_notifies_no_update_discovery_and_failure(self):
        for policy, code in (("auto", "no_update"), ("notify", "update_available"),
                             ("manual", "update_available"), ("auto", "check_failed")):
            with self.subTest(policy=policy, code=code):
                self.enroll(policy)
                notices = Notices(self.directory)
                try:
                    if code == "no_update":
                        with patch.object(self.gateway, "plan_update", return_value=None), patch.object(
                                self.gateway, "current_metadata", create=True,
                                return_value={"current_version":"1.0.0-demo"}):
                            self.core.management.run_initial()
                    elif code == "check_failed":
                        with patch.object(self.gateway, "plan_update", side_effect=MaintenanceError(code)):
                            self.core.management.run_initial()
                    else:
                        self.core.management.run_initial()
                    notices.collect(self.core)
                    pending = notices.pending()
                    self.assertEqual([item["action"] for _, item in pending], ["initial_check"])
                    self.assertEqual(pending[0][1]["code"], code)
                    self.assertEqual(pending[0][1]["status"], "failed" if code == "check_failed" else "succeeded")
                    self.assertIsNone(self.core.management.initial_checks()[0]["operation_request"])
                    if code != "check_failed":
                        self.assertEqual(pending[0][1]["details"]["current_version"], "1.0.0-demo")
                        self.assertEqual(pending[0][1]["details"]["target_version"],
                                         None if code == "no_update" else "2.0.0-demo")
                    notices.sent(pending[0][0])
                    self.core.management.run_initial()
                    notices.collect(self.core)
                    self.assertEqual(notices.pending(), [])
                    self.core.management.change("remove", "MEDIAVAULT3", "web", self.gateway.registry_revision)
                finally:
                    notices.close()

    def test_interrupted_initial_check_before_dispatch_emits_durable_failure(self):
        self.enroll()
        with self.core._transaction() as db:
            db.execute("UPDATE initial_checks SET status='running',code='checking'")
        self.core.close()
        self.core = Core(self.directory, self.gateway)
        self.core.reconcile()
        notices = Notices(self.directory)
        try:
            notices.collect(self.core)
            pending = notices.pending()
            self.assertEqual([item["action"] for _, item in pending], ["initial_check"])
            self.assertEqual(pending[0][1]["code"], "interrupted_before_dispatch")
            self.assertEqual(pending[0][1]["status"], "failed")
            notices.sent(pending[0][0])
            self.core.close()
            self.core = Core(self.directory, self.gateway)
            self.core.reconcile()
            notices.collect(self.core)
            self.assertEqual(notices.pending(), [])
        finally:
            notices.close()

    def test_restart_after_update_before_initial_completion_does_not_lose_notice(self):
        self.enroll()
        notices = Notices(self.directory)
        original = self.core._apply

        class Interrupted(BaseException):
            pass

        def interrupt_after_update(*args, **kwargs):
            original(*args, **kwargs)
            notices.collect(self.core)
            self.assertEqual(notices.pending(), [])
            raise Interrupted

        try:
            with patch.object(self.core, "_apply", side_effect=interrupt_after_update):
                with self.assertRaises(Interrupted):
                    self.core.management.run_initial()
            self.core.close()
            self.core = Core(self.directory, self.gateway)
            self.assertTrue(self.core.reconcile())
            notices.collect(self.core)
            pending = notices.pending()
            self.assertEqual([(item["action"], item["status"]) for _, item in pending],
                             [("initial_check", "succeeded")])
            notices.sent(pending[0][0])
            self.core.reconcile()
            notices.collect(self.core)
            self.assertEqual(notices.pending(), [])
        finally:
            notices.close()

    def test_preparatory_accept_remains_suppressed_after_link_moves_and_restart(self):
        self.enroll()
        self.gateway.catalog["MEDIAVAULT3"]["adapter"] = "mv3"
        notices = Notices(self.directory)
        plan_update = self.gateway.plan_update
        validate_action = self.gateway._action
        apply = self.core._apply
        planned = False

        def allow_accept(project, action):
            if action != "accept":
                validate_action(project, action)

        def plan_after_accept(project):
            nonlocal planned, notices
            if not planned:
                planned = True
                raise PlanUnavailable("rollback_slot_occupied")
            # Acceptance completed, but its operation is no longer the job's
            # current link. A fresh collector must still recognize ownership.
            self.assertIsNone(self.core.management.initial_checks()[0]["operation_request"])
            notices.close()
            notices = Notices(self.directory)
            notices.collect(self.core)
            self.assertEqual(notices.pending(), [])
            return plan_update(project)

        def collect_after_update(plan, *args, **kwargs):
            outcome = apply(plan, *args, **kwargs)
            if plan.action == "update":
                notices.collect(self.core)
                self.assertEqual(notices.pending(), [])
            return outcome

        try:
            with patch.object(self.gateway, "_action", side_effect=allow_accept), \
                    patch.object(self.gateway, "plan_update", side_effect=plan_after_accept), \
                    patch.object(self.core, "_apply", side_effect=collect_after_update):
                self.assertEqual(self.core.management.run_initial(), [("MEDIAVAULT3", "succeeded", "ok")])
            self.core.close()
            self.core = Core(self.directory, self.gateway)
            self.assertTrue(self.core.reconcile())
            notices.collect(self.core)
            pending = notices.pending()
            self.assertEqual([(item["action"], item["status"]) for _, item in pending],
                             [("initial_check", "succeeded")])
            self.assertEqual(pending[0][1]["details"]["target_version"], "2.0.0-demo")
            notices.sent(pending[0][0])
            notices.collect(self.core)
            self.assertEqual(notices.pending(), [])
        finally:
            notices.close()

    def test_pending_unknown_is_replaced_only_after_initial_terminal_audit(self):
        self.enroll()
        notices = Notices(self.directory)
        try:
            with patch.object(self.gateway, "apply_update", side_effect=TimeoutError):
                self.core.management.run_initial()
            notices.collect(self.core)
            job = self.core.management.initial_checks()[0]
            with self.core._transaction() as db:
                self.core._finish(db, job["operation_request"], job["project"], job["actor"],
                                  Outcome("succeeded", "ok", recovery="not_required"))
            notices.collect(self.core)
            initial = [item for _, item in notices.pending() if item["action"] == "initial_check"]
            self.assertEqual([item["status"] for item in initial], ["unknown"])
            self.assertFalse(any(item["action"] == "update" for _, item in notices.pending()))
            self.core.management.reconcile_checks()
            notices.close()
            notices = Notices(self.directory)
            notices.collect(self.core)
            initial = [item for _, item in notices.pending() if item["action"] == "initial_check"]
            self.assertEqual([item["status"] for item in initial], ["succeeded"])
            self.assertEqual(initial[0]["details"]["target_version"], "2.0.0-demo")
            notices.collect(self.core)
            self.assertEqual([item for _, item in notices.pending() if item["action"] == "initial_check"], initial)
        finally:
            notices.close()
