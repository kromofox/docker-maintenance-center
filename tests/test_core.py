import json
import tempfile
import unittest
from pathlib import Path

from maintenance_center.core import Core, MaintenanceError, Outcome, Plan, PlanUnavailable, PROJECTS, RemoteState


class FakeGateway:
    def __init__(self, clock):
        self.clock = clock
        self.updates = set(PROJECTS)
        self.outcomes = {}
        self.calls = []
        self.remote = {}
        self.on_plan = None
        self.plan_failure = None

    def plan_update(self, project):
        if self.on_plan:
            self.on_plan(project)
        if project == self.plan_failure:
            raise TimeoutError("secret must not be logged")
        return Plan(project, self.clock() + 300, "approval-secret-value") if project in self.updates else None

    def apply_update(self, plan, request_id):
        self.calls.append((plan.project, request_id))
        result = self.outcomes.get(plan.project, Outcome("succeeded", "ok"))
        if isinstance(result, Exception):
            raise result
        self.remote[plan.project] = RemoteState(result.status, request_id, result.code)
        return result

    def query(self, project, action="health", tail=200):
        return {"project": project, "overall": "healthy", "containers": []}

    def operation_status(self, project):
        return self.remote.get(project, RemoteState("idle"))


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.now = 10000.0
        self.gateway = FakeGateway(lambda: self.now)
        self.core = Core(self.directory, self.gateway, lambda: self.now)
        self.assertTrue(self.core.reconcile())

    def tearDown(self):
        self.core.close()
        self.tmp.cleanup()

    def schedule(self, targets):
        return self.core.configure(targets, 1, True, self.core.state()["revision"], "telegram")

    def restart(self):
        self.core.close()
        self.core = Core(self.directory, self.gateway, lambda: self.now)

    def test_schedule_is_continuous_authorization_in_fixed_order(self):
        self.schedule(list(reversed(PROJECTS)))
        self.assertEqual(self.core.run_due(), [])
        self.now += 3600
        result = self.core.run_due()
        self.assertEqual([p for p, _ in result], list(PROJECTS))
        self.assertEqual(len(self.gateway.calls), 4)
        self.assertEqual(self.core.run_due(), [])

    def test_retired_unknown_operation_still_fails_closed_without_authorizing_recovery(self):
        request_id = "f" * 32
        with self.core._transaction() as db:
            db.execute("""INSERT INTO operations(request_id,project,actor,status,code,created)
                          VALUES(?,?,?,?,?,?)""",
                       (request_id, "MEDIAVAULT3", "web", "unknown", "transport_uncertain", self.now))
            self.core._audit(db, "web", "update_result", "transport_uncertain", "MEDIAVAULT3", request_id, "unknown")
        self.assertFalse(self.core.reconcile())
        self.assertEqual(self.core.audit_page(project="MEDIAVAULT3")["rows"][0]["request_id"], request_id)
        self.assertEqual(self.core.db.execute("SELECT status FROM operations WHERE request_id=?", (request_id,)).fetchone()[0], "unknown")
        with self.assertRaisesRegex(MaintenanceError, "project_not_allowed"):
            self.core.prepare_manual("MEDIAVAULT3", "web")
        with self.assertRaisesRegex(MaintenanceError, "project_not_allowed"):
            self.core.resume_project("MEDIAVAULT3", "web")

    def test_manual_check_does_not_update_and_approval_cannot_replay(self):
        ref = self.core.prepare_manual("PLEX", "telegram")
        self.assertEqual(self.gateway.calls, [])
        self.assertFalse(self.core.state()["enabled"])
        self.core.approve(ref, "web")
        with self.assertRaisesRegex(MaintenanceError, "consumed"):
            self.core.approve(ref, "telegram")
        self.assertEqual(len(self.gateway.calls), 1)

    def test_manual_check_recovers_transient_planning_gate(self):
        self.core._pause_all("planning_unavailable")
        ref = self.core.prepare_manual("PLEX", "telegram")
        self.assertIsNotNone(ref)
        self.assertEqual(self.core.state()["gate"], "ready")
    def test_reconcile_ignores_status_failure_for_idle_projects(self):
        self.core._pause_all("planning_unavailable")

        def operation_status(_project):
            raise TimeoutError("idle project status must not be queried")

        self.gateway.operation_status = operation_status
        self.assertTrue(self.core.reconcile())
        self.assertEqual(self.core.state()["gate"], "ready")


    def test_manual_plan_failure_does_not_strand_checks(self):
        self.gateway.plan_failure = "PLEX"
        with self.assertRaisesRegex(MaintenanceError, "planning_unavailable"):
            self.core.prepare_manual("PLEX", "telegram")
        self.assertEqual(self.core.state()["gate"], "ready")
        self.gateway.plan_failure = None
        self.assertIsNotNone(self.core.prepare_manual("PLEX", "telegram"))

    def test_manual_plan_refusal_is_audited_without_stranding_gate(self):
        self.gateway.plan_update = lambda project: (_ for _ in ()).throw(PlanUnavailable("plan_rejected"))
        with self.assertRaisesRegex(PlanUnavailable, "plan_rejected"):
            self.core.prepare_manual("PLEX", "telegram")
        event = self.core.db.execute(
            "SELECT actor,action,project,code,result FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(tuple(event), ("telegram", "project_checked", "PLEX", "request_rejected", "failed"))
        self.assertEqual(self.core.state()["gate"], "ready")

    def test_unscheduled_project_never_auto_updates(self):
        self.schedule(["EMBY"])
        self.now += 3600
        self.core.run_due()
        self.assertEqual([p for p, _ in self.gateway.calls], ["EMBY"])

    def test_known_failure_retries_once_then_requires_resume(self):
        self.gateway.outcomes["EMBY"] = Outcome("failed", "update_failed")
        self.schedule(["EMBY", "PLEX"])
        self.now += 3600
        self.core.run_due()
        self.assertEqual([p for p, _ in self.gateway.calls], ["EMBY", "PLEX"])
        self.assertEqual(self.core.state()["paused_projects"], {"EMBY": "update_failed"})
        self.now += 3600
        self.core.run_due()
        self.assertEqual([p for p, _ in self.gateway.calls], ["EMBY", "PLEX", "EMBY", "PLEX"])
        self.now += 3600
        self.core.run_due()
        self.assertEqual([p for p, _ in self.gateway.calls].count("EMBY"), 2)
        self.core.resume_project("EMBY", "telegram")
        self.assertEqual(self.core.state()["paused_projects"], {})

    def fail_plex(self):
        self.gateway.outcomes["PLEX"] = Outcome("failed", "startup_probe_failed")
        self.schedule(["PLEX"])
        self.now += 3600
        self.core.run_due()

    def test_retry_success_clears_pause(self):
        self.fail_plex()
        self.gateway.outcomes["PLEX"] = Outcome("succeeded", "ok")
        self.now += 3600
        self.core.run_due()
        self.assertNotIn("PLEX", self.core.state()["paused_projects"])
        self.assertEqual(len(self.gateway.calls), 2)

    def test_healthy_no_update_clears_pause_without_write(self):
        self.fail_plex()
        self.gateway.updates.clear()
        self.now += 3600
        self.core.run_due()
        self.assertNotIn("PLEX", self.core.state()["paused_projects"])
        self.assertEqual(len(self.gateway.calls), 1)

    def test_unhealthy_retry_never_writes_and_notifies_once(self):
        from maintenance_center.notices import Notices
        self.fail_plex()
        self.gateway.query = lambda *a: {"project": "PLEX", "overall": "unhealthy"}
        self.now += 3600
        self.core.run_due()
        self.now += 3600
        self.core.run_due()
        self.assertEqual(len(self.gateway.calls), 1)
        notices = Notices(self.directory, lambda: self.now)
        try:
            notices.collect(self.core)
            messages = [item for _, item in notices.pending() if item["action"] == "retry"]
            self.assertEqual(len(messages), 1)
            self.assertIn("/resume PLEX", notices.text(messages[0]))
        finally:
            notices.close()

    def test_retry_budget_survives_restart(self):
        self.fail_plex()
        self.now += 3600
        self.core.run_due()
        self.restart()
        self.assertTrue(self.core.reconcile())
        self.now += 3600
        self.core.run_due()
        self.assertEqual(len(self.gateway.calls), 2)

    def test_retry_unknown_preserves_global_gate(self):
        self.fail_plex()
        self.gateway.outcomes["PLEX"] = TimeoutError()
        self.now += 3600
        self.core.run_due()
        self.assertNotEqual(self.core.state()["gate"], "ready")
        self.now += 3600
        self.core.run_due()
        self.assertEqual(len(self.gateway.calls), 2)

    def test_retry_revocation_during_health_blocks_write(self):
        self.fail_plex()
        def query(*args):
            self.core.configure([], 1, False, self.core.state()["revision"], "web")
            return {"project": "PLEX", "overall": "healthy"}
        self.gateway.query = query
        self.now += 3600
        self.core.run_due()
        self.assertEqual(len(self.gateway.calls), 1)

    def test_retry_crash_is_not_replayed_and_is_reported(self):
        self.fail_plex()
        def crash(*a):
            raise SystemExit()
        self.gateway.query = crash
        self.now += 3600
        with self.assertRaises(SystemExit):
            self.core.run_due()
        self.restart()
        self.assertTrue(self.core.reconcile())
        report = self.core.failure_report("PLEX")
        self.assertEqual(report["retry_events"][0]["code"], "retry_interrupted")
        self.now += 3600
        self.core.run_due()
        self.assertEqual(len(self.gateway.calls), 1)

    def test_resume_removes_unsent_retry_failure(self):
        from maintenance_center.notices import Notices
        self.fail_plex()
        self.now += 3600
        self.core.run_due()
        notices = Notices(self.directory, lambda: self.now)
        try:
            notices.collect(self.core)
            self.assertTrue(any(x[1]["action"] == "retry" for x in notices.pending()))
            self.core.resume_project("PLEX", "telegram")
            notices.collect(self.core)
            self.assertFalse(any(x[1]["action"] == "retry" for x in notices.pending()))
        finally:
            notices.close()

    def test_round_summary_includes_only_successes_and_failures(self):
        from maintenance_center.notices import Notices
        self.gateway.updates = {"MOVIEPILOT2", "PLEX"}
        self.gateway.outcomes["MOVIEPILOT2"] = Outcome("failed", "plan_stale", recovery="not_required")
        self.gateway.outcomes["PLEX"] = Outcome("succeeded", "ok")
        self.gateway.current_metadata = lambda p: {"current_version": "1.2.3"}
        self.schedule(["MOVIEPILOT2", "EMBY", "PLEX", "CONFIGFLOW"])
        self.now += 3600
        self.core.run_due()
        notices = Notices(self.directory, lambda: self.now)
        try:
            notices.collect(self.core)
            reports = [x for _,x in notices.pending() if x["action"] == "summary"]
            self.assertEqual(len(reports), 1)
            self.assertEqual([x["project"] for x in reports[0]["items"]], ["MOVIEPILOT2", "PLEX"])
            text = notices.text(reports[0])
            self.assertNotIn("EMBY", text)
            self.assertNotIn("CONFIGFLOW", text)
            self.assertIn("未执行更新，无需恢复", text)
            notices.collect(self.core)
            self.assertEqual(sum(item["action"] == "summary" for _, item in notices.pending()), 1)
        finally:
            notices.close()

    def test_round_summary_unknown_marks_remaining_unchecked(self):
        self.gateway.outcomes["EMBY"] = TimeoutError()
        self.schedule(["EMBY", "PLEX"])
        self.now += 3600
        self.core.run_due()
        import json
        report = json.loads(self.core.db.execute("SELECT payload FROM schedule_reports").fetchone()[0])
        self.assertEqual([r["status"] for r in report], ["unknown", "not_checked"])
        self.assertEqual(len(self.gateway.calls), 1)

    def test_quiet_no_update_round_sends_no_summary(self):
        from maintenance_center.notices import Notices
        self.gateway.updates.clear()
        self.schedule(["MOVIEPILOT2", "EMBY", "PLEX", "CONFIGFLOW"])
        self.now += 3600
        self.core.run_due()
        notices = Notices(self.directory, lambda: self.now)
        try:
            notices.collect(self.core)
            self.assertEqual(notices.pending(), [])
            self.gateway.updates.add("EMBY")
            self.now += 3600
            self.core.run_due()
            notices.collect(self.core)
            self.assertEqual([x["action"] for _, x in notices.pending()], ["summary"])
        finally:
            notices.close()

    def test_plan_check_failure_continues_round_without_system_notice(self):
        from maintenance_center.notices import Notices
        class LocalPlanFailure(Exception):
            pass
        self.gateway.updates.clear()
        original = self.gateway.plan_update
        def fail_mp2(project):
            if project == "MOVIEPILOT2":
                raise LocalPlanFailure("project-local planning error")
            return original(project)
        self.gateway.plan_update = fail_mp2
        self.schedule(["MOVIEPILOT2", "EMBY", "PLEX", "CONFIGFLOW"])
        self.now += 3600
        self.core.run_due()
        self.assertEqual(self.core.state()["gate"], "ready")
        report = json.loads(self.core.db.execute("SELECT payload FROM schedule_reports").fetchone()[0])
        self.assertEqual([r["status"] for r in report], ["check_failed", "no_update", "no_update", "no_update"])
        notices = Notices(self.directory, lambda: self.now)
        try:
            notices.collect(self.core)
            self.assertEqual([x["action"] for _, x in notices.pending()], ["summary"])
            text = notices.text(notices.pending()[0][1])
            self.assertIn("MoviePilot2：检查失败（planning_unavailable）", text)
            self.assertNotIn("PLEX：当前版本号", text)
        finally:
            notices.close()

    def test_round_report_restart_preserves_partial_and_paused_projects(self):
        import json
        self.fail_plex()
        with self.core._transaction() as db:
            db.execute("UPDATE project_pause SET retry_used=1")
        self.now += 3600
        self.core.run_due()
        self.restart()
        self.assertTrue(self.core.reconcile())
        rows = self.core.db.execute("SELECT payload FROM schedule_reports ORDER BY id DESC").fetchall()
        self.assertEqual(json.loads(rows[0][0])[0]["status"], "paused")

    def test_schedule_notice_waits_for_summary_and_suppresses_success_details(self):
        from maintenance_center.notices import Notices
        self.schedule(["MOVIEPILOT2", "EMBY"])
        self.gateway.updates = {"MOVIEPILOT2"}
        original = self.gateway.plan_update
        notices = Notices(self.directory, lambda: self.now)
        def plan(project):
            if project == "EMBY":
                notices.collect(self.core)
                self.assertEqual(notices.pending(), [])
            result = original(project)
            if result:
                return Plan(project, result.expires_at, result.approval, details={"current_version":"3.6.6","target_version":"3.6.7"})
            return result
        self.gateway.plan_update = plan
        try:
            self.now += 3600
            self.core.run_due()
            notices.collect(self.core)
            payloads = [x for _,x in notices.pending()]
            self.assertEqual([x["action"] for x in payloads], ["summary"])
        finally:
            notices.close()

    def test_failed_schedule_sends_summary_before_failure_detail(self):
        from maintenance_center.notices import Notices
        self.schedule(["MOVIEPILOT2", "EMBY"])
        self.gateway.updates = {"MOVIEPILOT2"}
        self.gateway.outcomes["MOVIEPILOT2"] = Outcome("failed", "plan_stale", recovery="not_required")
        notices = Notices(self.directory, lambda: self.now)
        def on_plan(project):
            if project == "EMBY":
                notices.collect(self.core)
                self.assertEqual(notices.pending(), [])
        self.gateway.on_plan = on_plan
        try:
            self.now += 3600
            self.core.run_due()
            notices.collect(self.core)
            self.assertEqual([x["action"] for _,x in notices.pending()], ["summary", "update"])
            notices.close()
            notices = Notices(self.directory, lambda: self.now)
            notices.collect(self.core)
            self.assertEqual([x["action"] for _,x in notices.pending()], ["summary", "update"])
        finally:
            notices.close()

    def test_offline_retry_success_removes_old_details_but_keeps_round_history(self):
        from maintenance_center.notices import Notices
        self.fail_plex()
        notices = Notices(self.directory, lambda: self.now)
        try:
            notices.collect(self.core)
            self.assertEqual([x["action"] for _,x in notices.pending()], ["summary", "update"])
            self.gateway.outcomes["PLEX"] = Outcome("succeeded", "ok")
            self.now += 3600
            self.core.run_due()
            notices.collect(self.core)
            self.assertTrue(all(x["action"] == "summary" for _,x in notices.pending()))
            self.now += 86401
            notices.collect(self.core)
            self.assertTrue(all(x["action"] == "summary" for _,x in notices.pending()))
        finally:
            notices.close()

    def test_failed_round_summary_survives_offline_with_details(self):
        from maintenance_center.notices import Notices
        self.fail_plex()
        notices = Notices(self.directory, lambda: self.now)
        try:
            notices.collect(self.core)
            self.now += 86401
            notices.collect(self.core)
            self.assertEqual([x["action"] for _,x in notices.pending()], ["summary", "update"])
        finally:
            notices.close()

    def test_success_summary_persists_dual_service_versions_without_registry(self):
        from maintenance_center.notices import Notices
        old_images = {"config-flow": "sha256:" + "1" * 64, "sub-store": "sha256:" + "2" * 64}
        new_images = {"config-flow": old_images["config-flow"], "sub-store": "sha256:" + "3" * 64}
        installed = {
            "images": old_images,
            "versions": {"config-flow": "1.3.0", "sub-store": "2.38.4"},
        }
        original_apply = self.gateway.apply_update

        def plan_update(project):
            if project != "CONFIGFLOW":
                return None
            details = {"images": [
                {"service": service, "current": old_images[service], "target": new_images[service]}
                for service in ("config-flow", "sub-store")
            ]}
            image_ids = {
                service: {"current": old_images[service], "target": new_images[service]}
                for service in ("config-flow", "sub-store")
            }
            return Plan(project, self.now + 300, "approval-secret-value", details=details, image_ids=image_ids)

        def apply_update(plan, request_id):
            result = original_apply(plan, request_id)
            installed["images"] = new_images
            installed["versions"] = {"config-flow": "1.3.0", "sub-store": "2.39.6"}
            return result

        self.gateway.plan_update = plan_update
        self.gateway.apply_update = apply_update
        self.gateway.current_metadata = lambda project: {
            "current_images": installed["images"],
            "current_versions": installed["versions"],
            "current_version": None,
        }
        self.schedule(["CONFIGFLOW"])
        self.now += 3600
        self.core.run_due()
        notices = Notices(self.directory, lambda: self.now)
        try:
            notices.collect(self.core)
            summaries = [item for _, item in notices.pending() if item["action"] == "summary"]
            self.assertEqual(len(summaries), 1)
            details = json.loads(self.core.db.execute(
                "SELECT details FROM operations WHERE project='CONFIGFLOW'"
            ).fetchone()[0])
            self.assertEqual(details["current_versions"], {"config-flow": "1.3.0", "sub-store": "2.38.4"})
            self.assertEqual(details["target_versions"], {"config-flow": "1.3.0", "sub-store": "2.39.6"})
            self.assertNotIn("sha256:" + "1" * 64, json.dumps(details))
        finally:
            notices.close()

    def test_post_version_failure_keeps_success_and_safe_unknown(self):
        from maintenance_center.notices import Notices
        old_image, new_image = "sha256:" + "4" * 64, "sha256:" + "5" * 64
        plan = Plan(
            "EMBY", self.now + 3900, "approval-secret-value",
            details={"images": [{"service": "EMBY", "current": old_image, "target": new_image}]},
            image_ids={"EMBY": {"current": old_image, "target": new_image}},
        )
        original_apply = self.gateway.apply_update
        reads = 0

        def current_metadata(project):
            nonlocal reads
            reads += 1
            if reads > 1:
                raise TimeoutError("private remote detail")
            return {
                "current_images": {"EMBY": old_image},
                "current_versions": {"EMBY": "4.9.5.0"},
                "current_version": "4.9.5.0",
            }

        self.gateway.plan_update = lambda project: plan if project == "EMBY" else None
        self.gateway.current_metadata = current_metadata
        self.gateway.apply_update = original_apply
        self.schedule(["EMBY"])
        self.now += 3600
        result = self.core.run_due()
        self.assertEqual(result[0][1].status, "succeeded")
        self.assertEqual(self.core.state()["gate"], "ready")
        notices = Notices(self.directory, lambda: self.now)
        try:
            notices.collect(self.core)
            summary = next(item for _, item in notices.pending() if item["action"] == "summary")
            details = json.loads(self.core.db.execute(
                "SELECT details FROM operations WHERE project='EMBY'"
            ).fetchone()[0])
            self.assertEqual(details["version_observation"], {"before": "ok", "after": "read_failed"})
            self.assertNotIn("private remote detail", json.dumps(details))
        finally:
            notices.close()

    def test_plan_version_wins_only_after_full_image_identity_match(self):
        image = "sha256:" + "a" * 64
        plan = Plan("EMBY", self.now + 300, "approval",
                    details={"current_version":"3.8.2","target_version":"3.8.3"},
                    image_ids={"mediavault":{"current":image,"target":image}})
        observed = {"current_images":{"mediavault":image},
                    "current_versions":{"mediavault":"24.04"},"current_version":"24.04"}
        self.gateway.current_metadata = lambda project: observed
        self.assertEqual(self.core._version_snapshot(plan, "current"), ({"mediavault":"3.8.2"}, "3.8.2", "ok"))
        self.assertEqual(self.core._version_snapshot(plan, "target"), ({"mediavault":"3.8.3"}, "3.8.3", "ok"))
        observed["current_images"]["mediavault"] = "sha256:" + "b" * 64
        self.assertEqual(self.core._version_snapshot(plan, "target")[1:], (None, "image_mismatch"))
        self.gateway.current_metadata = lambda project: (_ for _ in ()).throw(OSError())
        self.assertEqual(self.core._version_snapshot(plan, "target")[1:], (None, "read_failed"))

    def test_snapshot_rejects_matching_malformed_image_identity(self):
        invalid = "sha256:" + "a" * 12
        plan = Plan(
            "EMBY", self.now + 3900, "approval-secret-value",
            image_ids={"EMBY": {"current": invalid, "target": invalid}},
        )
        self.gateway.current_metadata = lambda project: {
            "current_images": {"EMBY": invalid},
            "current_versions": {"EMBY": "4.9.5.0"},
            "current_version": "4.9.5.0",
        }
        versions, version, status = self.core._version_snapshot(plan, "current")
        self.assertEqual(status, "image_mismatch")
        self.assertIsNone(version)
        self.assertEqual(versions, {"EMBY": None})


    def test_unknown_write_stops_cycle_and_requires_matching_result(self):
        self.gateway.outcomes["EMBY"] = TimeoutError("Bearer secret-test")
        self.schedule(["EMBY", "PLEX"])
        self.now += 3600
        self.core.run_due()
        self.assertNotEqual(self.core.state()["gate"], "ready")
        self.assertEqual(len(self.gateway.calls), 1)
        self.gateway.remote["EMBY"] = RemoteState("succeeded", "some-old-operation")
        self.assertFalse(self.core.reconcile())
        request_id = self.gateway.calls[0][1]
        self.gateway.remote["EMBY"] = RemoteState("succeeded", request_id)
        self.assertTrue(self.core.reconcile())
        self.assertEqual(len(self.gateway.calls), 1)
        self.assertNotIn("secret-test", str(list(self.core.db.execute("SELECT * FROM audit"))))

    def test_plan_transport_failure_stops_all_writes(self):
        self.schedule(["EMBY", "PLEX"])
        self.gateway.plan_failure = "EMBY"
        self.now += 3600
        self.core.run_due()
        self.assertEqual(self.gateway.calls, [])
        self.assertNotEqual(self.core.state()["gate"], "ready")
        self.gateway.plan_failure = None
        self.now += 3600
        self.core.run_due()
        self.assertEqual(self.core.state()["gate"], "ready")
        self.assertEqual([p for p, _ in self.gateway.calls], ["EMBY", "PLEX"])

    def test_plan_local_failure_continues_round_and_auto_recovers_gate(self):
        class LocalPlanFailure(Exception):
            pass
        self.schedule(["EMBY", "PLEX"])
        due = self.core.state()["next_run"]
        def fail_emby(project):
            if project == "EMBY":
                self.now += 120
                raise LocalPlanFailure("project-local planning error")
            return None
        self.gateway.plan_update = fail_emby
        self.now = due
        self.core.run_due()
        self.assertEqual(self.core.state()["gate"], "ready")
        report = json.loads(self.core.db.execute("SELECT payload FROM schedule_reports").fetchone()[0])
        self.assertEqual([r["status"] for r in report], ["check_failed", "no_update"])
        self.assertEqual(self.core.state()["next_run"], due + 3600)

    def test_final_project_plan_failure_auto_recovers_gate(self):
        class LocalPlanFailure(Exception):
            pass

        self.schedule(["EMBY", "PLEX"])

        def fail_plex(project):
            if project == "PLEX":
                raise LocalPlanFailure("final project planning error")
            return None

        self.gateway.plan_update = fail_plex
        self.now += 3600
        self.core.run_due()
        self.assertEqual(self.core.state()["gate"], "ready")
        report = json.loads(self.core.db.execute(
            "SELECT payload FROM schedule_reports ORDER BY id DESC LIMIT 1"
        ).fetchone()[0])
        self.assertEqual([row["status"] for row in report], ["no_update", "check_failed"])


    def test_known_shared_gateway_failure_also_stops_all(self):
        self.schedule(["EMBY", "PLEX"])
        self.gateway.outcomes["EMBY"] = Outcome("failed", "shared_storage_failed", "common")
        self.now += 3600
        self.core.run_due()
        self.assertEqual([p for p, _ in self.gateway.calls], ["EMBY"])
        self.assertNotEqual(self.core.state()["gate"], "ready")

    def test_malformed_result_is_uncertain_and_not_success(self):
        ref = self.core.prepare_manual("PLEX", "web")
        self.gateway.apply_update = lambda *_: {"ok": True}
        result = self.core.approve(ref, "web")
        self.assertEqual(result.status, "unknown")
        self.assertNotEqual(self.core.state()["gate"], "ready")

    def test_revoke_during_plan_prevents_dispatch(self):
        self.schedule(["EMBY"])
        def revoke(_):
            self.core.configure([], 1, False, self.core.state()["revision"], "web")
        self.gateway.on_plan = revoke
        self.now += 3600
        self.core.run_due()
        self.assertEqual(self.gateway.calls, [])

    def test_cross_channel_stale_schedule_and_approval(self):
        ref = self.core.prepare_manual("PLEX", "telegram")
        self.schedule(["PLEX"])
        with self.assertRaisesRegex(MaintenanceError, "stale_schedule"):
            self.core.configure(["EMBY"], 2, True, 0, "web")
        with self.assertRaisesRegex(MaintenanceError, "consumed"):
            self.core.approve(ref, "telegram")
        self.assertEqual(self.gateway.calls, [])

    def test_restart_invalidates_plans_but_preserves_due_time(self):
        self.schedule(["PLEX"])
        ref = self.core.prepare_manual("PLEX", "telegram")
        due = self.core.state()["next_run"]
        self.now += 100000
        self.restart()
        self.assertEqual(self.core.run_due(), [])
        self.assertTrue(self.core.reconcile())
        with self.assertRaisesRegex(MaintenanceError, "consumed"):
            self.core.approve(ref, "web")
        self.assertEqual(self.core.state()["next_run"], due)
        result = self.core.run_due()
        self.assertEqual([p for p, _ in result], ["PLEX"])
        self.assertEqual(self.core.state()["next_run"], self.now + 3600)
        self.assertEqual(self.core.run_due(), [])

    def test_unknown_operation_survives_restart(self):
        ref = self.core.prepare_manual("PLEX", "web")
        self.gateway.outcomes["PLEX"] = TimeoutError()
        self.core.approve(ref, "web")
        self.restart()
        self.assertFalse(self.core.reconcile())
        with self.assertRaisesRegex(MaintenanceError, "writes_paused"):
            self.core.prepare_manual("EMBY", "web")
        self.assertEqual(len(self.gateway.calls), 1)

    def test_whitelist_and_interval_validation(self):
        for project in ("NADEX", "CODEX", "anything", "PLEX;whoami"):
            with self.assertRaises(MaintenanceError):
                self.core.prepare_manual(project, "web")
        for hours in (0, 721, True, 1.5, "1"):
            with self.assertRaises(MaintenanceError):
                self.core.configure(["PLEX"], hours, True, 0, "web")
        self.assertEqual(self.gateway.calls, [])

    def test_no_update_is_silent_and_no_secret_persisted(self):
        self.gateway.updates.clear()
        self.schedule(["PLEX"])
        self.now += 3600
        self.assertEqual(self.core.run_due(), [])
        self.gateway.updates.add("PLEX")
        self.core.prepare_manual("PLEX", "web")
        self.assertNotIn(b"approval-secret-value", (self.directory / "state.sqlite3").read_bytes())

    def test_second_process_controller_is_rejected(self):
        with self.assertRaisesRegex(MaintenanceError, "controller_already_running"):
            Core(self.directory, self.gateway)

    def test_expired_plan_cannot_dispatch(self):
        ref = self.core.prepare_manual("PLEX", "web")
        self.now += 301
        with self.assertRaisesRegex(MaintenanceError, "expiry"):
            self.core.approve(ref, "web")
        self.assertEqual(self.gateway.calls, [])


if __name__ == "__main__":
    unittest.main()
