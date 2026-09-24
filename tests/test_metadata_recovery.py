import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from maintenance_center import metadata
from maintenance_center.core import Core, MaintenanceError, Outcome, Plan
from maintenance_center.demo import DemoGateway
from maintenance_center.notices import Notices
from maintenance_center.web import create_demo_app
from test_auth_web import Inputs


class MetadataTests(unittest.TestCase):
    def test_legacy_queued_failure_preserves_reason_without_fabricated_versions(self):
        text = Notices.text({"project": "PLEX", "action": "update", "status": "failed", "stamp": 10000,
                             "operation": "a" * 32, "code": "health_failed", "recovered": False})
        self.assertIn("原因：health_failed", text)
        self.assertNotIn("状态：成功", text)
        self.assertNotIn("恢复状态：未知", text)

    def test_metadata_allowlist_drops_secrets_paths_and_invalid_digests(self):
        result = metadata.clean("PLEX", {"current_version": "https://user:password@host/1.2", "target_version": "v1.2.3-rc1",
            "token": "a-secret", "images": [{"service": "PLEX", "current": "sha256:" + "a" * 64, "target": "/private/key"}]})
        self.assertIsNone(result["current_version"])
        self.assertEqual(result["target_version"], "v1.2.3-rc1")
        self.assertEqual(result["images"][0]["current"], "a" * 12)
        self.assertIsNone(result["images"][0]["target"])
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(metadata.recovery("token-secret"), "unknown")

    def test_configflow_preserves_both_services_and_ignores_aggregate(self):
        result = metadata.from_plan("CONFIGFLOW", {"current_image_id": "sha256:" + "e" * 64,
            "current_images": {"config-flow": "sha256:" + "a" * 64, "sub-store": "sha256:" + "b" * 64},
            "target_images": {"config-flow": "sha256:" + "c" * 64, "sub-store": "sha256:" + "d" * 64}})
        self.assertEqual([row["current"] for row in result["images"]], ["a" * 12, "b" * 12])
        self.assertEqual([row["target"] for row in result["images"]], ["c" * 12, "d" * 12])

    def test_demo_detail_and_plan_match_each_configflow_service(self):
        gateway = DemoGateway()
        current = gateway.query("CONFIGFLOW")["containers"]
        plan = gateway.plan_update("CONFIGFLOW")
        details = metadata.clean("CONFIGFLOW", plan.details)
        self.assertEqual(len(current), 2)
        for container, image in zip(current, details["images"]):
            self.assertEqual(container["name"], image["service"])
            self.assertEqual(metadata.digest(container["image_id"]), image["current"])
            self.assertEqual(container["version"], details["current_version"])


    def test_details_persist_before_apply_and_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = DemoGateway()
            core = Core(Path(tmp), gateway)
            core.reconcile()
            ref = core.prepare_manual("PLEX", "web")
            details = core.plan_view(ref, "web")["details"]
            apply = gateway.apply_update
            def verify(plan, request_id):
                row = core.db.execute("SELECT details FROM operations WHERE request_id=?", (request_id,)).fetchone()
                self.assertEqual(json.loads(row[0]), details)
                return apply(plan, request_id)
            gateway.apply_update = verify
            core.approve(ref, "web")
            core.close()
            core = Core(Path(tmp), gateway)
            try:
                row = core.db.execute("SELECT details,recovery FROM operations").fetchone()
                self.assertEqual(json.loads(row[0]), details)
                self.assertEqual(row[1], "not_required")
            finally:
                core.close()

    def test_old_database_schema_migrates_without_losing_operations(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            db = sqlite3.connect(directory / "state.sqlite3")
            db.executescript("""CREATE TABLE project_pause(project TEXT PRIMARY KEY, code TEXT NOT NULL);
                INSERT INTO project_pause VALUES('PLEX','failed');
                CREATE TABLE operations(request_id TEXT PRIMARY KEY,project TEXT NOT NULL,actor TEXT NOT NULL,
                    status TEXT NOT NULL,code TEXT NOT NULL,created REAL NOT NULL,finished REAL,
                    operation_ref TEXT,action TEXT NOT NULL DEFAULT 'update');
                INSERT INTO operations VALUES('historical','PLEX','web','failed','failed',1,2,NULL,'update');""")
            db.close()
            core = Core(directory, DemoGateway())
            try:
                self.assertEqual(core.state()["paused_projects"], {"PLEX": "failed"})
                self.assertEqual(len(core.state()["pause_refs"]["PLEX"]), 32)
                row = core.db.execute("SELECT details,recovery FROM operations").fetchone()
                self.assertEqual(tuple(row), ("{}", "unknown"))
            finally:
                core.close()

    def test_notice_omits_image_evidence_but_preserves_recovery_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            core = Core(directory, DemoGateway())
            core.reconcile()
            notices = Notices(directory)
            try:
                ref = core.prepare_manual("CONFIGFLOW", "web")
                core.approve(ref, "web")
                notices.collect(core)
                _, payload = notices.pending()[0]
                text = notices.text(payload)
                self.assertIn("1.0.0-demo", text)
                self.assertNotIn("镜像", text)
                self.assertNotIn("恢复状态", text)
                self.assertNotIn("sha256:", text)
                for i, recovery in enumerate(["rollback_failed", "current_restored"]):
                    request_id = str(i) * 32
                    with core._transaction() as db:
                        db.execute("INSERT INTO operations(request_id,project,actor,status,code,created) VALUES(?,?,?,?,?,?)", (request_id, "MEDIAVAULT3", "web", "running", "ok", core.clock()))
                        core._finish(db, request_id, "MEDIAVAULT3", "web", Outcome("failed", "postcheck_failed", recovery=recovery))
                    notices.collect(core)
                    failed = [item for _, item in notices.pending() if item["project"] == "MEDIAVAULT3"]
                    self.assertEqual([item["recovery"] for item in failed], [recovery])
                    self.assertIn(metadata.RECOVERY[recovery], notices.text(failed[0]))
                    self.assertIn("postcheck_failed", notices.text(failed[0]))
                    self.assertNotIn("状态：成功", notices.text(failed[0]))
                matching = [item for _, item in notices.pending() if item["project"] == "MEDIAVAULT3"]
                self.assertEqual(len(matching), 1)
                self.assertEqual(matching[0]["recovery"], "current_restored")
            finally:
                notices.close()
                core.close()


class RecoveryWebTests(unittest.TestCase):
    def test_audit_filter_page_and_invalid_cursor(self):
        self.failure("a" * 32)
        page = self.client.get("/audit", params={"project": "PLEX", "result": "failed"})
        self.assertEqual(page.status_code, 200)
        self.assertIn("health_failed", page.text)
        self.assertIn("时间（上海）", page.text)
        self.assertEqual(self.client.get("/audit", params={"before": str(2**63)}).status_code, 400)
        self.assertEqual(self.client.get("/audit", params={"start": "not-a-date"}).status_code, 400)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = TestClient(create_demo_app(Path(self.tmp.name)))
        self.client.__enter__()
        auth = self.client.app.state.auth
        auth.set_password(auth.issue_code("initialize"), "admin", "test-only-password")
        data = Inputs(self.client.get("/login").text).fields
        data.update(name="admin", password="test-only-password")
        self.post("/login", data)
        self.core = self.client.app.state.core

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.tmp.cleanup()

    def post(self, path, data):
        return self.client.post(path, data=data, headers={"Origin": "http://testserver"})

    def failure(self, ref):
        with self.core._transaction() as db:
            db.execute("INSERT INTO operations(request_id,project,actor,status,code,created) VALUES(?,?,?,?,?,?)", (ref, "PLEX", "web", "running", "ok", self.core.clock()))
            self.core._finish(db, ref, "PLEX", "web", Outcome("failed", "health_failed"))

    def test_resume_requires_confirmation_and_rejects_old_failure_form(self):
        self.failure("a" * 32)
        data = Inputs(self.client.get("/maintenance").text).fields
        self.assertEqual(self.post("/maintenance/resume/PLEX", data).status_code, 400)
        data["confirmed"] = "yes"
        self.assertEqual(self.post("/maintenance/resume/PLEX", data).status_code, 200)
        self.failure("b" * 32)
        self.assertEqual(self.post("/maintenance/resume/PLEX", data).status_code, 400)
        self.assertIn("PLEX", self.core.state()["paused_projects"])

    def test_unknown_special_operation_cannot_be_cleared_by_reconcile_or_resume(self):
        self.failure("b" * 32)
        with self.core._transaction() as db:
            db.execute("INSERT INTO operations(request_id,project,actor,status,code,created,operation_ref,action) VALUES(?,?,?,?,?,?,?,?)",
                       ("c" * 32, "MOVIEPILOT2", "web", "unknown", "transport_uncertain", self.core.clock(), "d" * 16, "restart"))
        page = self.client.get("/maintenance")
        self.assertIn("不能强制清除记录或重复执行", page.text)
        data = Inputs(page.text).fields
        self.post("/maintenance/reconcile", data)
        self.assertNotEqual(self.core.state()["gate"], "ready")
        data["confirmed"] = "yes"
        self.assertEqual(self.post("/maintenance/resume/PLEX", data).status_code, 400)

    def test_plan_page_shows_metadata_without_approval_secret(self):
        data = Inputs(self.client.get("/project/PLEX").text).fields
        page = self.post("/plan/PLEX/update", data)
        self.assertIn("1.0.0-demo", page.text)
        self.assertIn("2.0.0-demo", page.text)
        plan = next(iter(self.core._plans.values()))[0]
        self.assertNotIn(plan.approval, page.text)
        self.assertNotIn(plan.operation_ref, page.text)

        self.core.gateway.plan_action = lambda project, action: Plan(
            project,
            self.core.clock() + 300,
            "configflow-approval-secret",
            details={
                "current_versions": {"config-flow": "1.3.0", "sub-store": "2.39.6"},
                "target_versions": {"config-flow": "1.4.0", "sub-store": "2.40.0"},
            },
        )
        data = Inputs(self.client.get("/project/CONFIGFLOW").text).fields
        page = self.post("/plan/CONFIGFLOW/update", data)
        self.assertIn("ConfigFlow 1.3.0 / Sub-Store 2.39.6", page.text)
        self.assertIn("ConfigFlow 1.4.0 / Sub-Store 2.40.0", page.text)



if __name__ == "__main__":
    unittest.main()
