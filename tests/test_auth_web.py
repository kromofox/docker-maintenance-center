import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from maintenance_center.auth import Auth
from maintenance_center.core import MaintenanceError
from maintenance_center.web import create_demo_app


class Inputs(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.fields = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("type") == "hidden":
            self.fields[values["name"]] = values.get("value", "")


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = 10000
        self.auth = Auth(Path(self.tmp.name), clock=lambda: self.now)

    def tearDown(self):
        self.auth.close()
        self.tmp.cleanup()

    def initialize(self):
        code = self.auth.issue_code("initialize")
        self.auth.set_password(code, "admin", "test-only-password")
        return code

    def test_initialization_code_is_once_only_and_not_stored_clear(self):
        code = self.initialize()
        with self.assertRaises(MaintenanceError):
            self.auth.set_password(code, "other", "other-test-password")
        raw = (Path(self.tmp.name) / "auth.sqlite3").read_bytes()
        self.assertNotIn(code.encode(), raw)
        self.assertNotIn(b"test-only-password", raw)

    def test_expired_code_is_rejected(self):
        code = self.auth.issue_code("initialize")
        self.now += 600
        with self.assertRaises(MaintenanceError):
            self.auth.set_password(code, "admin", "test-only-password")

    def test_failures_are_persisted_and_rate_limited(self):
        self.initialize()
        for _ in range(5):
            with self.assertRaisesRegex(MaintenanceError, "login_failed"):
                self.auth.login("不存在", "wrong", "test-ip")
        with self.assertRaisesRegex(MaintenanceError, "login_limited"):
            self.auth.login("admin", "test-only-password", "test-ip")
        self.now += 301
        self.assertTrue(self.auth.check(self.auth.login("admin", "test-only-password", "test-ip")))

    def test_session_idle_expiry_logout_and_recovery(self):
        self.initialize()
        token = self.auth.login("admin", "test-only-password", "test-ip")
        self.assertTrue(self.auth.check(token))
        self.now += 1800
        self.assertFalse(self.auth.check(token))
        token = self.auth.login("admin", "test-only-password", "test-ip")
        code = self.auth.issue_code("recover")
        self.auth.set_password(code, "admin", "replacement-test-password", "recover")
        self.assertFalse(self.auth.check(token))
        token = self.auth.login("admin", "replacement-test-password", "test-ip")
        self.auth.logout(token)
        self.assertFalse(self.auth.check(token))


class DemoWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.client = TestClient(create_demo_app(Path(self.tmp.name)))
        self.client.__enter__()
        auth = self.client.app.state.auth
        auth.set_password(auth.issue_code("initialize"), "admin", "test-only-password")
        fields = Inputs(self.client.get("/login").text).fields
        fields.update(name="admin", password="test-only-password")
        self.post("/login", fields)

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.tmp.cleanup()

    def post(self, path, data):
        return self.client.post(path, data=data, headers={"Origin": "http://testserver"})

    def test_removed_project_is_history_only_not_a_live_target(self):
        core = self.client.app.state.core
        request_id = "d" * 32
        with core._transaction() as db:
            db.execute("""INSERT INTO operations(request_id,project,actor,status,code,created,action,recovery)
                          VALUES(?,?,?,?,?,?,?,?)""",
                       (request_id, "MEDIAVAULT3", "web", "failed", "postcheck_failed",
                        core.clock(), "update", "rolled_back"))
            core._audit(db, "web", "update_result", "postcheck_failed", "MEDIAVAULT3", request_id, "failed")
        overview = self.client.get("/")
        self.assertIn("4 个白名单项目", overview.text)
        self.assertNotIn("MEDIAVAULT3", overview.text)
        self.assertNotIn("MEDIAVAULT3", self.client.get("/schedule").text)
        fields = Inputs(overview.text).fields
        with patch.object(core.gateway, "plan_action") as plan, patch.object(core.gateway, "query") as query:
            self.assertEqual(self.client.get("/project/MEDIAVAULT3").status_code, 400)
            for action in ("update", "accept", "rollback", "restart"):
                self.assertEqual(self.post("/plan/MEDIAVAULT3/" + action, fields).status_code, 400)
            self.assertEqual(self.post("/maintenance/resume/MEDIAVAULT3",
                                      {**fields, "confirmed": "yes", "event_ref": request_id}).status_code, 400)
            plan.assert_not_called()
            query.assert_not_called()
        audit = self.client.get("/audit?project=MEDIAVAULT3")
        self.assertEqual(audit.status_code, 200)
        self.assertIn("MediaVault3", audit.text)
        self.assertIn(request_id, audit.text)
        report = self.client.get("/maintenance/diagnostics/MEDIAVAULT3")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.json()["failures"][0]["recovery"], "rolled_back")

    def test_failure_log_export_is_authenticated_bounded_and_sanitized(self):
        from maintenance_center.core import Outcome
        core = self.client.app.state.core
        core.gateway.apply_update = lambda *a: Outcome("failed", "startup_probe_failed")
        core.gateway.query = lambda project, *a: {"project": project, "containers": [{"lines": ["normal failure", "mysql://admin:danger@host/db", "token=private-value", "-----BEGIN PRIVATE KEY-----", "private-key-body", "-----END PRIVATE KEY-----", "<script>alert(1)</script>"]}]}
        core.approve(core.prepare_manual("PLEX", "web"), "web")
        page = self.client.get("/maintenance")
        self.assertIn("normal failure", page.text)
        self.assertNotIn("<script>alert", page.text)
        response = self.client.get("/maintenance/diagnostics/PLEX")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["content-disposition"])
        for secret in ("danger", "private-value", "private-key-body"):
            self.assertNotIn(secret, response.text)
        self.assertTrue(response.json()["failures"][0]["logs"]["available"])
        self.client.cookies.clear()
        self.assertEqual(self.client.get("/maintenance/diagnostics/PLEX", follow_redirects=False).status_code, 303)

    def test_demo_and_host_boundary(self):
        response = self.client.get("/")
        self.assertIn("未连接 NAS", response.text)
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(self.client.get("/", headers={"Host": "evil.test"}).status_code, 400)
        self.assertEqual(self.client.get("/docs").status_code, 404)

    def test_real_status_shape_and_unavailable_projects_are_not_healthy(self):
        def query(project, action="status", tail=50):
            if project == "PLEX":
                raise MaintenanceError("query_unavailable")
            if action == "health":
                return {"project": project, "overall": "not_deployed"}
            return {"project": project, "deployment_state": "not_deployed", "containers": []}
        with patch("maintenance_center.demo.DemoGateway.query", side_effect=query):
            response = self.client.get("/")
            self.assertEqual(response.status_code, 200)
            self.assertIn("查询不可用", response.text)
            self.assertIn("未部署", response.text)
            self.assertNotIn("运行正常", response.text)
            self.assertIn("<strong>0</strong><span>运行中", response.text)
            detail = self.client.get("/project/PLEX")
            self.assertEqual(detail.status_code, 200)
            self.assertIn("日志暂时不可用", detail.text)

    def test_csrf_and_origin_are_required(self):
        self.assertEqual(self.client.post("/approve", data={}).status_code, 403)
        self.assertEqual(self.post("/approve", {"csrf": "bad"}).status_code, 403)

    def test_manual_demo_update_is_one_time_and_updates_visible_version(self):
        fields = Inputs(self.client.get("/project/PLEX").text).fields
        response = self.post("/plan/PLEX/update", fields)
        self.assertEqual(response.status_code, 200)
        approve = Inputs(response.text).fields
        self.assertIn("1.0.0-demo", self.client.get("/project/PLEX").text)
        self.assertEqual(self.post("/approve", approve).status_code, 200)
        self.assertIn("2.0.0-demo", self.client.get("/project/PLEX").text)
        self.assertEqual(self.post("/approve", approve).status_code, 400)

    def test_schedule_persists_and_rejects_stale_form(self):
        data = Inputs(self.client.get("/schedule").text).fields
        data.update({"hours": "2", "enabled": "yes", "projects": "PLEX"})
        self.assertEqual(self.post("/schedule", data).status_code, 200)
        self.assertIn("自动更新", self.client.get("/").text)
        self.assertEqual(self.post("/schedule", data).status_code, 400)

    def test_logout_blocks_all_project_routes_and_old_session(self):
        old = self.client.cookies.get("session")
        fields = Inputs(self.client.get("/").text).fields
        self.post("/logout", fields)
        self.assertFalse(self.client.app.state.auth.check(old))
        for path in ["/", "/project/PLEX", "/schedule", "/audit"]:
            self.assertEqual(self.client.get(path, follow_redirects=False).headers["location"], "/login")
        self.assertEqual(self.client.post("/plan/PLEX/update", headers={"Origin": "http://testserver"}, follow_redirects=False).status_code, 303)

    def test_recovery_invalidates_session_and_csrf_is_session_bound(self):
        fields = Inputs(self.client.get("/").text).fields
        self.assertEqual(self.post("/approve", {"csrf": "非ASCII"}).status_code, 403)
        self.post("/logout", fields)
        recovery = Inputs(self.client.get("/recover").text).fields
        recovery.update(code=self.client.app.state.auth.issue_code("recover"), name="admin", password="replacement-test-password")
        self.assertEqual(self.post("/recover", recovery).status_code, 200)
        login = Inputs(self.client.get("/login").text).fields
        login.update(name="admin", password="replacement-test-password")
        self.post("/login", login)
        self.assertEqual(self.post("/plan/PLEX/update", fields).status_code, 403)

    def test_oversized_request_rejected(self):
        self.assertEqual(self.client.post("/login", content=b"x" * 16385, headers={"Origin": "http://testserver"}).status_code, 413)

    def test_scheduler_wakeup_honors_persistent_due_time(self):
        core = self.client.app.state.core
        core.configure(["PLEX"], 1, True, core.state()["revision"], "web")
        job = self.client.app.state.scheduler.get_job("maintenance")
        self.assertEqual(job.func(), [])
        with core._transaction() as db:
            db.execute("UPDATE control SET next_run=0")
        result = job.func()
        self.assertEqual(result[0][0], "PLEX")
        self.assertEqual(result[0][1].status, "succeeded")
        self.assertEqual(job.func(), [])


if __name__ == "__main__":
    unittest.main()
