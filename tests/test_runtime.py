import json
import tempfile
import unittest
import threading
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from maintenance_center.core import MaintenanceError
from maintenance_center.demo import DemoGateway
from maintenance_center.managed_gateway import PROTOCOL
from maintenance_center.runtime import RuntimeConfig, ShadowTransport
from maintenance_center.web import create_app
from tests.test_auth_web import Inputs


class RuntimeTests(unittest.TestCase):
    def test_background_approval_remains_queryable_and_duplicate_cannot_execute(self):
        entered, release = threading.Event(), threading.Event()
        gateway = DemoGateway()
        original = gateway.apply_plan
        def apply(plan, request_id):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test_release_timeout")
            return original(plan, request_id)
        gateway.apply_plan = apply
        with tempfile.TemporaryDirectory() as tmp:
            with TestClient(create_app(Path(tmp), gateway, mode="active", address="192.168.50.10"), base_url="http://192.168.50.10:8767") as client:
                try:
                    auth = client.app.state.auth
                    auth.set_password(auth.issue_code("initialize"), "admin", "test-only-password")
                    fields = Inputs(client.get("/login").text).fields
                    fields.update(name="admin", password="test-only-password")
                    headers = {"Origin": "http://192.168.50.10:8767"}
                    client.post("/login", data=fields, headers=headers)
                    fields = Inputs(client.get("/project/PLEX").text).fields
                    plan = client.post("/plan/PLEX/update", data=fields, headers=headers)
                    approval = Inputs(plan.text).fields
                    response = client.post("/approve", data=approval, headers=headers, follow_redirects=False)
                    self.assertEqual(response.status_code, 303)
                    self.assertTrue(entered.wait(2))
                    page = client.get(response.headers["location"])
                    self.assertIn("已提交，正在执行", page.text)
                    self.assertIn('http-equiv="refresh"', page.text)
                    self.assertEqual(client.get("/").status_code, 200)
                    self.assertEqual(client.post("/approve", data=approval, headers=headers).status_code, 400)
                    self.assertNotIn("test-only-password", str(client.app.state.core.audit_page()))
                finally:
                    release.set()

    def test_shadow_transport_blocks_all_plans_and_writes_before_network(self):
        target = Mock(return_value={})
        transport = ShadowTransport(target)
        for action in ("plan-update", "apply-update", "plan-accept", "apply-accept", "apply-restart", "enroll", "configure", "remove"):
            with self.assertRaisesRegex(MaintenanceError, "shadow_readonly"):
                transport(PROTOCOL, {"action": action}, 90)
        with self.assertRaisesRegex(MaintenanceError, "shadow_readonly"):
            transport("nadex-gateway-v1", {"action": "status"}, 90)
        target.assert_not_called()
        transport(PROTOCOL, {"action": "status"}, 90)
        target.assert_called_once()

    def test_config_rejects_public_address_extra_fields_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime.json"
            data = dict(address="192.168.50.10", port=8767, gateway_address="192.168.50.10",
                        gateway_port=22, key_file="/run/secrets/ssh_key", known_hosts="/run/secrets/known_hosts",
                        gateway_user="maintenance", host_key_alias="docker-maintenance-center", mode="shadow")
            path.write_text(json.dumps(data))
            self.assertEqual(RuntimeConfig.load(path).mode, "shadow")
            for changed in ({**data, "address": "8.8.8.8"}, {**data, "command": "id"}, {**data, "observe_enabled": "false"}):
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):
                    RuntimeConfig.load(path)
            path.write_text('{"mode":"shadow","mode":"active"}')
            with self.assertRaises(ValueError):
                RuntimeConfig.load(path)

    def test_shadow_web_disables_scheduler_telegram_and_write_routes(self):
        with tempfile.TemporaryDirectory() as tmp, patch("maintenance_center.web.start_scheduler") as scheduler, patch("maintenance_center.web.TelegramRuntime.start") as telegram:
            with TestClient(create_app(Path(tmp), DemoGateway(), mode="shadow", address="192.168.50.10"), base_url="http://192.168.50.10:8767") as client:
                auth = client.app.state.auth
                auth.set_password(auth.issue_code("initialize"), "admin", "test-only-password")
                fields = Inputs(client.get("/login").text).fields
                fields.update(name="admin", password="test-only-password")
                client.post("/login", data=fields, headers={"Origin": "http://192.168.50.10:8767"})
                self.assertIn("只读影子模式", client.get("/").text)
                self.assertEqual(client.get("/", headers={"Host": "testserver"}).status_code, 400)
                for route in ("/approve", "/schedule", "/telegram/token", "/maintenance/reconcile", "/plan/PLEX/update"):
                    self.assertEqual(client.post(route, headers={"Origin": "http://192.168.50.10:8767"}).status_code, 403)
                scheduler.assert_not_called()
                telegram.assert_not_called()
                self.assertEqual(client.app.state.core.state()["gate"], "shadow_readonly")

    def test_real_gateway_log_lines_are_rendered_escaped(self):
        gateway = DemoGateway()
        original = gateway.query
        def query(project, action="status", tail=50):
            if action == "logs":
                return {"project": project, "containers": [{"service": "plex", "container": "plex", "lines": ["<script>bad</script>", "healthy"]}]}
            return original(project, action, tail)
        gateway.query = query
        with tempfile.TemporaryDirectory() as tmp:
            with TestClient(create_app(Path(tmp), gateway)) as client:
                auth = client.app.state.auth
                auth.set_password(auth.issue_code("initialize"), "admin", "test-only-password")
                fields = Inputs(client.get("/login").text).fields
                fields.update(name="admin", password="test-only-password")
                client.post("/login", data=fields, headers={"Origin": "http://testserver"})
                text = client.get("/project/PLEX").text
                self.assertIn("&lt;script&gt;bad&lt;/script&gt;", text)
                self.assertIn("plex plex", text)
