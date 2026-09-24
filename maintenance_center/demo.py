"""Deterministic local demonstration. This module cannot contact a NAS."""

import copy
import hashlib
import secrets
import time

from .core import MaintenanceError, Outcome, Plan, PROJECTS, RemoteState


# Display names include retired projects for historical audit and notices only.
NAMES = {"MEDIAVAULT3": "MediaVault3", "MOVIEPILOT2": "MoviePilot2", "EMBY": "EMBY", "PLEX": "PLEX", "CONFIGFLOW": "ConfigFlow + Sub-Store"}


class DemoGateway:
    def __init__(self):
        self.versions = {p: 1 for p in NAMES}
        self.operations = {}
        self.registry_revision = 1
        self.allowed_roots = ["/demo/compose"]
        self.catalog = {p: self.definition(p) for p in PROJECTS}
        self.previews = {}

    @staticmethod
    def definition(project):
        services = ["config-flow", "sub-store"] if project == "CONFIGFLOW" else [project.lower()]
        return {"id": project, "name": NAMES[project], "active": True, "revision": 1,
                "compose_path": "/demo/compose/" + project.lower() + "/compose.yaml",
                "compose_project": project.lower(), "services": services, "adapter": "compose",
                "policy": "auto", "backup_exempt": True, "backup_paths": [], "health": {"mode": "running"}}

    def _project(self, project, active=True):
        if project not in self.catalog or (active and not self.catalog[project]["active"]):
            raise MaintenanceError("project_not_allowed")

    def _action(self, project, action):
        self._project(project)
        if action != "update":
            raise MaintenanceError("action_not_allowed")

    def refresh(self):
        return {"revision": self.registry_revision, "projects": copy.deepcopy(list(self.catalog.values())),
                "allowed_roots": self.allowed_roots[:]}

    def request(self, action, request_id=None, **values):
        if action == "list":
            return self.refresh()
        candidate = self.definition("MEDIAVAULT3")
        if action == "discover":
            return {"candidates": [] if self.catalog.get("MEDIAVAULT3", {}).get("active") else [candidate]}
        if action == "preview":
            if values.get("compose_path") != candidate["compose_path"] or values.get("services") != candidate["services"]:
                raise MaintenanceError("project_not_allowed")
            token = secrets.token_urlsafe(32)
            candidate["backup_exempt"] = False
            result = {"token": token, "expires_at": time.time() + 300, "definition": candidate,
                      "mounts": [], "backup_supported": False, "warnings": ["本地演示，不连接 NAS；需演示备份豁免确认"]}
            self.previews[token] = copy.deepcopy(result)
            return result
        if action not in {"enroll", "configure", "remove"}:
            raise MaintenanceError("action_not_allowed")
        if values.get("expected_revision") != self.registry_revision:
            raise MaintenanceError("revision_conflict")
        if action == "enroll":
            preview = self.previews.pop(values.get("token"), None)
            if not preview or preview["expires_at"] <= time.time():
                raise MaintenanceError("preview_expired")
            definition = preview["definition"]
            project = definition["id"]
            if self.catalog.get(project, {}).get("active"):
                raise MaintenanceError("project_conflict")
            definition["name"] = values["name"]
        else:
            project = values["project"]
            self._project(project)
            definition = copy.deepcopy(self.catalog[project])
        if action == "remove":
            definition["active"] = False
        else:
            if values["policy"] not in {"auto", "manual", "notify"}:
                raise MaintenanceError("policy_invalid")
            if not values["backup_exempt"]:
                raise MaintenanceError("backup_exemption_required")
            definition.update({k: copy.deepcopy(values[k]) for k in ("policy", "backup_exempt", "backup_paths", "health")})
        definition["revision"] = self.catalog.get(project, {}).get("revision", 0) + 1
        definition["last_change_ref"] = request_id
        self.catalog[project] = definition
        self.registry_revision += 1
        return {"revision": self.registry_revision, "project": copy.deepcopy(definition)}

    def plan_update(self, project):
        return self.plan_action(project, "update")

    def plan_action(self, project, action):
        self._action(project, action)
        if action == "update" and self.versions[project] == 2:
            return None
        secret = secrets.token_urlsafe(32)
        current = self.versions[project]
        target = 2 if action == "update" else current
        services = self.catalog[project]["services"]
        details = {"current_version": f"{current}.0.0-demo", "target_version": f"{target}.0.0-demo",
                   "images": [{"service": service,
                               "current": "sha256:" + hashlib.sha256((service + str(current)).encode()).hexdigest(),
                               "target": "sha256:" + hashlib.sha256((service + str(target)).encode()).hexdigest()} for service in services]}
        return Plan(project, time.time() + 300, secret, hashlib.sha256(secret.encode()).hexdigest()[:16], action, details)

    def apply_update(self, plan, request_id):
        return self.apply_plan(plan, request_id)

    def apply_plan(self, plan, request_id):
        self._action(plan.project, plan.action)
        if plan.action == "update":
            if self.catalog[plan.project]["policy"] == "notify":
                raise MaintenanceError("policy_notify_only")
            self.versions[plan.project] = 2
        recovery = "not_required"
        self.operations[plan.project] = RemoteState("succeeded", request_id, "ok", plan.operation_ref, plan.action, recovery)
        return Outcome("succeeded", "ok", recovery=recovery)

    def operation_status(self, project):
        self._project(project, active=False)
        return self.operations.get(project, RemoteState("idle"))

    def query(self, project, action="status", tail=50):
        self._project(project)
        services = self.catalog[project]["services"]
        if action == "logs":
            return {"project": project, "tail": tail, "containers": [{"name": service, "logs": "[demo] Service running\n[demo] Health check passed"} for service in services]}
        return {"project": project, "deployment_state": "deployed", "overall": "healthy",
                "containers": [{"name": service, "service": service, "status": "running", "health": "healthy", "version": f"{self.versions[project]}.0.0-demo",
                                "image_id": "sha256:" + hashlib.sha256((service + str(self.versions[project])).encode()).hexdigest()} for service in services]}
