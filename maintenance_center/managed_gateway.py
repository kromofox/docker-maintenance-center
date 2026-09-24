"""Uniform V2 host protocol; registry membership is independent of presentation history."""
import hashlib
import math
import re
import time
import uuid

from .core import MaintenanceError, Outcome, Plan, PlanUnavailable, RemoteState
from .gateway import GatewayFailure
from . import metadata

PROTOCOL = "project007-v2"
IDENTIFIER = re.compile(r"[A-Z][A-Z0-9]{1,31}")


class ManagedGateway:
    def __init__(self, transport, clock=time.time):
        self.transport, self.clock = transport, clock
        self.catalog = {}
        self.registry_revision = 0
        self.allowed_roots = []
        self.observe_enabled = True

    def request(self, action, request_id=None, **values):
        request_id = request_id or uuid.uuid4().hex
        request = dict(values, action=action, request_id=request_id)
        timeout = 25200 if action.startswith("apply-") else 180
        try:
            response = self.transport(PROTOCOL, request, timeout)
        except Exception as error:
            raise GatewayFailure("transport_uncertain" if action.startswith("apply-") else "registry_unavailable") from error
        if (not isinstance(response, dict) or response.get("protocol") != PROTOCOL
                or response.get("request_id") != request_id or type(response.get("ok")) is not bool):
            raise GatewayFailure("invalid_gateway_response")
        if not response["ok"]:
            code = response.get("error", {}).get("code", "host_rejected")
            if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
                code = "host_rejected"
            if action.startswith("plan-"):
                raise PlanUnavailable(code)
            raise GatewayFailure(code)
        data = response.get("data")
        if not isinstance(data, dict):
            raise GatewayFailure("invalid_gateway_data")
        return data

    def refresh(self):
        data = self.request("list")
        entries = data.get("projects")
        revision = data.get("revision")
        if not isinstance(entries, list) or len(entries) > 256 or type(revision) is not int or revision < 0:
            raise GatewayFailure("invalid_registry")
        catalog = {}
        for entry in entries:
            if (not isinstance(entry, dict) or not isinstance(entry.get("id"), str)
                    or IDENTIFIER.fullmatch(entry["id"]) is None or entry["id"] in catalog
                    or type(entry.get("active")) is not bool or type(entry.get("revision")) is not int
                    or entry.get("policy") not in {"auto", "manual", "notify"}
                    or not isinstance(entry.get("name"), str) or not 1 <= len(entry["name"]) <= 80):
                raise GatewayFailure("invalid_registry")
            catalog[entry["id"]] = dict(entry)
        self.catalog, self.registry_revision = catalog, revision
        self.allowed_roots = data.get("allowed_roots", [])
        return data

    def _project(self, project, active=True):
        definition = self.catalog.get(project)
        if definition is None or (active and not definition["active"]):
            raise GatewayFailure("project_not_allowed")
        return definition

    def query(self, project, action="status", tail=50):
        self._project(project)
        if action not in {"status", "health", "logs"}:
            raise GatewayFailure("action_not_allowed")
        return self.request(action, project=project, **({"tail": tail} if action == "logs" else {}))

    def current_metadata(self, project):
        data = self.query(project)
        rows = data.get("containers", [])
        images, versions = {}, {}
        for row in rows:
            service = row.get("service") or row.get("name")
            if not isinstance(service, str):
                continue
            images[service] = row.get("image_id")
            versions[service] = metadata.version(row.get("version"))
        return {"current_images": images, "current_versions": versions,
                "current_version": next(iter(versions.values())) if len(versions) == 1 else None}

    def plan_update(self, project):
        return self.plan_action(project, "update")

    def plan_action(self, project, action):
        self._project(project)
        if action not in {"update", "accept"}:
            raise GatewayFailure("action_not_allowed")
        data = self.request("plan-" + action, project=project)
        if data.get("no_update") is True:
            return None
        token, expires = data.get("plan_id"), data.get("expires_at")
        if (data.get("project") != project or data.get("action") != action
                or not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token)
                or type(expires) not in {int, float} or not math.isfinite(expires)
                or not self.clock() < expires <= self.clock() + 300):
            raise GatewayFailure("invalid_plan")
        images = data.get("image_ids", {})
        if not isinstance(images, dict) or len(images) > 32:
            raise GatewayFailure("invalid_plan_images")
        for service, pair in images.items():
            if (not isinstance(service, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", service)
                    or not isinstance(pair, dict) or set(pair) != {"current", "target"}
                    or any(not isinstance(v, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", v) for v in pair.values())):
                raise GatewayFailure("invalid_plan_images")
        return Plan(project=project, approval=token, expires_at=expires, action=action,
                    operation_ref=hashlib.sha256(token.encode()).hexdigest()[:16],
                    details=metadata.clean(project, data.get("details")), image_ids=images)

    def apply_update(self, plan, request_id):
        return self.apply_plan(plan, request_id)

    def apply_plan(self, plan, request_id):
        self._project(plan.project)
        try:
            data = self.request("apply-" + plan.action, request_id=request_id,
                                project=plan.project, plan_id=plan.approval)
        except GatewayFailure as error:
            if str(error) in {"plan_stale", "plan_expired", "token_invalid", "project_inactive",
                              "project_not_allowed", "policy_notify_only", "manifest_drift"}:
                return Outcome("failed", str(error), recovery="not_required")
            raise
        if data.get("operation_ref") != plan.operation_ref or data.get("action") != plan.action:
            return Outcome("unknown", "operation_mismatch")
        status = data.get("status")
        if status not in {"succeeded", "failed", "unknown"}:
            return Outcome("unknown", "invalid_operation_state")
        return Outcome(status, data.get("code", "unknown"), recovery=metadata.recovery(data.get("recovery")))

    def operation_status(self, project):
        self._project(project, active=False)
        data = self.request("operation-status", project=project)
        status = data.get("status")
        if status not in {"idle", "running", "unknown", "succeeded", "failed"}:
            raise GatewayFailure("invalid_operation_state")
        return RemoteState(status, data.get("request_id"), data.get("code", "ok"),
                           data.get("operation_ref"), data.get("action", "update"),
                           metadata.recovery(data.get("recovery")))

    def release_check(self, project):
        # Background observation must not create plans or consume update authorization.
        data = self.current_metadata(project)
        return {"project": project, "current_images": data["current_images"],
                "current_version": data["current_version"], "observation_kind": "current_runtime_only"}
