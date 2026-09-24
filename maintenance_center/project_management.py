"""Durable registration changes and one-shot enrollment checks, sharing Core's write lock."""
import json
import secrets

from .core import MaintenanceError
from . import metadata


class ProjectManagement:
    def __init__(self, core):
        self.core = core
        self.wake = lambda: None
        core.db.executescript("""
            CREATE TABLE IF NOT EXISTS registry_changes (
                request_id TEXT PRIMARY KEY, project TEXT NOT NULL, action TEXT NOT NULL,
                actor TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, code TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS initial_checks (
                request_id TEXT PRIMARY KEY, project TEXT NOT NULL, actor TEXT NOT NULL,
                status TEXT NOT NULL, code TEXT NOT NULL, created REAL NOT NULL,
                operation_request TEXT
            );
        """)
        core.db.execute("""CREATE TABLE IF NOT EXISTS initial_check_details (
            request_id TEXT PRIMARY KEY, details TEXT NOT NULL
        )""")
        with core._transaction() as db:
            # A claimed first check is never replayed after interruption. A dispatched
            # operation is reconciled through Core's normal durable operation claim.
            interrupted = db.execute("SELECT * FROM initial_checks WHERE status='running' AND operation_request IS NULL").fetchall()
            for job in interrupted:
                db.execute("UPDATE initial_checks SET status='failed',code='interrupted_before_dispatch' WHERE request_id=?", (job["request_id"],))
                core._audit(db, job["actor"], "initial_check", "interrupted_before_dispatch", job["project"], job["request_id"], "failed")

    def supported(self):
        if not hasattr(self.core.gateway, "request"):
            raise MaintenanceError("project_management_unavailable")

    def overview(self):
        self.supported()
        return {"revision": self.core.gateway.registry_revision,
                "allowed_roots": self.core.gateway.allowed_roots,
                "projects": list(self.core.gateway.catalog.values()),
                "initial_checks": self.initial_checks()}

    def discover(self):
        self.supported()
        return self.core.gateway.request("discover")

    def preview(self, compose_path, services):
        self.supported()
        return self.core.gateway.request("preview", compose_path=compose_path, services=services)

    def initial_checks(self):
        with self.core._db_lock:
            return [dict(row) for row in self.core.db.execute("SELECT * FROM initial_checks ORDER BY created DESC LIMIT 50")]

    def _commit(self, change):
        core = self.core
        definition = core.gateway.catalog.get(change["project"])
        if definition is None or definition.get("last_change_ref") != change["request_id"]:
            return False
        active = definition["active"]
        with core._transaction() as db:
            row = db.execute("SELECT status FROM registry_changes WHERE request_id=?", (change["request_id"],)).fetchone()
            if row is None or row[0] == "completed":
                return True
            state = db.execute("SELECT targets FROM control").fetchone()
            targets = [p for p in json.loads(state[0]) if p in core.projects]
            if active and change["action"] == "enroll" and change["project"] not in targets:
                targets.append(change["project"])
            db.execute("UPDATE control SET targets=?,revision=revision+1 WHERE id=1", (json.dumps(targets),))
            if not active:
                db.execute("DELETE FROM project_pause WHERE project=?", (change["project"],))
                db.execute("UPDATE initial_checks SET status='cancelled',code='project_removed' WHERE project=? AND status='pending'", (change["project"],))
            elif change["action"] == "enroll":
                db.execute("""INSERT OR IGNORE INTO initial_checks
                    (request_id,project,actor,status,code,created,operation_request) VALUES(?,?,?,?,?,?,NULL)""",
                           (change["request_id"], change["project"], change["actor"], "pending", "queued", core.clock()))
            db.execute("UPDATE registry_changes SET status='completed',code='ok' WHERE request_id=?", (change["request_id"],))
            core._plans.clear()
            core._audit(db, change["actor"], "project_" + change["action"], project=change["project"], request_id=change["request_id"])
        return True

    def change(self, action, project, actor, expected_revision, **values):
        self.supported()
        core = self.core
        core._actor(actor)
        if action not in {"enroll", "configure", "remove"}:
            raise MaintenanceError("action_not_allowed")
        if not core._execution.acquire(blocking=False):
            raise MaintenanceError("operation_busy")
        change = None
        try:
            if core.state()["gate"] != "ready":
                raise MaintenanceError("writes_paused")
            if expected_revision != core.gateway.registry_revision:
                raise MaintenanceError("stale_registry")
            request_id = secrets.token_hex(16)
            change = {"request_id": request_id, "project": project, "action": action, "actor": actor}
            with core._transaction() as db:
                if db.execute("SELECT 1 FROM operations WHERE status IN ('running','unknown')").fetchone():
                    raise MaintenanceError("operation_busy")
                db.execute("INSERT INTO registry_changes VALUES(?,?,?,?,?,?,?)",
                           (request_id, project, action, actor, "pending", core.clock(), "submitted"))
            arguments = dict(values, expected_revision=expected_revision)
            if action != "enroll":
                arguments["project"] = project
            try:
                core.gateway.request(action, request_id=request_id, **arguments)
                core.gateway.refresh()
            except MaintenanceError as error:
                if str(error) not in {"registry_unavailable", "transport_uncertain", "invalid_gateway_response", "invalid_gateway_data", "invalid_registry"}:
                    with core._transaction() as db:
                        db.execute("UPDATE registry_changes SET status='failed',code=? WHERE request_id=?", (core._code(str(error)), request_id))
                    raise
                try:
                    core.gateway.refresh()
                except Exception:
                    pass
                if not self._commit(change):
                    core._pause_all("registry_change_unknown", event_actor=actor)
                    raise MaintenanceError("registry_change_unknown") from None
            if not self._commit(change):
                core._pause_all("registry_change_unknown", event_actor=actor)
                raise MaintenanceError("registry_change_unknown")
            return core.gateway.catalog[project]
        finally:
            core._execution.release()
            if change is not None:
                try:
                    self.wake()
                except Exception:
                    # Durable pending jobs are also consumed by the periodic worker.
                    pass

    def reconcile_changes(self):
        with self.core._db_lock:
            pending = [dict(row) for row in self.core.db.execute("SELECT * FROM registry_changes WHERE status='pending'")]
        if not pending:
            return True
        try:
            self.core.gateway.refresh()
        except Exception:
            return False
        return all(self._commit(change) for change in pending)

    def reconcile_checks(self):
        with self.core._transaction() as db:
            jobs = db.execute("""SELECT i.*,o.status AS operation_status,o.code AS operation_code,o.action
                FROM initial_checks i JOIN operations o ON o.request_id=i.operation_request
                WHERE i.status IN ('running','unknown')
                AND o.status IN ('succeeded','failed','unknown','rolled_back')""").fetchall()
            for job in jobs:
                status, code = job["operation_status"], job["operation_code"]
                if job["action"] == "accept" and status == "succeeded":
                    status, code = "failed", "interrupted_after_accept"
                if (status, code) == (job["status"], job["code"]):
                    continue
                db.execute("UPDATE initial_checks SET status=?,code=? WHERE request_id=?", (status, code, job["request_id"]))
                self.core._audit(db, job["actor"], "initial_check", code, job["project"], job["request_id"], status)

    def run_initial(self):
        core = self.core
        if not core._execution.acquire(blocking=False):
            return []
        results = []
        try:
            if core.state()["gate"] != "ready":
                return results
            with core._db_lock:
                pending = [dict(row) for row in core.db.execute("SELECT * FROM initial_checks WHERE status='pending' ORDER BY created")]
            for job in pending:
                project = job["project"]
                if core.state()["gate"] != "ready":
                    break
                with core._transaction() as db:
                    claimed = db.execute("UPDATE initial_checks SET status='running',code='checking' WHERE request_id=? AND status='pending'", (job["request_id"],)).rowcount
                if not claimed:
                    continue
                status, code = "failed", "check_failed"
                try:
                    core._project(project)
                    if project in core.state()["paused_projects"]:
                        raise MaintenanceError("project_paused")
                    revision = core.state()["revision"]
                    plan = core.plan_automatic(project, job["actor"], revision, automatic=False, initial_job=job["request_id"])
                    if plan is None:
                        status, code = "succeeded", "no_update"
                        try:
                            details = metadata.clean(project, core.gateway.current_metadata(project))
                        except Exception:
                            details = metadata.clean(project, {})
                        with core._transaction() as db:
                            db.execute("INSERT OR REPLACE INTO initial_check_details VALUES(?,?)", (job["request_id"], json.dumps(details)))
                    elif core.project_policy(project) != "auto":
                        status, code = "succeeded", "update_available"
                        core._validate_plan(project, plan)
                        plan = core._with_current_versions(plan)
                        with core._transaction() as db:
                            db.execute("INSERT OR REPLACE INTO initial_check_details VALUES(?,?)", (job["request_id"], json.dumps(metadata.clean(project, plan.details))))
                            core._audit(db, job["actor"], "update_available", project=project)
                    else:
                        core._validate_plan(project, plan)
                        plan = core._with_current_versions(plan)
                        # Explicit enrollment grants this one execution even if the
                        # global periodic schedule is paused. Hard gate still applies.
                        outcome = core._apply(plan, job["actor"], revision, automatic=False, initial_job=job["request_id"])
                        status, code = outcome.status, outcome.code
                except MaintenanceError as error:
                    code = core._code(str(error))
                except Exception:
                    code = "planning_unavailable"
                with core._transaction() as db:
                    linked = db.execute("""SELECT o.status,o.code FROM operations o JOIN initial_checks i
                        ON o.request_id=i.operation_request WHERE i.request_id=?""", (job["request_id"],)).fetchone()
                    if linked and linked["status"] == "unknown":
                        status, code = "unknown", linked["code"]
                    db.execute("UPDATE initial_checks SET status=?,code=? WHERE request_id=?", (status, code, job["request_id"]))
                    core._audit(db, job["actor"], "initial_check", code, project, job["request_id"], status)
                results.append((project, status, code))
        finally:
            core._execution.release()
        return results
