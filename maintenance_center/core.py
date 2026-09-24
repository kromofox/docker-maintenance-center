from __future__ import annotations

import fcntl
import json
import math
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Protocol
from . import metadata, diagnostics


PROJECTS = ("MOVIEPILOT2", "EMBY", "PLEX", "CONFIGFLOW")
HISTORICAL_PROJECTS = ("MEDIAVAULT3",) + PROJECTS
TERMINAL = {"succeeded", "failed"}
AUDIT_ACTIONS = ("update", "accept", "rollback", "restart", "schedule_configured", "project_resumed", "writes_paused", "reconciled", "manual_plan_created", "manual_plan_rejected", "login", "logout", "initialize", "recover", "telegram_token", "telegram_bind", "telegram_unbind", "telegram_delete", "project_checked")
AUDIT_RESULTS = ("recorded", "running", "succeeded", "failed", "unknown")
AUDIT_ACTIONS += ("project_enroll", "project_configure", "project_remove", "initial_check", "update_available")


class MaintenanceError(Exception):
    """A stable, non-secret error code for the trusted controller."""


class PlanUnavailable(MaintenanceError):
    """A structured host refusal while preparing a plan."""


@dataclass(frozen=True)
class Plan:
    project: str
    expires_at: float
    approval: str = field(repr=False)
    operation_ref: str | None = None
    action: str = "update"
    details: dict = field(default_factory=dict)
    image_ids: dict = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class Outcome:
    status: str
    code: str
    scope: str = "project"
    recovery: str = "unknown"


@dataclass(frozen=True)
class RemoteState:
    status: str
    request_id: str | None = None
    code: str = "ok"
    operation_ref: str | None = None
    action: str = "update"
    recovery: str = "unknown"


class Gateway(Protocol):
    # Each adapter must enforce digest, drift, health and recovery contracts.
    # It must never turn an uncorrelated last operation into a current result.
    def plan_update(self, project: str) -> Plan | None: ...

    def apply_update(self, plan: Plan, request_id: str) -> Outcome: ...

    def operation_status(self, project: str) -> RemoteState: ...


class Core:
    """Internal service API. Callers must authenticate before invoking methods.

    Holds one process lock for the lifetime of a local database. No live gateway
    is provided here; an adapter must preserve the existing host contracts.
    """

    def __init__(self, directory: Path, gateway: Gateway, clock: Callable = time.time):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        self._process_lock = (directory / "controller.lock").open("a+")
        (directory / "controller.lock").chmod(0o600)
        try:
            fcntl.flock(self._process_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._process_lock.close()
            raise MaintenanceError("controller_already_running") from None
        self.gateway, self.clock = gateway, clock
        self._db_lock = threading.RLock()
        self._execution = threading.Lock()
        self._plans: dict[str, tuple[Plan, int]] = {}
        self.db = sqlite3.connect(directory / "state.sqlite3", check_same_thread=False)
        (directory / "state.sqlite3").chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA foreign_keys = ON;
            PRAGMA journal_mode = DELETE;
            PRAGMA synchronous = FULL;
            CREATE TABLE IF NOT EXISTS control (
                id INTEGER PRIMARY KEY CHECK(id=1),
                gate TEXT NOT NULL,
                revision INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 0,
                hours INTEGER NOT NULL DEFAULT 2,
                targets TEXT NOT NULL DEFAULT '[]',
                next_run REAL
            );
            INSERT OR IGNORE INTO control(id,gate) VALUES(1,'startup');
            CREATE TABLE IF NOT EXISTS schedule_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, started REAL NOT NULL,
                finished REAL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS failure_logs (
                request_id TEXT PRIMARY KEY, captured REAL NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS project_pause (
                project TEXT PRIMARY KEY, code TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS operations (
                request_id TEXT PRIMARY KEY,
                project TEXT NOT NULL,
                actor TEXT NOT NULL,
                status TEXT NOT NULL,
                code TEXT NOT NULL,
                created REAL NOT NULL,
                finished REAL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_unresolved_operation
            ON operations((1)) WHERE status IN ('running','unknown');
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY,
                time REAL NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                project TEXT,
                code TEXT NOT NULL,
                request_id TEXT
            );
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(operations)")}
        if "operation_ref" not in columns:
            self.db.execute("ALTER TABLE operations ADD COLUMN operation_ref TEXT")
            self.db.commit()
        if "action" not in columns:
            self.db.execute("ALTER TABLE operations ADD COLUMN action TEXT NOT NULL DEFAULT 'update'")
            self.db.commit()
        if "details" not in columns:
            self.db.execute("ALTER TABLE operations ADD COLUMN details TEXT NOT NULL DEFAULT '{}'")
            self.db.commit()
        if "recovery" not in columns:
            self.db.execute("ALTER TABLE operations ADD COLUMN recovery TEXT NOT NULL DEFAULT 'unknown'")
            self.db.commit()
        if "event_ref" not in {row[1] for row in self.db.execute("PRAGMA table_info(project_pause)")}:
            self.db.execute("ALTER TABLE project_pause ADD COLUMN event_ref TEXT NOT NULL DEFAULT ''")
            self.db.execute("UPDATE project_pause SET event_ref=lower(hex(randomblob(16))) WHERE event_ref=''")
            self.db.commit()
        if "retry_used" not in {row[1] for row in self.db.execute("PRAGMA table_info(project_pause)")}:
            self.db.execute("ALTER TABLE project_pause ADD COLUMN retry_used INTEGER NOT NULL DEFAULT 0")
            self.db.commit()
        if "result" not in {row[1] for row in self.db.execute("PRAGMA table_info(audit)")}:
            self.db.execute("ALTER TABLE audit ADD COLUMN result TEXT NOT NULL DEFAULT 'recorded'")
            self.db.execute("UPDATE audit SET result='running' WHERE action='update_dispatched'")
            self.db.execute("""UPDATE audit SET result=(SELECT o.status FROM operations o WHERE o.request_id=audit.request_id)
                WHERE action='update_result'
                AND id=(SELECT max(a.id) FROM audit a WHERE a.request_id=audit.request_id AND a.action='update_result')
                AND EXISTS(SELECT 1 FROM operations o WHERE o.request_id=audit.request_id
                    AND o.code=audit.code AND o.status IN ('succeeded','failed','unknown'))""")
            self.db.commit()
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS audit_sequence(id INTEGER PRIMARY KEY CHECK(id=1), value INTEGER NOT NULL);
            INSERT OR IGNORE INTO audit_sequence VALUES(1,0);
            UPDATE audit_sequence SET value=max(value,(SELECT coalesce(max(id),0) FROM audit));
            CREATE INDEX IF NOT EXISTS audit_time ON audit(time);
            CREATE INDEX IF NOT EXISTS audit_operation ON audit(request_id,action,id);
        """)
        with self._transaction() as db:
            db.execute("UPDATE control SET gate='startup' WHERE id=1")
            interrupted = db.execute("SELECT request_id,project FROM operations WHERE status='running'").fetchall()
            db.execute("UPDATE operations SET status='unknown',code='interrupted' WHERE status='running'")
            for row in interrupted:
                self._audit(db, "system", "update_result", "interrupted", row["project"], row["request_id"], "unknown")
        self._startup = True
        from .project_management import ProjectManagement
        self.management = ProjectManagement(self)

    @property
    def projects(self):
        if hasattr(self.gateway, "catalog"):
            return tuple(p for p, definition in self.gateway.catalog.items() if definition["active"])
        return PROJECTS

    @property
    def history_projects(self):
        with self._db_lock:
            recorded = [row[0] for row in self.db.execute("SELECT DISTINCT project FROM audit WHERE project IS NOT NULL")]
        return tuple(dict.fromkeys((*HISTORICAL_PROJECTS, *getattr(self.gateway, "catalog", {}), *recorded)))

    @property
    def names(self):
        from .demo import NAMES
        names = {p: NAMES.get(p, p) for p in self.history_projects}
        names.update({p: d["name"] for p, d in getattr(self.gateway, "catalog", {}).items()})
        return names

    def project_policy(self, project):
        return getattr(self.gateway, "catalog", {}).get(project, {}).get("policy", "auto")

    def close(self):
        with self._execution, self._db_lock:
            self._plans.clear()
            self.db.close()
            self._process_lock.close()

    @contextmanager
    def _transaction(self):
        with self._db_lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def _project(self, project):
        if project not in self.projects:
            raise MaintenanceError("project_not_allowed")

    @staticmethod
    def _actor(actor):
        if actor not in {"web", "telegram"}:
            raise MaintenanceError("actor_not_allowed")

    @staticmethod
    def _code(code):
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
            return "invalid_gateway_code"
        return code

    def _audit(self, db, actor, action, code="ok", project=None, request_id=None, result="recorded"):
        db.execute("UPDATE audit_sequence SET value=value+1")
        sequence = db.execute("SELECT value FROM audit_sequence").fetchone()[0]
        db.execute("INSERT INTO audit(id,time,actor,action,project,code,request_id,result) VALUES(?,?,?,?,?,?,?,?)",
                   (sequence, self.clock(), actor, action, project, code, request_id, result))

    def audit_page(self, start=None, end=None, project=None, action=None, result=None, before=None):
        now = self.clock()
        if project is not None and project not in self.history_projects:
            raise MaintenanceError("project_not_allowed")
        if action is not None and action not in AUDIT_ACTIONS:
            raise MaintenanceError("invalid_audit_action")
        if result is not None and result not in AUDIT_RESULTS:
            raise MaintenanceError("invalid_audit_result")
        for value in (start, end):
            if value is not None and (type(value) not in {int, float} or not math.isfinite(value)):
                raise MaintenanceError("invalid_audit_time")
        if start is not None and end is not None and start >= end:
            raise MaintenanceError("invalid_audit_time")
        if before is not None and (type(before) is not int or not 1 <= before <= 2**63 - 1):
            raise MaintenanceError("invalid_audit_cursor")
        where, values = ["a.time>=?"], [max(start if start is not None else now - 180 * 86400, now - 180 * 86400)]
        for clause, value in (("a.time<?", end), ("a.project=?", project),
                              ("coalesce(o.action,a.action)=?", action), ("a.result=?", result), ("a.id<?", before)):
            if value is not None:
                where.append(clause)
                values.append(value)
        with self._db_lock:
            rows = [dict(row) for row in self.db.execute("""SELECT a.*,coalesce(o.action,a.action) AS display_action
                FROM audit a LEFT JOIN operations o ON o.request_id=a.request_id WHERE """ + " AND ".join(where) + " ORDER BY a.id DESC LIMIT 51", values)]
        return {"rows": rows[:50], "next": rows[49]["id"] if len(rows) > 50 else None}

    def record_event(self, actor, action, succeeded, project=None):
        self._actor(actor)
        if action not in AUDIT_ACTIONS or type(succeeded) is not bool:
            raise MaintenanceError("invalid_audit_event")
        if project is not None:
            self._project(project)
        with self._transaction() as db:
            self._audit(db, actor, action, "ok" if succeeded else "request_rejected", project,
                        result="succeeded" if succeeded else "failed")

    def prune_audit(self, consumed_through):
        if type(consumed_through) is not int or consumed_through < 0:
            raise MaintenanceError("invalid_audit_cursor")
        with self._transaction() as db:
            db.execute("""DELETE FROM audit WHERE time<? AND id<=?
                AND NOT (action='initial_operation' AND request_id IN (SELECT request_id FROM operations))""",
                (self.clock() - 180 * 86400, consumed_through))

    def state(self):
        with self._db_lock:
            row = dict(self.db.execute("SELECT * FROM control WHERE id=1").fetchone())
            row["targets"] = json.loads(row["targets"])
            row["enabled"] = bool(row["enabled"])
            row["paused_projects"] = dict(self.db.execute("SELECT project,code FROM project_pause"))
            row["pause_refs"] = dict(self.db.execute("SELECT project,event_ref FROM project_pause"))
            row["retry_pending"] = [r[0] for r in self.db.execute("SELECT project FROM project_pause WHERE retry_used=0")]
            return row

    def configure(self, targets, hours, enabled, expected_revision, actor):
        self._actor(actor)
        if not isinstance(targets, (list, tuple)) or any(p not in self.projects for p in targets):
            raise MaintenanceError("project_not_allowed")
        if type(hours) is not int or not 1 <= hours <= 720 or type(enabled) is not bool:
            raise MaintenanceError("invalid_schedule")
        if enabled and not targets:
            raise MaintenanceError("empty_schedule")
        selected = [p for p in self.projects if p in targets]
        with self._transaction() as db:
            changed = db.execute("""UPDATE control SET revision=revision+1,targets=?,hours=?,
                enabled=?,next_run=? WHERE id=1 AND revision=?""",
                (json.dumps(selected), hours, enabled,
                 self.clock() + hours * 3600 if enabled else None, expected_revision)).rowcount
            if not changed:
                raise MaintenanceError("stale_schedule")
            self._plans.clear()
            self._audit(db, actor, "schedule_configured")
        return self.state()

    def resume_project(self, project, actor, expected_ref=None):
        self._project(project)
        self._actor(actor)
        with self._transaction() as db:
            if db.execute("SELECT gate FROM control").fetchone()[0] != "ready":
                raise MaintenanceError("writes_paused")
            row = db.execute("SELECT event_ref FROM project_pause WHERE project=?", (project,)).fetchone()
            if expected_ref is not None and (row is None or row[0] != expected_ref):
                raise MaintenanceError("stale_recovery_confirmation")
            db.execute("DELETE FROM project_pause WHERE project=?", (project,))
            self._audit(db, actor, "project_resumed", project=project)

    def _pause_all(self, code, event_actor="system"):
        with self._transaction() as db:
            db.execute("UPDATE control SET gate=?", (self._code(code),))
            self._plans.clear()
            self._audit(db, event_actor, "writes_paused", self._code(code))

    def _validate_plan(self, project, plan):
        self._project(project)
        if not isinstance(plan, Plan) or plan.project != project:
            raise MaintenanceError("invalid_plan")
        self._action(project, plan.action)
        if not isinstance(plan.approval, str) or not plan.approval or len(plan.approval) > 16384:
            raise MaintenanceError("invalid_plan")
        if plan.operation_ref is not None and not re.fullmatch(r"[a-f0-9]{16}", plan.operation_ref):
            raise MaintenanceError("invalid_operation_reference")
        if not isinstance(plan.expires_at, (int, float)) or not self.clock() < plan.expires_at <= self.clock() + 300:
            raise MaintenanceError("invalid_plan_expiry")

    def _version_snapshot(self, plan, side):
        services = tuple(plan.image_ids)
        if not services or len(services) > 32:
            return metadata.versions(plan.project, None), None, "read_failed"
        try:
            expected = {service: plan.image_ids[service][side] for service in services}
            observed = self.gateway.current_metadata(plan.project)
            images = observed.get("current_images")
        except Exception:
            return metadata.versions(plan.project, None), None, "read_failed"
        digest = r"sha256:[a-f0-9]{64}"
        if (not isinstance(images, dict) or set(images) != set(services)
                or any(not isinstance(expected[service], str)
                       or re.fullmatch(digest, expected[service]) is None
                       or not isinstance(images.get(service), str)
                       or re.fullmatch(digest, images[service]) is None
                       or images[service] != expected[service] for service in services)):
            return metadata.versions(plan.project, None), None, "image_mismatch"
        # The host plan already binds these application versions to full image
        # identities. Runtime labels must not replace them after that match.
        values = metadata.versions(plan.project, plan.details.get(side + "_versions"))
        if len(services) == 1 and values.get(services[0]) is None:
            values = {services[0]: metadata.version(plan.details.get(side + "_version"))}
        runtime = metadata.versions(plan.project, observed.get("current_versions"))
        for service in services:
            if values.get(service) is None:
                values[service] = runtime.get(service)
                if len(services) == 1 and values[service] is None:
                    values[service] = metadata.version(observed.get("current_version"))
        if any(values.get(service) is None for service in services):
            return metadata.versions(plan.project, None), None, "filtered"
        return values, next(iter(values.values())) if len(services) == 1 else None, "ok"

    def _with_current_versions(self, plan):
        if plan.action != "update" or not plan.image_ids:
            return plan
        versions, version, status = self._version_snapshot(plan, "current")
        details = dict(plan.details)
        observed = dict(details.get("version_observation") or {})
        observed["before"] = status
        details.update(current_version=version, current_versions=versions, version_observation=observed)
        return replace(plan, details=details)

    def _action(self, project, action):
        allowed = {"update"}
        if getattr(self.gateway, "catalog", {}).get(project, {}).get("adapter") == "mv3":
            allowed.add("accept")
        if action not in allowed:
            raise MaintenanceError("action_not_allowed")

    def prepare_manual(self, project, actor, action="update"):
        self._project(project)
        self._actor(actor)
        self._action(project, action)
        initial = self.state()
        if initial["gate"] in {"planning_unavailable", "reconciling"}:
            # Planning failures happen before any business write. Re-check the
            # host before rejecting a later manual check forever.
            try:
                self.reconcile()
            except MaintenanceError:
                pass
            initial = self.state()
        if initial["gate"] != "ready":
            raise MaintenanceError("writes_paused")
        try:
            plan = (self.gateway.plan_update(project) if action == "update"
                    else self.gateway.plan_action(project, action))
            self.record_event(actor, "project_checked", True, project)
            if plan is None:
                return None
            self._validate_plan(project, plan)
            if plan.action != action:
                raise MaintenanceError("invalid_plan_action")
            plan = self._with_current_versions(plan)
        except PlanUnavailable:
            self.record_event(actor, "project_checked", False, project)
            raise
        except Exception:
            # Planning happens before any business write. A failed manual check
            # is auditable, but must not turn a read failure into a permanent
            # global write lock; every later write still requires a fresh plan.
            self.record_event(actor, "project_checked", False, project)
            raise MaintenanceError("planning_unavailable") from None
        if action == "update" and self.project_policy(project) == "notify":
            self.record_event(actor, "update_available", True, project)
            raise MaintenanceError("policy_notify_only")
        ref = secrets.token_hex(16)
        with self._transaction() as db:
            state = db.execute("SELECT gate,revision FROM control").fetchone()
            if state["gate"] != "ready" or state["revision"] != initial["revision"]:
                raise MaintenanceError("stale_schedule")
            self._plans[ref] = (plan, initial["revision"])
            self._audit(db, actor, "manual_plan_created", project=project)
        return ref

    def plan_view(self, ref, actor):
        self._actor(actor)
        with self._db_lock:
            item = self._plans.get(ref)
            if item is None or item[0].expires_at <= self.clock():
                raise MaintenanceError("approval_expired_or_consumed")
            plan, revision = item
            details = metadata.clean(plan.project, plan.details)
            return {
                "project": plan.project,
                "action": plan.action,
                "expires_at": plan.expires_at,
                "details": details,
                "current_text": metadata.current_text(plan.project, details),
                "target_text": metadata.current_text(plan.project, {
                    "current_version": details["target_version"],
                    "current_versions": details["target_versions"],
                }),
            }

    def recovery_view(self):
        with self._db_lock:
            return [dict(row) for row in self.db.execute("""SELECT request_id,project,action,status,code,recovery,created
                FROM operations WHERE status IN ('running','unknown') ORDER BY created""")]

    def reject(self, ref, actor):
        self._actor(actor)
        with self._transaction() as db:
            item = self._plans.get(ref)
            if item is None:
                raise MaintenanceError("approval_expired_or_consumed")
            del self._plans[ref]
            self._audit(db, actor, "manual_plan_rejected", project=item[0].project)

    def approve(self, ref, actor):
        self._actor(actor)
        if not self._execution.acquire(blocking=False):
            raise MaintenanceError("operation_busy")
        try:
            with self._db_lock:
                item = self._plans.pop(ref, None)
            if item is None:
                raise MaintenanceError("approval_expired_or_consumed")
            plan, revision = item
            return self._apply(plan, actor, revision, automatic=False)
        finally:
            self._execution.release()

    def _apply(self, plan, actor, revision, automatic, retry_ref=None, report_id=None, initial_job=None):
        self._validate_plan(plan.project, plan)
        if plan.action == "update" and self.project_policy(plan.project) == "notify":
            raise MaintenanceError("policy_notify_only")
        if automatic and plan.action not in {"update", "accept"}:
            raise MaintenanceError("action_not_automated")
        request_id = secrets.token_hex(16)
        # Commit the dispatch claim and trusted pre-update versions together
        # before network I/O. A crash is reconciled, never replayed.
        with self._transaction() as db:
            state = db.execute("SELECT * FROM control").fetchone()
            if state["gate"] != "ready":
                raise MaintenanceError("writes_paused")
            if state["revision"] != revision:
                raise MaintenanceError("stale_schedule")
            if automatic and (not state["enabled"] or plan.project not in json.loads(state["targets"]) or self.project_policy(plan.project) != "auto"):
                raise MaintenanceError("authorization_revoked")
            pause = db.execute("SELECT event_ref,retry_used FROM project_pause WHERE project=?", (plan.project,)).fetchone()
            if automatic and pause and not (retry_ref == pause["event_ref"] and pause["retry_used"] == 1):
                raise MaintenanceError("project_paused")
            if retry_ref is not None and (pause is None or pause["event_ref"] != retry_ref):
                raise MaintenanceError("stale_recovery_confirmation")
            db.execute("""INSERT INTO operations
                       (request_id,project,actor,status,code,created,finished,operation_ref,action,details)
                       VALUES(?,?,?,?,?,?,NULL,?,?,?)""",
                       (request_id, plan.project, actor, "running", "submitted", self.clock(), plan.operation_ref, plan.action,
                        json.dumps(metadata.clean(plan.project, plan.details))))
            self._audit(db, actor, "update_dispatched", project=plan.project, request_id=request_id, result="running")
            if initial_job is not None:
                db.execute("UPDATE initial_checks SET operation_request=? WHERE request_id=? AND status='running'", (request_id, initial_job))
                self._audit(db, actor, "initial_operation", project=plan.project, request_id=request_id)
        try:
            result = (self.gateway.apply_update(plan, request_id) if plan.action == "update"
                      else self.gateway.apply_plan(plan, request_id))
            if (not isinstance(result, Outcome) or result.status not in TERMINAL | {"unknown"}
                    or result.scope not in {"project", "common"}):
                result = Outcome("unknown", "invalid_gateway_result")
        except Exception:
            result = Outcome("unknown", "transport_uncertain")
        result = Outcome(result.status, self._code(result.code), result.scope, metadata.recovery(result.recovery))
        details = metadata.clean(plan.project, plan.details)
        if result.status == "succeeded" and plan.action == "update" and plan.image_ids:
            versions, version, status = self._version_snapshot(plan, "target")
            observed = dict(details["version_observation"])
            observed["after"] = status
            details = metadata.clean(plan.project, {
                **details, "target_version": version, "target_versions": versions,
                "version_observation": observed,
            })
        with self._transaction() as db:
            self._finish(db, request_id, plan.project, actor, result)
            db.execute("UPDATE operations SET details=? WHERE request_id=?", (json.dumps(details), request_id))
            if report_id is not None:
                self._report_item_locked(db, report_id, plan.project, result.status, result.code)
        if result.status == "failed":
            try:
                logs = diagnostics.clean_logs(self.gateway.query(plan.project, "logs", 200), plan.project)
            except Exception:
                logs = {"available": False}
            with self._transaction() as db:
                db.execute("INSERT OR REPLACE INTO failure_logs VALUES(?,?,?)", (request_id, self.clock(), json.dumps(logs)))
                db.execute("DELETE FROM failure_logs WHERE request_id NOT IN (SELECT request_id FROM failure_logs ORDER BY captured DESC LIMIT 100)")
        return result

    def failure_history(self, project=None):
        if project is not None and project not in self.history_projects:
            raise MaintenanceError("project_not_allowed")
        with self._db_lock:
            rows = self.db.execute("""SELECT o.request_id,o.project,o.action,o.status,o.code,o.created,o.finished,o.details,o.recovery,
                l.captured,l.payload FROM operations o LEFT JOIN failure_logs l ON o.request_id=l.request_id
                WHERE o.status='failed' AND (? IS NULL OR o.project=?) ORDER BY o.created DESC LIMIT 50""", (project, project))
            result = []
            for row in rows:
                item = dict(row)
                item["details"] = metadata.clean(item["project"], json.loads(item["details"]))
                item["logs"] = json.loads(item.pop("payload") or '{"available":false}')
                result.append(item)
            return result

    def failure_report(self, project):
        if project not in self.history_projects:
            raise MaintenanceError("project_not_allowed")
        with self._db_lock:
            pause = self.db.execute("SELECT code,event_ref,retry_used FROM project_pause WHERE project=?", (project,)).fetchone()
            events = [dict(row) for row in self.db.execute("SELECT time,action,code,request_id,result FROM audit WHERE project=? AND action IN ('retry_started','retry_exhausted','project_resumed') ORDER BY id DESC LIMIT 100", (project,))]
            return {"pause": dict(pause) if pause else None, "retry_events": events, "failures": self.failure_history(project)}

    def _finish(self, db, request_id, project, actor, result):
        db.execute("UPDATE operations SET status=?,code=?,finished=?,recovery=? WHERE request_id=?",
                   (result.status, result.code, self.clock() if result.status in TERMINAL else None,
                    metadata.recovery(result.recovery), request_id))
        if result.status == "unknown" or result.scope == "common":
            db.execute("UPDATE control SET gate='operation_uncertain'")
            self._plans.clear()
        if result.status == "failed":
            previous = db.execute("SELECT retry_used FROM project_pause WHERE project=?", (project,)).fetchone()
            action = db.execute("SELECT action FROM operations WHERE request_id=?", (request_id,)).fetchone()[0]
            used = previous[0] if previous else int(action != "update" or result.scope != "project")
            db.execute("INSERT OR REPLACE INTO project_pause(project,code,event_ref,retry_used) VALUES(?,?,?,?)", (project, result.code, request_id, used))
            if used:
                self._audit(db, actor, "retry_exhausted", result.code, project, request_id, "failed")
        elif result.status == "succeeded":
            action = db.execute("SELECT action FROM operations WHERE request_id=?", (request_id,)).fetchone()[0]
            if action == "update":
                db.execute("DELETE FROM project_pause WHERE project=?", (project,))
        self._audit(db, actor, "update_result", result.code, project, request_id, result.status)

    def _report_item_locked(self, db, report_id, project, status, code="ok", version=None, versions=None):
        rows = json.loads(db.execute("SELECT payload FROM schedule_reports WHERE id=?", (report_id,)).fetchone()[0])
        for row in rows:
            if row["project"] == project:
                row.update(status=status, code=self._code(code), version=metadata.version(version),
                           current_versions=metadata.versions(project, versions))
                operation = db.execute("""SELECT details FROM operations WHERE project=? AND actor='schedule' AND action='update'
                    AND created >= (SELECT started FROM schedule_reports WHERE id=?) AND status=? AND code=? ORDER BY created DESC,rowid DESC LIMIT 1""",
                    (project, report_id, status, code)).fetchone()
                if operation:
                    details = metadata.clean(project, json.loads(operation[0]))
                    row.update(
                        current_version=details["current_version"],
                        target_version=details["target_version"],
                        current_versions=details["current_versions"],
                        target_versions=details["target_versions"],
                        version_observation=details["version_observation"],
                    )
        db.execute("UPDATE schedule_reports SET payload=? WHERE id=?", (json.dumps(rows), report_id))

    def _report_item(self, report_id, project, status, code="ok", version=None, versions=None):
        with self._transaction() as db:
            self._report_item_locked(db, report_id, project, status, code, version, versions)

    def _report_no_update(self, report_id, project, recovered=False):
        version, versions = None, None
        try:
            observed = self.gateway.current_metadata(project)
            version = metadata.version(observed.get("current_version"))
            versions = metadata.versions(project, observed.get("current_versions"))
        except Exception:
            pass
        self._report_item(report_id, project, "recovered_no_update" if recovered else "no_update", version=version, versions=versions)

    def plan_automatic(self, project, actor, revision, automatic=True, initial_job=None):
        try:
            return self.gateway.plan_update(project)
        except PlanUnavailable as error:
            if (str(error) != "rollback_slot_occupied" or self.project_policy(project) != "auto"
                    or getattr(self.gateway, "catalog", {}).get(project, {}).get("adapter") != "mv3"):
                raise
            plan = self.gateway.plan_action(project, "accept")
            self._validate_plan(project, plan)
            result = self._apply(plan, actor, revision, automatic, initial_job=initial_job)
            if result.status != "succeeded":
                raise PlanUnavailable("acceptance_failed")
            if initial_job is not None:
                with self._transaction() as db:
                    db.execute("UPDATE initial_checks SET operation_request=NULL WHERE request_id=?", (initial_job,))
            return self.gateway.plan_update(project)

    def run_due(self):
        report_id = None
        revision = None
        if not self._execution.acquire(blocking=False):
            return []
        try:
            current = self.state()
            if (current["gate"] in {"planning_unavailable", "reconciling"}
                    and current["enabled"] and current["next_run"] <= self.clock()):
                # A previous read-only planning failure must not suppress every
                # future schedule wake. Host reconciliation remains the safety
                # boundary before the next round is allowed to proceed.
                self._reconcile_locked()
            with self._transaction() as db:
                state = db.execute("SELECT * FROM control").fetchone()
                now = self.clock()
                if state["gate"] != "ready" or not state["enabled"] or state["next_run"] > now:
                    return []
                revision = state["revision"]
                entries = [{"project": p, "status": "not_checked", "code": "round_interrupted", "version": None} for p in self.projects if p in json.loads(state["targets"])]
                report_id = db.execute("INSERT INTO schedule_reports(started,payload) VALUES(?,?)", (now, json.dumps(entries))).lastrowid
                db.execute("UPDATE control SET next_run=?", (now + state["hours"] * 3600,))
            results = []
            auto_recovered = False
            recover_planning_gate = False
            for project in self.projects:
                current = self.state()
                while current["gate"] != "ready" or current["revision"] != revision:
                    if current["gate"] == "planning_unavailable" and current["revision"] == revision and current["enabled"]:
                        # The schedule's own earlier check failure paused this
                        # process only; recovery is host-confirmed below, so the
                        # remaining projects still get their round.
                        if not self._reconcile_locked():
                            break
                        auto_recovered = True
                        current = self.state()
                        continue
                    break
                if current["gate"] != "ready" or current["revision"] != revision:
                    break
                if project not in current["targets"]:
                    continue
                if project in current["paused_projects"]:
                    if project in current["retry_pending"]:
                        result = self._retry_paused(project, revision, current["pause_refs"][project], report_id)
                        if result is not None:
                            results.append((project, result))
                        elif project not in self.state()["paused_projects"]:
                            self._report_no_update(report_id, project, recovered=True)
                        else:
                            self._report_item(report_id, project, "retry_failed", self.state()["paused_projects"][project])
                    else:
                        self._report_item(report_id, project, "paused", current["paused_projects"][project])
                    continue
                try:
                    plan = self.plan_automatic(project, "schedule", revision)
                    if plan is None:
                        self._report_no_update(report_id, project)
                        continue
                    self._validate_plan(project, plan)
                    if plan.action != "update":
                        raise MaintenanceError("invalid_plan_action")
                    plan = self._with_current_versions(plan)
                    if self.project_policy(project) != "auto":
                        self._report_item(report_id, project, "update_available", "update_available")
                        with self._transaction() as db:
                            self._audit(db, "schedule", "update_available", project=project)
                        continue
                except PlanUnavailable as error:
                    self._report_item(report_id, project, "check_failed", str(error))
                    continue
                except (TimeoutError, OSError):
                    # Transport/shared-infrastructure failure: every project's
                    # plan call would fail the same way. Stop the round and all
                    # writes until an administrator reconciles the host.
                    self._report_item(report_id, project, "check_failed", "planning_unavailable")
                    self._pause_all("planning_unavailable")
                    recover_planning_gate = False
                    break
                except Exception:
                    # Project-local planning failure: record it, keep the other
                    # projects' checks in this round, and recover the gate below
                    # so no writes or summary notices depend on that pause.
                    self._report_item(report_id, project, "check_failed", "planning_unavailable")
                    self._pause_all("planning_unavailable")
                    recover_planning_gate = True
                    continue
                try:
                    result = self._apply(plan, "schedule", revision, automatic=True, report_id=report_id)
                except MaintenanceError:
                    break
                results.append((project, result))
                if result.status == "unknown":
                    break
            current = self.state()
            if (recover_planning_gate and current["gate"] == "planning_unavailable"
                    and current["revision"] == revision and current["enabled"]):
                # The final project can fail during planning, leaving no next
                # loop iteration to run the normal transient-gate recovery.
                if self._reconcile_locked():
                    auto_recovered = True
            return results
        finally:
            try:
                if report_id is not None:
                    with self._transaction() as db:
                        db.execute("UPDATE schedule_reports SET finished=? WHERE id=?", (self.clock(), report_id))
                        if auto_recovered:
                            # Reconciliation closes any interrupted report. The
                            # next due time was fixed when this round started;
                            # never shift cadence by time spent recovering.
                            db.execute("UPDATE schedule_reports SET finished=? WHERE finished IS NULL", (self.clock(),))
            finally:
                self._execution.release()

    def _retry_paused(self, project, revision, event_ref, report_id=None):
        # Durable one-shot claim: a crash must not create unlimited retries.
        with self._transaction() as db:
            state = db.execute("SELECT * FROM control").fetchone()
            if state["gate"] != "ready" or state["revision"] != revision or not state["enabled"] or project not in json.loads(state["targets"]):
                return None
            if not db.execute("UPDATE project_pause SET retry_used=1 WHERE project=? AND event_ref=? AND retry_used=0", (project, event_ref)).rowcount:
                return None
            self._audit(db, "schedule", "retry_started", project=project, request_id=event_ref)
        try:
            health = self.gateway.query(project, "health")
            if health.get("project") != project or health.get("overall") not in {"healthy", "running_no_probe"}:
                raise MaintenanceError("retry_health_failed")
            plan = self.gateway.plan_update(project)
            if plan is None:
                with self._transaction() as db:
                    state = db.execute("SELECT gate,revision FROM control").fetchone()
                    if state["gate"] == "ready" and state["revision"] == revision:
                        changed = db.execute("DELETE FROM project_pause WHERE project=? AND event_ref=?", (project, event_ref)).rowcount
                        if changed:
                            self._audit(db, "schedule", "project_resumed", project=project)
                return None
            self._validate_plan(project, plan)
            if plan.action != "update":
                raise MaintenanceError("invalid_plan_action")
            plan = self._with_current_versions(plan)
        except Exception as error:
            code = "retry_health_failed" if isinstance(error, MaintenanceError) and str(error) == "retry_health_failed" else "retry_recheck_failed"
            with self._transaction() as db:
                db.execute("UPDATE project_pause SET code=? WHERE project=? AND event_ref=?", (code, project, event_ref))
                self._audit(db, "schedule", "retry_exhausted", code, project, event_ref, "failed")
            return None
        try:
            return self._apply(plan, "schedule", revision, automatic=True, retry_ref=event_ref, report_id=report_id)
        except MaintenanceError:
            with self._transaction() as db:
                self._audit(db, "schedule", "retry_exhausted", "retry_dispatch_blocked", project, event_ref, "failed")
            return None

    def reconcile(self):
        if not self._execution.acquire(blocking=False):
            raise MaintenanceError("operation_busy")
        try:
            return self._reconcile_locked()
        finally:
            self._execution.release()

    def _reconcile_locked(self):
        """Reconcile while the caller already holds the execution claim."""
        if not self.management.reconcile_changes():
            self._pause_all("registry_change_unknown")
            return False
        self._pause_all("reconciling")
        for project in self.history_projects:
            with self._db_lock:
                pending = self.db.execute("SELECT * FROM operations WHERE project=? AND status IN ('running','unknown')", (project,)).fetchone()
            # An idle project has no operation result to reconcile. Do not make
            # an unrelated gateway status request capable of stranding the
            # controller in reconciling forever.
            if pending is None:
                continue
            try:
                if pending["action"] == "restart" and hasattr(self.gateway, "recovery_evidence"):
                    remote = self.gateway.recovery_evidence(project, pending["action"], pending["operation_ref"], pending["request_id"], pending["created"])
                else:
                    remote = self.gateway.operation_status(project)
            except Exception:
                return False
            if not isinstance(remote, RemoteState) or remote.status not in TERMINAL | {"idle"}:
                return False
            with self._transaction() as db:
                pending = db.execute("SELECT * FROM operations WHERE project=? AND status IN ('running','unknown')",
                                     (project,)).fetchone()
                if pending:
                    matched = (remote.operation_ref == pending["operation_ref"]
                               if pending["operation_ref"] else remote.request_id == pending["request_id"])
                    if not matched or remote.status not in TERMINAL or remote.action != pending["action"]:
                        return False
                    if pending["action"] == "restart" and hasattr(self.gateway, "recovery_evidence") and remote.request_id != pending["request_id"]:
                        return False
                    result = Outcome(remote.status, self._code(remote.code), recovery=metadata.recovery(remote.recovery))
                    self._finish(db, pending["request_id"], project, "system", result)
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM operations WHERE status IN ('running','unknown')").fetchone():
                return False
            for pause in db.execute("SELECT project,event_ref FROM project_pause WHERE retry_used=1").fetchall():
                if not db.execute("SELECT 1 FROM audit WHERE action='retry_exhausted' AND request_id=?", (pause["event_ref"],)).fetchone():
                    self._audit(db, "system", "retry_exhausted", "retry_interrupted", pause["project"], pause["event_ref"], "failed")
            db.execute("UPDATE control SET gate='ready'")
            if self._startup:
                db.execute("UPDATE schedule_reports SET finished=? WHERE finished IS NULL", (self.clock(),))
                db.execute("UPDATE control SET next_run=? + hours*3600 WHERE enabled=1 AND next_run IS NULL", (self.clock(),))
            self._audit(db, "system", "reconciled")
        self._startup = False
        self.management.reconcile_checks()
        return True
