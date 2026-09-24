"""Durable, bounded notice outbox containing only approved audit fields."""

import json
import re
import sqlite3
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from .managed_gateway import IDENTIFIER
from .demo import NAMES
from . import metadata


class Notices:
    def __init__(self, directory, clock=time.time):
        self.clock = clock
        self.db = sqlite3.connect(directory / "notices.sqlite3", check_same_thread=False)
        (directory / "notices.sqlite3").chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS cursor(id INTEGER PRIMARY KEY CHECK(id=1), value INTEGER);
            INSERT OR IGNORE INTO cursor VALUES(1,0);
            CREATE TABLE IF NOT EXISTS latest(project TEXT, action TEXT, signature TEXT, stamp REAL,
                PRIMARY KEY(project,action));
            CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY, project TEXT, action TEXT,
                payload TEXT, expires REAL, status TEXT);
        """)

    def collect(self, core):
        """Called by the serialized Telegram lifecycle, including while offline."""
        summary_cursor = self.db.execute("SELECT signature FROM latest WHERE project='SYSTEM' AND action='summary'").fetchone()
        summary_cursor = int(summary_cursor[0]) if summary_cursor else 0
        cursor = self.db.execute("SELECT value FROM cursor").fetchone()[0]
        with core._db_lock:
            reports = [dict(r) for r in core.db.execute("SELECT * FROM schedule_reports WHERE id>? AND finished IS NOT NULL ORDER BY id LIMIT 20", (summary_cursor,))]
            paused = dict(core.db.execute("SELECT project,event_ref FROM project_pause"))
            rows = [dict(r) for r in core.db.execute("""SELECT a.id,a.project,a.code,a.request_id,
                a.time AS stamp,a.result AS event_result,o.action,o.status,
                CASE WHEN o.request_id IS NOT NULL THEN o.details ELSE d.details END AS details,
                o.recovery,o.actor AS operation_actor,a.actor AS event_actor,a.action AS event,
                i.request_id AS initial_request,
                EXISTS(SELECT 1 FROM audit owned WHERE owned.action='initial_operation'
                    AND owned.request_id=a.request_id) AS initial_operation,
                (SELECT sr.id FROM schedule_reports sr WHERE sr.started<=a.time AND (sr.finished IS NULL OR sr.finished>=a.time) ORDER BY sr.id DESC LIMIT 1) AS report_id,
                (a.id=(SELECT max(b.id) FROM audit b WHERE b.request_id=a.request_id AND b.action=a.action)) AS latest_result
                FROM audit a LEFT JOIN initial_checks i
                ON (a.action='initial_check' AND a.request_id=i.request_id)
                    OR (a.action='update_result' AND a.request_id=i.operation_request)
                LEFT JOIN operations o ON o.request_id=CASE WHEN a.action='initial_check'
                    THEN i.operation_request ELSE a.request_id END
                LEFT JOIN initial_check_details d ON d.request_id=i.request_id
                WHERE a.id>? ORDER BY a.id LIMIT 500""", (cursor,))]
        with self.db:
            self.db.execute("DELETE FROM outbox WHERE expires<=?", (self.clock(),))
            for notice_id, payload in self.db.execute("SELECT id,payload FROM outbox WHERE action='retry'").fetchall():
                item = json.loads(payload)
                if paused.get(item["project"]) != item["operation"]:
                    self.db.execute("DELETE FROM outbox WHERE id=?", (notice_id,))
            for report in reports:
                items = json.loads(report["payload"])
                # Automatic round notices contain only actionable outcomes.
                # No-update and interrupted entries remain in the persisted
                # report and Web audit, but do not repeat in Telegram.
                items = [dict(item, name=core.names.get(item["project"], item["project"])) for item in items if item["status"] not in {"no_update", "recovered_no_update", "not_checked"}]
                payload = {"action": "summary", "stamp": report["started"], "items": items}
                # A quiet round (no update, no fault) changes nothing the
                # administrator must see; only rounds with effects notify.
                has_effect = bool(items)
                if has_effect:
                    has_problem = any(x["status"] != "succeeded" for x in items)
                    self.db.execute("INSERT INTO outbox(project,action,payload,expires,status) VALUES('SYSTEM','summary',?,?, 'succeeded')", (json.dumps(payload), None if has_problem else self.clock()+86400))
                self.db.execute("INSERT OR REPLACE INTO latest VALUES('SYSTEM','summary',?,?)", (str(report["id"]), self.clock()))
            queued_report = reports[-1]["id"] if reports else summary_cursor
            for row in rows:
                row["name"] = core.names.get(row["project"], row["project"] or "维护中心")
                # Never consume an event from an unfinished/unannounced round.
                # Summary is inserted first in this same outbox transaction.
                scheduled_event = row["event"] in {"update_result", "retry_exhausted"} and (row["operation_actor"] == "schedule" or row["event_actor"] == "schedule")
                if scheduled_event and row["report_id"] is not None and row["report_id"] > queued_report:
                    break
                # The job owns its final notice. Consuming the linked operation
                # here is safe even before the job commits its completion audit:
                # that later audit (including reconciliation) has its own cursor.
                if row["latest_result"] and row["event"] == "update_result" and not row["initial_request"] and not row["initial_operation"] and row["project"] in core.history_projects and row["action"] in {"update", "accept", "rollback", "restart"} and row["status"] in {"succeeded", "failed", "unknown", "rolled_back"}:
                    notify = not (row["operation_actor"] == "schedule" and row["report_id"] is not None and row["status"] == "succeeded")
                    self._enqueue(row, notify=notify)
                elif row["event"] == "retry_exhausted" and row["project"] in core.projects and paused.get(row["project"]) == row["request_id"]:
                    self._enqueue({**row, "action": "retry", "status": "failed"})
                elif row["event"] == "initial_check" and row["latest_result"]:
                    self._enqueue({**row, "action": "initial_check", "status": row["event_result"]})
                elif row["event"] == "writes_paused" and row["code"] not in {"startup", "reconciling"} and row["event_actor"] != "schedule" and row["report_id"] is None:
                    self._enqueue({**row, "project": "SYSTEM", "action": "gate", "status": "failed"})
                elif row["event"] == "reconciled":
                    previous = self.db.execute("SELECT signature FROM latest WHERE project='SYSTEM' AND action='gate'").fetchone()
                    if previous and not previous[0].startswith("succeeded:"):
                        self._enqueue({**row, "project": "SYSTEM", "action": "gate", "status": "succeeded", "code": "writes_resumed"})
                self.db.execute("UPDATE cursor SET value=?", (row["id"],))
        if reports:
            with core._transaction() as db:
                db.execute("DELETE FROM schedule_reports WHERE id<? AND finished IS NOT NULL", (reports[-1]["id"] - 100,))
        core.prune_audit(self.db.execute("SELECT value FROM cursor").fetchone()[0])

    def _enqueue(self, row, notify=True):
        # Only strict fields cross the messaging boundary; no gateway response text.
        code = row["code"] if re.fullmatch(r"[a-z][a-z0-9_]{0,79}", row["code"] or "") else "unclassified"
        recovery = metadata.recovery(row.get("recovery"))
        signature = row["status"] + ":" + code + ":" + recovery + ((":" + str(row["request_id"])) if row["action"] in {"retry", "initial_check"} else "")
        previous = self.db.execute("SELECT signature,stamp FROM latest WHERE project=? AND action=?", (row["project"], row["action"])).fetchone()
        failed = row["status"] != "succeeded"
        if failed and previous and previous[0] == signature and self.clock() - previous[1] < 86400:
            return
        # Replace obsolete pending failure notices when the state changes.
        self.db.execute("DELETE FROM outbox WHERE project=? AND action=? AND status!='succeeded'", (row["project"], row["action"]))
        operation = row["request_id"] if re.fullmatch(r"[a-f0-9]{32}", row["request_id"] or "") else "audit-" + str(row["id"])
        try:
            details = metadata.clean(row["project"], json.loads(row.get("details") or "{}"))
        except (ValueError, TypeError):
            details = metadata.clean(row["project"], {})
        payload = {"project": row["project"], "action": row["action"], "status": row["status"],
                   "code": code, "operation": operation, "stamp": row["stamp"],
                   "details": details, "recovery": recovery, "name": row.get("name", row["project"]),
                   "recovered": bool(previous and not previous[0].startswith("succeeded:") and not failed)}
        if notify:
            self.db.execute("INSERT INTO outbox(project,action,payload,expires,status) VALUES(?,?,?,?,?)", (row["project"], row["action"], json.dumps(payload), None if failed else self.clock() + 86400, row["status"]))
        self.db.execute("INSERT OR REPLACE INTO latest VALUES(?,?,?,?)", (row["project"], row["action"], signature, self.clock()))

    def pending(self):
        return [(r[0], json.loads(r[1])) for r in self.db.execute("SELECT id,payload FROM outbox WHERE expires IS NULL OR expires>? ORDER BY id LIMIT 20", (self.clock(),))]

    def sent(self, notice_id):
        with self.db:
            self.db.execute("DELETE FROM outbox WHERE id=?", (notice_id,))

    @staticmethod
    def text(item):
        if item["action"] == "summary":
            stamp = datetime.fromtimestamp(item["stamp"], ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
            lines = ["自动更新本轮摘要（北京时间 " + stamp + "）"]
            statuses = {"succeeded": "更新成功", "update_available": "发现更新，按项目策略仅通知或等待人工批准", "failed": "更新失败", "unknown": "结果待对账", "paused": "故障暂停，需人工恢复", "retry_failed": "复查失败，需人工恢复", "check_failed": "检查失败", "not_checked": "未检查（本轮中断或计划已变更）"}
            for row in item["items"]:
                project = row["project"]
                if not isinstance(project, str) or IDENTIFIER.fullmatch(project) is None:
                    continue
                status = row["status"]
                if status in {"no_update", "recovered_no_update"}:
                    detail = "当前版本号：" + metadata.current_text(project, {"current_version": row.get("version"), "current_versions": row.get("current_versions")}) + "，无更新" + ("；复查通过，已恢复自动更新" if status == "recovered_no_update" else "")
                elif status == "succeeded":
                    before = metadata.current_text(project, {
                        "current_version": row.get("current_version"),
                        "current_versions": row.get("current_versions"),
                    })
                    after = metadata.current_text(project, {
                        "current_version": row.get("target_version") or row.get("version"),
                        "current_versions": row.get("target_versions"),
                    })
                    detail = before + "版 ---> " + after + "版，更新成功"
                else:
                    detail = statuses.get(status, "状态未知") + "（" + metadata.error_text(row.get("code", "unknown")) + "）"
                if row.get("code") in {"plan_stale", "plan_expired", "confirmation_mismatch"}:
                    detail += "；未执行更新，无需恢复"
                lines.append((row.get("name") or NAMES.get(project, project)) + "：" + detail)
            return "\n".join(lines)
        labels = {"initial_check": "接管后首次检查更新", "retry": "自动复查/重试", "update": "更新", "accept": "业务验收", "rollback": "回滚", "restart": "重启", "gate": "全局写操作门禁"}
        statuses = {"succeeded": "成功", "failed": "失败", "unknown": "结果未知，待对账", "rolled_back": "已回滚"}
        lines = [f"项目名称：{item.get('name') or NAMES.get(item['project'], item['project'])}",
                 f"动作：{labels[item['action']]}"]
        if item["project"] != "SYSTEM" and item["action"] in {"initial_check", "update", "rollback"}:
            details = metadata.clean(item["project"], item.get("details"))
            before = metadata.current_text(item["project"], details)
            after = metadata.current_text(item["project"], {
                "current_version": details["target_version"], "current_versions": details["target_versions"]})
            if item["code"] == "no_update":
                lines.append("发现更新：无，当前版本 " + before)
            elif item["action"] == "initial_check" and item["status"] != "succeeded" and not details["target_version"] and not any(details["target_versions"].values()):
                lines.append("当前版本：" + before)
            else:
                lines.append(("发现更新：" if item["action"] == "initial_check" else "") + "版本从 " + before + " -> " + after)
            if item["code"] == "update_available":
                lines.append("执行情况：仅发现更新，按项目策略等待人工处理")
        lines.append("状态：" + statuses.get(item["status"], "未知"))
        if item["status"] != "succeeded":
            lines.append("原因：" + metadata.error_text(item["code"]))
        recovery = metadata.recovery(item.get("recovery"))
        if recovery not in {"unknown", "not_required"}:
            lines.append("恢复状态：" + metadata.RECOVERY[recovery])
        if item["action"] == "retry":
            lines.append("自动更新已暂停。处理故障后发送 /resume " + item["project"] + "，确认恢复自动更新。")
        return "\n".join(lines)

    def close(self):
        self.db.close()
