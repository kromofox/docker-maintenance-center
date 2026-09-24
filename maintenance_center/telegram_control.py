"""Deterministic Telegram commands; no free-form interpreter or shell."""

import secrets
import time
from dataclasses import dataclass, field

from .core import MaintenanceError
from . import metadata


@dataclass
class Reply:
    text: str
    buttons: list = field(default_factory=list)


class TelegramControl:
    def __init__(self, core, store, clock=time.time):
        self.core, self.store, self.clock = core, store, clock
        self.pending = {}

    def _button(self, title, action, **values):
        now = self.clock()
        self.pending = {k: v for k, v in self.pending.items() if v[0] > now}
        if len(self.pending) >= 100:
            raise MaintenanceError("telegram_menu_limit")
        handle = secrets.token_urlsafe(18)
        self.pending[handle] = (now + 300, self.store.state()["revision"], action, values)
        return (title, handle)

    def _allowed(self, user_id, chat_id, chat_type):
        if not self.store.authorized(user_id, chat_id, chat_type):
            raise MaintenanceError("telegram_access_denied")

    def command(self, text, user_id, chat_id, chat_type):
        parts = text.split() if isinstance(text, str) and len(text) <= 512 else []
        if parts and parts[0] == "/bind" and len(parts) == 2:
            self.store.bind(parts[1], user_id, chat_id, chat_type)
            return Reply("管理员绑定完成。")
        self._allowed(user_id, chat_id, chat_type)
        if parts in [["/start"], ["/status"]]:
            state = self.core.state()
            lines = ["白名单 Docker 维护中心", "写操作状态：" + ("可用" if state["gate"] == "ready" else "暂停")]
            for p in self.core.projects:
                policy = self.core.project_policy(p)
                mode = "故障待复查（下一轮）" if p in state["retry_pending"] else "故障暂停（需人工恢复）" if p in state["paused_projects"] else "仅检查通知" if policy == "notify" else "人工批准" if policy == "manual" else "自动更新" if state["enabled"] and p in state["targets"] else "周期暂停或未加入计划"
                lines.append(f"{self.core.names[p]}（{p}）：{mode}")
            return Reply("\n".join(lines), [self._button("检查 " + self.core.names[p], "check", project=p) for p in self.core.projects] + [self._button("自动更新设置", "settings"), self._button("项目管理", "projects")])
        if parts == ["/projects"]:
            return self.projects_menu()
        if parts == ["/check"]:
            return Reply("选择要检查更新的项目：", [self._button("检查 " + self.core.names[p], "check", project=p) for p in self.core.projects])
        if parts and parts[0] == "/check" and len(parts) == 2:
            return self.plan(parts[1].upper(), "update")
        if parts == ["/resume"]:
            state = self.core.state()
            return Reply("选择要恢复自动更新的项目：" if state["paused_projects"] else "没有故障暂停的项目。",
                         [self._button("恢复 " + self.core.names[p], "resume", project=p) for p in state["paused_projects"]])
        if len(parts) == 2 and parts[0] == "/resume":
            return self.resume(parts[1].upper())
        if parts == ["/set"]:
            return self.settings()
        if parts and parts[0] == "/set" and len(parts) == 3:
            try:
                hours = int(parts[1])
            except ValueError:
                raise MaintenanceError("invalid_schedule") from None
            targets = parts[2].split(",")
            if not 1 <= hours <= 720 or any(p not in self.core.projects for p in targets):
                raise MaintenanceError("invalid_schedule")
            return self.settings({**self.core.state(), "hours": hours, "targets": [p for p in self.core.projects if p in targets], "enabled": True})
        return Reply("可用命令：/projects（项目管理）、/resume、/status、/check、/check 项目标识、/set、/set 小时 项目标识列表（英文逗号分隔）。")

    def progress(self, user_id, chat_id, chat_type, text=None, handle=None):
        """Validate presentation intent without consuming or authorizing a write."""
        self._allowed(user_id, chat_id, chat_type)
        if handle is not None:
            item = self.pending.get(handle)
            if not item or item[0] <= self.clock() or item[1] != self.store.state()["revision"]:
                return None
            action, values = item[2], item[3]
            if action == "check":
                return "正在检查 " + self.core.names.get(values["project"], values["project"]) + "……请稍候。"
            if action == "approve":
                return "正在执行已批准的操作……完成后会更新此消息，请勿重复操作。"
            if action == "registry_preview":
                return "正在预检所选 Compose 项目……此步骤不会接管或更新业务。"
        elif isinstance(text, str) and len(text) <= 512:
            parts = text.split()
            if len(parts) == 2 and parts[0] == "/check" and parts[1].upper() in self.core.projects:
                return "正在检查 " + self.core.names[parts[1].upper()] + "……请稍候。"
        return None

    def plan(self, project, action):
        if action != "update":
            raise MaintenanceError("action_not_allowed")
        ref = self.core.prepare_manual(project, "telegram", action)
        if ref is None:
            # Fresh, validated read-only metadata. An unavailable version must
            # not erase an already successful check or expose transport errors.
            current_version = None
            try:
                observed = self.core.gateway.current_metadata(project)
                current_version = metadata.current_text(project, observed)
            except Exception:
                pass
            return Reply(f"{self.core.names[project]}：当前版本 {current_version or '未知'}，没有更新。")
        boundary = "保留一个旧版本恢复点；只有经过验证的专用备份才支持数据恢复，豁免备份不保证数据回滚。"
        details = "\n".join(metadata.lines(project, self.core.plan_view(ref, "telegram")["details"]))
        return Reply(f"{self.core.names[project]}（{project}）\n更新确认\n{details}\n{boundary}",
                     [self._button("批准", "approve", ref=ref), self._button("拒绝", "reject", ref=ref)])

    def resume(self, project):
        if project not in self.core.projects:
            raise MaintenanceError("invalid_project")
        state = self.core.state()
        if project not in state["paused_projects"]:
            return Reply(self.core.names[project] + "：没有故障暂停。")
        return Reply(self.core.names[project] + "：请确认已核对业务状态并处理故障。恢复后按现有计划检查，不立即更新；未启用或未加入计划的项目仍不会自动更新。",
                     [self._button("确认恢复自动更新", "confirm_resume", project=project, event_ref=state["pause_refs"][project])])

    def settings(self, draft=None):
        state = draft or self.core.state()
        values = {k: state[k] for k in ("targets", "hours", "enabled", "revision")}
        lines = ["自动更新计划确认", f"周期：{values['hours']} 小时", "状态：" + ("启用" if values["enabled"] else "暂停"),
                 "项目：" + ("、".join(self.core.names[p] for p in values["targets"]) or "无"), "仅自动策略项目有更新直接执行；其余按项目策略检查通知。"]
        buttons = [self._button(("已选 " if p in values["targets"] else "未选 ") + self.core.names[p], "toggle_project", draft=values, project=p) for p in self.core.projects]
        buttons += [self._button("暂停" if values["enabled"] else "启用", "toggle_enabled", draft=values),
                    self._button("删除计划", "delete_schedule", draft=values),
                    self._button("确认保存", "save_schedule", draft=values)]
        return Reply("\n".join(lines), buttons)

    def callback(self, handle, user_id, chat_id, chat_type):
        self._allowed(user_id, chat_id, chat_type)
        item = self.pending.pop(handle, None)
        if not item or item[0] <= self.clock() or item[1] != self.store.state()["revision"]:
            raise MaintenanceError("telegram_menu_expired")
        _, _, action, values = item
        if action == "close_menu":
            return Reply("菜单已关闭。")
        if action == "projects" or action.startswith("registry_"):
            return self.project_callback(action, values)
        if action == "check":
            return self.plan(values["project"], "update")
        if action == "resume":
            return self.resume(values["project"])
        if action == "confirm_resume":
            self.core.resume_project(values["project"], "telegram", values["event_ref"])
            return Reply(self.core.names[values["project"]] + "：已解除故障暂停，将按现有自动计划检查。")
        if action == "settings":
            return self.settings()
        if action == "approve":
            outcome = self.core.approve(values["ref"], "telegram")
            return Reply("操作完成。" if outcome.status == "succeeded" else "操作未完成，请在 Web 核对操作记录。")
        if action == "reject":
            self.core.reject(values["ref"], "telegram")
            return Reply("已拒绝，计划已失效。")
        draft = dict(values["draft"])
        if draft["revision"] != self.core.state()["revision"]:
            raise MaintenanceError("stale_schedule")
        if action == "toggle_project":
            draft["targets"] = [p for p in self.core.projects if (p in draft["targets"]) != (p == values["project"])]
        elif action == "toggle_enabled":
            draft["enabled"] = not draft["enabled"]
        elif action == "delete_schedule":
            draft.update(enabled=False, targets=[])
        elif action == "save_schedule":
            self.core.configure(draft["targets"], draft["hours"], draft["enabled"], draft["revision"], "telegram")
            return Reply("自动更新计划已保存。")
        return self.settings(draft)

    def projects_menu(self):
        self.core.management.supported()
        return Reply("项目管理：仅接管已有 Compose 项目，不部署新应用。复杂备份范围与健康探测请在 Web 高级设置中配置。",
                     [self._button("添加已有项目", "registry_discover")] +
                     [self._button(self.core.names[p], "registry_project", project=p) for p in self.core.projects])

    def project_callback(self, action, values):
        manager = self.core.management
        gateway = self.core.gateway
        if action == "projects":
            return self.projects_menu()
        if action == "registry_discover":
            result = manager.discover()
            text = ("选择要接管的 Compose 项目（整个服务组）。需要选择部分服务请使用 Web。"
                    if result["candidates"] else "没有尚未接管的 Compose 项目。")
            return Reply(text,
                         [self._button(item["name"], "registry_preview", compose_path=item["compose_path"],
                                       services=item["services"]) for item in result["candidates"]] +
                         [self._button("关闭菜单", "close_menu")])
        if action == "registry_preview":
            preview = manager.preview(values["compose_path"], values["services"])
            definition = preview["definition"]
            params = {"project": definition["id"], "preview": preview, "revision": gateway.registry_revision}
            text = f"预检：{definition['name']}\n服务：{'、'.join(definition['services'])}\n默认自动策略：确认后立即检查，有更新即执行，可能中断业务。即使全局周期人工暂停，此次授权仍有效；不改变下一轮时间。"
            if not preview["backup_supported"]:
                return Reply(text + "\n没有经过验证的专用备份。继续必须明确豁免，可能无法恢复业务数据。",
                             [self._button("查看备份豁免风险", "registry_risk", **params),
                              self._button("取消", "projects")])
            return Reply(text + "\n使用预检提供的专用备份范围。修改范围请到 Web。",
                         [self._button("确认接管并立即检查", "registry_enroll", exempt=False, **params),
                          self._button("取消", "projects")])
        if action == "registry_risk":
            return Reply("再次确认：明确豁免更新前备份。保留旧镜像不等于可恢复数据。确认后自动检查并在有更新时执行。",
                         [self._button("接受风险并接管", "registry_enroll", exempt=True, **values),
                          self._button("取消", "projects")])
        if action == "registry_enroll":
            preview = values["preview"]
            if preview["expires_at"] <= self.clock():
                raise MaintenanceError("preview_expired")
            definition = preview["definition"]
            manager.change("enroll", values["project"], "telegram", values["revision"],
                           token=preview["token"], name=definition["name"], policy="auto",
                           backup_exempt=values["exempt"], backup_paths=definition["backup_paths"],
                           health=definition["health"])
            return Reply("已接管，首次检查已排队。执行锁忙时等待，不会并发修改业务；结果见 Web 项目管理与通知。")
        project = values["project"]
        self.core._project(project)
        definition = gateway.catalog[project]
        if action == "registry_project":
            return Reply(f"{definition['name']}\n策略：{definition['policy']}\n解除接管不会停止容器或删除数据、备份、历史。",
                         [self._button(label, "registry_policy", project=project, policy=policy,
                                       revision=gateway.registry_revision)
                          for policy, label in [("auto", "改为自动更新"), ("manual", "改为人工批准"), ("notify", "改为仅通知")]] +
                         [self._button("解除接管", "registry_remove", project=project,
                                       revision=gateway.registry_revision),
                          self._button("关闭菜单", "close_menu")])
        if action == "registry_policy":
            return Reply(f"确认将 {definition['name']} 策略改为 {values['policy']}？不改变全局下一轮时间。",
                         [self._button("确认策略", "registry_save", **values), self._button("取消", "projects")])
        if action == "registry_save":
            manager.change("configure", project, "telegram", values["revision"], policy=values["policy"],
                           backup_exempt=definition["backup_exempt"], backup_paths=definition["backup_paths"],
                           health=definition["health"])
            return Reply("项目策略已保存。")
        if action == "registry_remove":
            return Reply(f"确认解除 {definition['name']} 接管？撤销旧计划、取消尚未执行的首次任务；保留运行容器、数据、备份与历史。有未决操作时拒绝解除。",
                         [self._button("确认解除接管", "registry_remove_confirm", **values),
                          self._button("取消", "projects")])
        if action == "registry_remove_confirm":
            manager.change("remove", project, "telegram", values["revision"])
            return Reply("已解除接管；业务容器、数据、备份及历史保留。")
        raise MaintenanceError("action_not_allowed")
