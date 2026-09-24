"""Strict, non-secret presentation fields shared by plans and notifications."""

import re


RECOVERY = {
    "manual_recovery_verified": "管理员已核对业务恢复，原操作结果未认定成功；自动维护仍暂停",
    "unknown": "未知，需核对宿主证据",
    "not_required": "未触发恢复",
    "rolled_back": "已自动恢复旧镜像和数据",
    "automatic_rollback_succeeded": "双服务自动恢复成功",
    "rollback_failed": "自动恢复失败，需要管理员接管",
    "manual_recovery_required": "需要管理员恢复",
    "manual_intervention_required": "需要管理员接管",
    "manual_rollback_completed": "人工回滚完成",
    "current_restored": "回滚失败后已恢复回滚前状态",
    "rollback_healthy_cleanup_required": "回滚健康检查通过，清理未完成",
    "old_started": "已重新启动旧版本",
    "old_start_failed": "旧版本重新启动失败",
    "previous_image_and_hyper_backup_available": "宿主记录保留旧镜像；未恢复数据，需结合 Hyper Backup 处理",
}


def error_text(code):
    return "查询超时" if code == "query_timeout" else str(code)


def recovery(value):
    return value if isinstance(value, str) and value in RECOVERY else "unknown"


def version(value):
    if isinstance(value, str) and re.fullmatch(r"v?\d{1,8}(?:\.\d{1,8}){1,3}(?:-[A-Za-z0-9][A-Za-z0-9.-]{0,47}|[-.]?(?:alpha|beta|rc|dev|demo|post)\.?\d{0,8})?", value):
        return value
    return None


def versions(project, values):
    values = values if isinstance(values, dict) else {}
    services = ("config-flow", "sub-store") if project == "CONFIGFLOW" else tuple(
        key for key in values if isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", key)
    )[:32] or (project,)
    return {service: version(values.get(service)) for service in services}

def observation(value):
    allowed = {"ok", "read_failed", "image_mismatch", "filtered"}
    return value if isinstance(value, str) and value in allowed else None


def current_text(project, data):
    data = data if isinstance(data, dict) else {}
    values = versions(project, data.get("current_versions"))
    if not any(values.values()):
        return version(data.get("current_version")) or "未知"
    if project == "CONFIGFLOW" and any(values.values()):
        return "ConfigFlow " + (values["config-flow"] or "未知") + " / Sub-Store " + (values["sub-store"] or "未知")
    if len(values) > 1:
        return " / ".join(service + " " + (value or "未知") for service, value in values.items())
    return next(iter(values.values())) or "未知"


def digest(value):
    if isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}|[a-f0-9]{12}", value):
        return value.removeprefix("sha256:")[:12]
    return None


def clean(project, data):
    data = data if isinstance(data, dict) else {}
    incoming = data.get("images")
    incoming = incoming if isinstance(incoming, (list, tuple)) and len(incoming) <= 32 else []
    services = tuple(dict.fromkeys(row.get("service") for row in incoming if isinstance(row, dict)
        and isinstance(row.get("service"), str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", row["service"])))
    if not services:
        services = ("config-flow", "sub-store") if project == "CONFIGFLOW" else (project,)
    images = []
    for service in services:
        matches = [row for row in incoming if isinstance(row, dict) and row.get("service") == service]
        row = matches[0] if len(matches) == 1 else {}
        images.append({"service": service, "current": digest(row.get("current")), "target": digest(row.get("target"))})
    observed = data.get("version_observation")
    observed = observed if isinstance(observed, dict) else {}
    return {
        "current_version": version(data.get("current_version")),
        "target_version": version(data.get("target_version")),
        "current_versions": versions(project, data.get("current_versions")),
        "target_versions": versions(project, data.get("target_versions")),
        "version_observation": {
            "before": observation(observed.get("before")),
            "after": observation(observed.get("after")),
        },
        "images": images,
    }


def from_plan(project, data):
    if project == "CONFIGFLOW":
        current = data.get("current_images", {})
        target = data.get("target_images", {})
        images = [{"service": service,
                   "current": current.get(service) if isinstance(current, dict) else None,
                   "target": target.get(service) if isinstance(target, dict) else None}
                  for service in ("config-flow", "sub-store")]
    else:
        images = [{"service": project, "current": data.get("current_image_id"), "target": data.get("target_image_id")}]
    return clean(project, {"current_version": data.get("current_version"), "target_version": data.get("target_version"), "images": images})


def lines(project, data):
    data = clean(project, data)
    result = [
        "更新前版本：" + current_text(project, {
            "current_version": data["current_version"],
            "current_versions": data["current_versions"],
        }),
        "目标版本：" + current_text(project, {
            "current_version": data["target_version"],
            "current_versions": data["target_versions"],
        }),
    ]
    for row in data["images"]:
        result.append(f"{row['service']} 镜像：{row['current'] or '未知'} → {row['target'] or '未知'}")
    return result
