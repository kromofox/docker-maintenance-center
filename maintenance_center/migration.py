"""Validate selected legacy schedule fields without importing approvals or secrets."""

import json

from .core import PROJECTS


def schedule_from_legacy(data):
    if data is None:
        return {"targets": [], "hours": 2, "enabled": False}
    if not isinstance(data, dict) or data.get("status") not in {"enabled", "paused"}:
        raise ValueError("legacy_schedule_status_requires_review")
    targets = data.get("targets")
    seconds = data.get("interval_seconds")
    if (data.get("schedule_type") != "interval" or type(seconds) is not int
            or seconds % 3600 or not 3600 <= seconds <= 720 * 3600
            or not isinstance(targets, list) or not targets
            or any(not isinstance(p, str) or p not in PROJECTS for p in targets)
            or len(targets) != len(set(targets))):
        raise ValueError("legacy_schedule_invalid")
    return {"targets": [p for p in PROJECTS if p in targets], "hours": seconds // 3600,
            "enabled": data["status"] == "enabled"}


def apply_schedule(core, selected):
    """Caller must stop the legacy writer and hold the new controller lock."""
    if (not isinstance(selected, dict) or set(selected) != {"targets", "hours", "enabled"}
            or type(selected["enabled"]) is not bool or type(selected["hours"]) is not int
            or type(selected["targets"]) is not list):
        raise ValueError("invalid_selected_schedule")
    state = core.state()
    if state["enabled"] or state["targets"]:
        raise ValueError("destination_schedule_not_empty")
    with core._db_lock:
        if core.db.execute("SELECT 1 FROM operations LIMIT 1").fetchone():
            raise ValueError("destination_has_operations")
    checked = schedule_from_legacy({"status": "enabled" if selected["enabled"] else "paused",
                                   "targets": selected["targets"], "schedule_type": "interval",
                                   "interval_seconds": selected["hours"] * 3600}) if selected["targets"] else schedule_from_legacy(None)
    if checked != selected:
        raise ValueError("invalid_selected_schedule")
    with core._transaction() as db:
        if db.execute("SELECT 1 FROM operations LIMIT 1").fetchone():
            raise ValueError("destination_has_operations")
        changed = db.execute("UPDATE control SET revision=revision+1,targets=?,hours=?,enabled=?,next_run=? WHERE id=1 AND revision=? AND enabled=0 AND targets='[]'",
                             (json.dumps(checked["targets"]), checked["hours"], checked["enabled"],
                              core.clock() + checked["hours"] * 3600 if checked["enabled"] else None, state["revision"])).rowcount
        if changed != 1:
            raise ValueError("migration_state_changed")
        core._audit(db, "system", "schedule_configured", "legacy_schedule_migrated")
    return core.state()
