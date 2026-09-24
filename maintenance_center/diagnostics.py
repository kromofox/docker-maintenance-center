"""Bounded diagnostic logs, never raw gateway exceptions or configuration."""
import re


def clean_logs(data, project):
    if not isinstance(data, dict) or data.get("project") != project:
        return {"available": False}
    result = []
    budget = 48000
    for item in data.get("containers", [])[:2]:
        lines = item.get("lines", str(item.get("logs", "")).splitlines())
        cleaned = []
        private = False
        for value in lines[-200:]:
            line = str(value)[:2000]
            if "-----BEGIN" in line:
                private = True
            sensitive = private or re.search(r"(?i)authorization|bearer|api.?key|token|password|passwd|secret|cookie|[a-z][a-z0-9+.-]*://|sk-[a-z0-9_-]{8,}|[0-9]{6,}:[a-z0-9_-]{20,}", line)
            if "-----END" in line:
                private = False
            line = "[敏感内容已过滤]" if sensitive else line
            if len(line.encode("utf-8")) > budget:
                break
            budget -= len(line.encode("utf-8"))
            cleaned.append(line)
        result.append({"lines": cleaned})
    return {"available": True, "containers": result}
