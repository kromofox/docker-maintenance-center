"""Persistent shadow samples. Evidence never authorizes a mode switch."""

import asyncio
import hashlib
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path

from .core import PROJECTS


class ShadowObserver:
    INTERVAL = 3600
    MAX_GAP = 4200

    def __init__(self, directory, gateway, clock=time.time, monotonic=time.monotonic, mode="shadow"):
        if mode not in {"shadow", "active"}:
            raise ValueError("invalid_observation_mode")
        self.mode = mode
        self.path = Path(directory) / ("shadow.sqlite3" if mode == "shadow" else "monitor.sqlite3")
        self.gateway, self.clock, self.monotonic = gateway, clock, monotonic
        self.run_id = uuid.uuid4().hex
        self.window_start, self.last_wall, self.last_mono = None, None, None
        self.window_start_mono = None
        self.count = 0
        self.stop_event = asyncio.Event()
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS samples (id INTEGER PRIMARY KEY, run_id TEXT NOT NULL, time REAL NOT NULL, ok INTEGER NOT NULL, data TEXT NOT NULL)")
        os.chmod(self.path, 0o600)

    def connect(self):
        # Connections are confined to each worker invocation.
        from contextlib import closing, contextmanager

        @contextmanager
        def connection():
            with closing(sqlite3.connect(self.path)) as db:
                with db:
                    yield db
        return connection()

    def sample(self):
        rows = []
        projects = tuple(p for p, d in self.gateway.catalog.items() if d["active"]) if hasattr(self.gateway, "catalog") else PROJECTS
        for project in projects:
            try:
                release = self.gateway.release_check(project)
                status = self.gateway.query(project)
                health = self.gateway.query(project, "health")
                logs = self.gateway.query(project, "logs", 20)
                operation = self.gateway.operation_status(project)
                containers = status["containers"]
                current = {(item["service"] if hasattr(self.gateway, "catalog") or project == "CONFIGFLOW" else project): item["image_id"] for item in containers}
                ok = (len(containers) == len(release["current_images"]) and current == release["current_images"]
                      and health["overall"] in {"healthy", "running_no_probe"}
                      and operation.status in {"idle", "succeeded", "failed"}
                      and len(logs["containers"]) == len(containers))
                rows.append({"project": project, "ok": ok, "health": health["overall"],
                             "release": release, "last_host_operation": operation.status,
                             "log_sha256": hashlib.sha256(json.dumps(logs, sort_keys=True).encode()).hexdigest()})
            except Exception:
                rows.append({"project": project, "ok": False, "error": "observation_unavailable"})
        now, mono = self.clock(), self.monotonic()
        ok = all(row["ok"] for row in rows)
        continuous = (self.last_wall is not None and 0 < now - self.last_wall <= self.MAX_GAP
                      and 0 < mono - self.last_mono <= self.MAX_GAP
                      and abs((now - self.last_wall) - (mono - self.last_mono)) < 60)
        if not ok:
            self.window_start, self.count = None, 0
            self.window_start_mono = None
        elif self.window_start is None or not continuous:
            self.window_start, self.count = now, 1
            self.window_start_mono = mono
        else:
            self.count += 1
        self.last_wall, self.last_mono = now, mono
        elapsed = max(0, min(now - self.window_start, mono - self.window_start_mono)) if self.window_start is not None else 0
        evidence = {"projects": rows, "window_start": self.window_start, "sample_count": self.count,
                    "elapsed_seconds": elapsed,
                    "mode": self.mode,
                    "ready_for_review": bool(self.mode == "shadow" and ok and elapsed >= 86400 and self.count >= 25)}
        with self.connect() as db:
            db.execute("INSERT INTO samples(run_id,time,ok,data) VALUES(?,?,?,?)", (self.run_id, now, ok, json.dumps(evidence, sort_keys=True)))
            db.execute("DELETE FROM samples WHERE time < ?", (now - 180 * 86400,))
        return evidence

    async def run(self):
        while not self.stop_event.is_set():
            try:
                await asyncio.to_thread(self.sample)
            except Exception:
                self.window_start, self.count = None, 0
                self.window_start_mono = None
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=self.INTERVAL)
            except asyncio.TimeoutError:
                pass

    async def stop(self, task):
        self.stop_event.set()
        await asyncio.shield(task)
