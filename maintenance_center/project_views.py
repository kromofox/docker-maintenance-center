"""Authenticated project-management pages using the existing session/CSRF boundary."""
import asyncio
import secrets
import time

from fastapi import Request
from fastapi.responses import RedirectResponse

from .core import MaintenanceError


def install_project_routes(app, render, form):
    previews = {}

    def settings(data):
        policy = str(data.get("policy", "auto"))
        if policy not in {"auto", "manual", "notify"}:
            raise MaintenanceError("invalid_policy")
        exempt = data.get("backup_exempt") == "yes"
        if exempt and data.get("confirm_risk") != "yes":
            raise MaintenanceError("backup_exemption_confirmation_required")
        health = {"mode": str(data.get("health_mode", "docker"))}
        if health["mode"] == "http":
            health["url"] = str(data.get("health_url", ""))
        return {"policy": policy, "backup_exempt": exempt,
                "backup_paths": data.getlist("backup_paths"), "health": health}

    def revision(data):
        try:
            return int(data["registry_revision"])
        except (KeyError, ValueError, TypeError):
            raise MaintenanceError("stale_registry") from None

    @app.get("/projects")
    async def projects(request: Request):
        management = app.state.core.management
        return render(request, "registry", registry=management.overview())

    @app.get("/projects/add")
    async def add(request: Request):
        candidates = await asyncio.to_thread(app.state.core.management.discover)
        return render(request, "registry_add", discovery=candidates,
                      roots=app.state.core.gateway.allowed_roots)

    @app.post("/projects/preview")
    async def preview(request: Request):
        data = await form(request)
        services = data.getlist("services")
        if not services:
            services = [value.strip() for value in str(data.get("service_names", "")).split(",") if value.strip()]
        result = await asyncio.to_thread(app.state.core.management.preview,
                                       str(data.get("compose_path", "")), services)
        now = time.time()
        for handle in list(previews):
            if previews[handle]["expires_at"] <= now:
                del previews[handle]
        if len(previews) >= 100:
            raise MaintenanceError("preview_limit")
        handle = secrets.token_urlsafe(24)
        result = dict(result, registry_revision=app.state.core.gateway.registry_revision)
        previews[handle] = result
        return render(request, "registry_preview", preview=result, handle=handle)

    @app.post("/projects/enroll")
    async def enroll(request: Request):
        data = await form(request)
        if data.get("confirm_enroll") != "yes":
            raise MaintenanceError("enrollment_confirmation_required")
        values = settings(data)
        preview = previews.pop(str(data.get("handle", "")), None)
        if preview is None or preview["expires_at"] <= time.time():
            raise MaintenanceError("preview_expired")
        if revision(data) != preview["registry_revision"]:
            raise MaintenanceError("stale_registry")
        project = preview["definition"]["id"]
        await asyncio.to_thread(app.state.core.management.change, "enroll", project, "web",
                                preview["registry_revision"], token=preview["token"],
                                name=str(data.get("name", "")), **values)
        return RedirectResponse("/projects", status_code=303)

    @app.get("/projects/{project}/settings")
    async def edit(request: Request, project: str):
        app.state.core._project(project)
        definition = app.state.core.gateway.catalog[project]
        return render(request, "registry_settings", definition=definition,
                      registry_revision=app.state.core.gateway.registry_revision)

    @app.post("/projects/{project}/settings")
    async def save(request: Request, project: str):
        data = await form(request)
        app.state.core._project(project)
        await asyncio.to_thread(app.state.core.management.change, "configure", project, "web", revision(data), **settings(data))
        return RedirectResponse("/projects", status_code=303)

    @app.get("/projects/{project}/remove")
    async def remove_page(request: Request, project: str):
        app.state.core._project(project)
        return render(request, "registry_remove", definition=app.state.core.gateway.catalog[project],
                      registry_revision=app.state.core.gateway.registry_revision)

    @app.post("/projects/{project}/remove")
    async def remove(request: Request, project: str):
        data = await form(request)
        if data.get("confirm_remove") != "yes":
            raise MaintenanceError("removal_confirmation_required")
        await asyncio.to_thread(app.state.core.management.change, "remove", project, "web", revision(data))
        return RedirectResponse("/projects", status_code=303)
