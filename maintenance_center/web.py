"""Authenticated UI with explicit demo and NAS runtime configuration."""

import argparse
import asyncio
import hmac
import json
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .core import Core, MaintenanceError, AUDIT_ACTIONS, AUDIT_RESULTS
from .demo import DemoGateway
from .project_views import install_project_routes
from .auth import Auth
from .scheduler import start_scheduler
from .observer import ShadowObserver
from .telegram_store import TelegramStore
from .telegram_runtime import TelegramRuntime
from . import metadata, __version__

AUDIT_LABELS = {"update": "更新", "accept": "业务验收", "rollback": "回滚", "restart": "重启",
                "schedule_configured": "保存自动计划", "project_resumed": "恢复自动更新",
                "writes_paused": "暂停写操作", "reconciled": "完成对账",
                "manual_plan_created": "创建人工计划", "manual_plan_rejected": "拒绝人工计划"}
AUDIT_LABELS.update({"login": "登录", "logout": "退出登录", "initialize": "初始化账户", "recover": "恢复账户",
                     "telegram_token": "配置 Bot Token", "telegram_bind": "发起管理员绑定", "telegram_unbind": "解除管理员绑定",
                     "telegram_delete": "删除 Bot Token", "project_checked": "检查更新"})
AUDIT_LABELS.update({"project_enroll": "接管项目", "project_configure": "修改项目策略",
                     "project_remove": "解除接管", "initial_check": "首次检查", "update_available": "发现更新"})

def create_demo_app(directory: Path, telegram_key: Path | None = None, port: int = 8767):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid_demo_port")
    return create_app(directory, DemoGateway(), telegram_key, port=port)


def create_app(directory, gateway, telegram_key=None, port=8767, address="127.0.0.1", mode="demo"):
    if mode not in {"demo", "shadow", "active"}:
        raise ValueError("invalid_runtime_mode")
    shadow = mode == "shadow"
    root = Path(__file__).parent
    templates = Jinja2Templates(directory=str(root / "templates"))
    templates.env.filters["shanghai"] = lambda value: datetime.fromtimestamp(value, ZoneInfo("Asia/Shanghai")).strftime("%Y-%m-%d %H:%M:%S")
    templates.env.filters["error_text"] = metadata.error_text

    @asynccontextmanager
    async def lifespan(app):
        core = Core(directory, gateway)
        app.state.core = core
        app.state.jobs = {}
        auth, scheduler, telegram_store, telegram = None, None, None, None
        observer, observer_task = None, None
        try:
            auth = app.state.auth = Auth(directory)
            telegram_store = app.state.telegram_store = TelegramStore(directory, None if shadow else telegram_key)
            telegram = app.state.telegram = TelegramRuntime(core, telegram_store, directory, demo=mode == "demo")
            # The simulated remote resets on start; uncertain writes stay paused.
            await asyncio.to_thread(core.reconcile)
            if not shadow:
                scheduler = app.state.scheduler = start_scheduler(core)
                telegram.start()
            else:
                core._pause_all("shadow_readonly")
            if mode in {"shadow", "active"} and getattr(gateway, "observe_enabled", False):
                observer = app.state.observer = ShadowObserver(directory, gateway, mode=mode)
                observer_task = asyncio.create_task(observer.run())
            yield
        finally:
            try:
                for job in app.state.jobs.values():
                    await asyncio.shield(job["task"])
                if scheduler is not None:
                    await asyncio.to_thread(scheduler.shutdown, wait=True)
                if observer is not None:
                    await observer.stop(observer_task)
            finally:
                try:
                    if telegram is not None:
                        await telegram.stop()
                finally:
                    try:
                        if telegram_store is not None:
                            telegram_store.close()
                    finally:
                        try:
                            if auth is not None:
                                await asyncio.to_thread(auth.close)
                        finally:
                            await asyncio.to_thread(core.close)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=str(root / "static")), name="static")

    @app.middleware("http")
    async def boundary(request, call_next):
        host = request.headers.get("host", "")
        allowed_hosts = {f"{address}:{port}"}
        if mode == "demo":
            allowed_hosts.update({f"localhost:{port}", "testserver"})
        if host not in allowed_hosts:
            return HTMLResponse("访问地址不匹配", status_code=400)
        if request.method == "POST":
            if shadow and request.url.path not in {"/login", "/initialize", "/recover", "/logout"}:
                return HTMLResponse("只读影子模式（shadow_readonly）", status_code=403)
            if request.headers.get("origin") != "http://" + host:
                return HTMLResponse("请求来源不匹配", status_code=403)
            chunks, size = [], 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > 16384:
                    return HTMLResponse("请求过大", status_code=413)
                chunks.append(chunk)
            request._body = b"".join(chunks)
        token = request.cookies.get("session", "")
        request.state.authenticated = await asyncio.to_thread(app.state.auth.check, token)
        request.state.csrf_token = token if request.state.authenticated else request.cookies.get("visitor", "")
        if not request.state.csrf_token or len(request.state.csrf_token) > 100:
            request.state.csrf_token = secrets.token_urlsafe(32)
        public = request.url.path in {"/login", "/initialize", "/recover"} or request.url.path.startswith("/static/")
        if not public and not request.state.authenticated:
            response = RedirectResponse("/login", status_code=303)
        else:
            response = await call_next(request)
            actions = {"/login": "login", "/logout": "logout", "/initialize": "initialize", "/recover": "recover",
                       "/telegram/token": "telegram_token", "/telegram/bind": "telegram_bind",
                       "/telegram/unbind": "telegram_unbind", "/telegram/delete": "telegram_delete"}
            if request.method == "POST" and request.url.path in actions:
                await asyncio.to_thread(app.state.core.record_event, "web", actions[request.url.path], response.status_code < 400)
        if not request.state.authenticated:
            response.set_cookie("visitor", request.state.csrf_token, httponly=True, samesite="strict", max_age=600)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        return response

    def render(request, page, **context):
        return templates.TemplateResponse(request=request, name="index.html", context={
            "page": page, "csrf": app.state.auth.csrf(request.state.csrf_token), "names": app.state.core.names, "projects": app.state.core.projects,
            "historical_projects": app.state.core.history_projects,
            "catalog": getattr(gateway, "catalog", {}),
            "authenticated": request.state.authenticated,
            "mode": mode, "version": __version__,
            "recovery_labels": metadata.RECOVERY,
            "audit_labels": AUDIT_LABELS,
            "state": app.state.core.state() if request.state.authenticated else {}, **context})

    async def form(request):
        data = await request.form()
        if not hmac.compare_digest(str(data.get("csrf", "")).encode(), app.state.auth.csrf(request.state.csrf_token).encode()):
            raise MaintenanceError("csrf_invalid")
        return data

    @app.exception_handler(MaintenanceError)
    async def failure(request, error):
        response = render(request, "message", message="操作未执行或尚未完成", detail=metadata.error_text(str(error)))
        response.status_code = 403 if str(error) == "csrf_invalid" else 400
        return response

    @app.get("/login", response_class=HTMLResponse)
    @app.get("/initialize", response_class=HTMLResponse)
    @app.get("/recover", response_class=HTMLResponse)
    async def credentials_page(request: Request):
        return render(request, request.url.path[1:])

    @app.post("/login")
    async def login(request: Request):
        data = await form(request)
        token = await asyncio.to_thread(app.state.auth.login, str(data.get("name", "")), str(data.get("password", "")), request.client.host if request.client else "unknown")
        response = RedirectResponse("/", status_code=303)
        response.set_cookie("session", token, httponly=True, samesite="strict")
        response.delete_cookie("visitor")
        return response

    @app.post("/initialize")
    @app.post("/recover")
    async def password(request: Request):
        data = await form(request)
        await asyncio.to_thread(app.state.auth.set_password, str(data.get("code", "")), str(data.get("name", "")), str(data.get("password", "")), request.url.path[1:])
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie("session")
        return response

    @app.post("/logout")
    async def logout(request: Request):
        await form(request)
        await asyncio.to_thread(app.state.auth.logout, request.cookies.get("session", ""))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie("session")
        return response

    @app.get("/", response_class=HTMLResponse)
    async def overview(request: Request):
        items = [await project_state(p) for p in app.state.core.projects]
        state = app.state.core.state()
        return render(request, "overview", items=items,
                      running_count=sum(item["overall"] in {"healthy", "running_no_probe"} for item in items),
                      automatic_count=sum(app.state.core.project_policy(p) == "auto" and p not in state["paused_projects"]
                                          for p in state["targets"]) if state["enabled"] else 0)

    async def project_state(project):
        try:
            item = await asyncio.to_thread(gateway.query, project)
            health = await asyncio.to_thread(gateway.query, project, "health")
            return {**item, "overall": health.get("overall", "unknown")}
        except MaintenanceError:
            return {"project": project, "overall": "unavailable", "containers": []}

    @app.get("/project/{project}", response_class=HTMLResponse)
    async def detail(request: Request, project: str, tail: int = 50):
        app.state.core._project(project)
        if tail not in {20, 50, 100, 200}:
            raise MaintenanceError("invalid_log_tail")
        item = await project_state(project)
        try:
            logs = await asyncio.to_thread(gateway.query, project, "logs", tail)
        except MaintenanceError:
            logs = {"containers": [{"logs": "日志暂时不可用（query_unavailable）"}]}
        return render(request, "project", project=project, item=item, logs=logs, tail=tail)

    @app.post("/plan/{project}/{action}", response_class=HTMLResponse)
    async def plan(request: Request, project: str, action: str):
        await form(request)
        ref = await asyncio.to_thread(app.state.core.prepare_manual, project, "web", action)
        if ref is None:
            return render(request, "message", message="当前没有更新", detail=app.state.core.names[project])
        return render(request, "plan", project=project, action=action, ref=ref,
                      plan=app.state.core.plan_view(ref, "web"))

    @app.post("/approve", response_class=HTMLResponse)
    async def approve(request: Request):
        data = await form(request)
        if mode == "active":
            if any(not job["task"].done() for job in app.state.jobs.values()):
                raise MaintenanceError("operation_busy")
            ref = str(data.get("ref", ""))
            app.state.core.plan_view(ref, "web")
            handle = secrets.token_hex(16)
            job = {"status": "running", "code": "submitted"}
            async def execute():
                try:
                    outcome = await asyncio.to_thread(app.state.core.approve, ref, "web")
                    job.update(status=outcome.status, code=outcome.code)
                except MaintenanceError as error:
                    job.update(status="failed", code=app.state.core._code(str(error)))
                except Exception:
                    # The persisted core operation remains authoritative after a lost result.
                    job.update(status="unknown", code="operation_result_unknown")
            app.state.jobs = {key: value for key, value in app.state.jobs.items() if not value["task"].done()}
            job["task"] = asyncio.create_task(execute())
            app.state.jobs[handle] = job
            return RedirectResponse("/operation/" + handle, status_code=303)
        result = await asyncio.to_thread(app.state.core.approve, str(data.get("ref", "")), "web")
        return render(request, "message", message="操作完成" if result.status == "succeeded" else "操作未完成", detail=result.code)

    @app.get("/operation/{handle}")
    async def operation(request: Request, handle: str):
        job = app.state.jobs.get(handle)
        return render(request, "operation", operation=job or {"status": "unknown", "code": "operation_view_expired"},
                      pending=app.state.core.recovery_view(), failures=app.state.core.failure_history())

    @app.get("/schedule", response_class=HTMLResponse)
    async def schedule(request: Request):
        return render(request, "schedule")

    @app.post("/schedule")
    async def save_schedule(request: Request):
        data = await form(request)
        try:
            hours, revision = int(str(data.get("hours", ""))), int(str(data.get("revision", "")))
        except ValueError:
            raise MaintenanceError("invalid_schedule") from None
        await asyncio.to_thread(app.state.core.configure, data.getlist("projects"), hours, data.get("enabled") == "yes", revision, "web")
        return RedirectResponse("/schedule", status_code=303)

    @app.get("/audit", response_class=HTMLResponse)
    async def audit(request: Request):
        filters = {name: request.query_params.get(name, "") for name in ("start", "end", "project", "action", "result", "before")}
        def stamp(value):
            if not value:
                return None
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is not None:
                raise ValueError()
            return parsed.replace(tzinfo=ZoneInfo("Asia/Shanghai")).timestamp()
        try:
            start, end = stamp(filters["start"]), stamp(filters["end"])
            before = int(filters["before"]) if filters["before"] else None
        except (ValueError, OverflowError):
            raise MaintenanceError("invalid_audit_filter") from None
        page = app.state.core.audit_page(start, end, filters["project"] or None, filters["action"] or None, filters["result"] or None, before)
        next_url = "/audit?" + urlencode({**filters, "before": page["next"]}) if page["next"] else None
        return render(request, "audit", rows=page["rows"], filters=filters, next_url=next_url,
                      audit_actions=AUDIT_ACTIONS, audit_results=AUDIT_RESULTS)

    @app.get("/maintenance", response_class=HTMLResponse)
    async def maintenance(request: Request):
        return render(request, "maintenance", pending=app.state.core.recovery_view(), failures=app.state.core.failure_history())

    @app.get("/maintenance/diagnostics/{project}")
    async def diagnostics_report(request: Request, project: str):
        details = await asyncio.to_thread(app.state.core.failure_report, project)
        report = {"project": project, "exported_at": datetime.now(ZoneInfo("Asia/Shanghai")).isoformat(),
                  "note": "失败操作记录与失败后采集的最近200行容器日志；日志可能包含回退后的容器输出，不保证是失败瞬间现场。历史未采集或超过最近100次保留范围会标记不可用。常见凭据已过滤，分享前请检查业务隐私。", **details}
        return Response(json.dumps(report, ensure_ascii=False, indent=2), media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="project007-' + project + '-diagnostics.json"'})

    @app.post("/maintenance/reconcile")
    async def reconcile(request: Request):
        await form(request)
        result = await asyncio.to_thread(app.state.core.reconcile)
        return render(request, "message", message="对账完成，写操作已恢复" if result else "仍缺少可信终态，写操作保持暂停", detail="reconciled" if result else "reconciliation_incomplete")

    @app.post("/maintenance/resume/{project}")
    async def resume(request: Request, project: str):
        data = await form(request)
        if data.get("confirmed") != "yes":
            raise MaintenanceError("recovery_confirmation_required")
        await asyncio.to_thread(app.state.core.resume_project, project, "web", str(data.get("event_ref", "")))
        return RedirectResponse("/maintenance", status_code=303)

    @app.get("/telegram", response_class=HTMLResponse)
    async def telegram_settings(request: Request):
        return render(request, "telegram", telegram=app.state.telegram_store.state(), connection=app.state.telegram.connection)

    @app.post("/telegram/{action}")
    async def telegram_change(request: Request, action: str):
        data = await form(request)
        try:
            revision = int(str(data.get("revision", "")))
        except ValueError:
            raise MaintenanceError("telegram_stale_settings") from None
        if action == "token":
            await app.state.telegram.replace(str(data.get("token", "")), revision)
        else:
            code = await app.state.telegram.change_binding(action, revision)
            if action == "bind":
                return render(request, "binding", binding_code=code)
        return RedirectResponse("/telegram", status_code=303)

    install_project_routes(app, render, form)
    return app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--issue-code", choices=("initialize", "recover"))
    parser.add_argument("--telegram-key", type=Path)
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--runtime-config", type=Path)
    args = parser.parse_args()
    if args.issue_code:
        # Run with the service stopped, from the administrator's own terminal.
        guard = Core(args.state_dir, DemoGateway())
        try:
            auth = Auth(args.state_dir)
            try:
                print(auth.issue_code(args.issue_code))
            finally:
                auth.close()
        finally:
            guard.close()
        return
    import uvicorn
    if args.runtime_config:
        from .runtime import RuntimeConfig
        config = RuntimeConfig.load(args.runtime_config)
        app = create_app(args.state_dir, config.make_gateway(), args.telegram_key,
                         config.port, config.address, config.mode)
        uvicorn.run(app, host="0.0.0.0", port=config.port, access_log=False, proxy_headers=False)
    else:
        uvicorn.run(create_demo_app(args.state_dir, args.telegram_key, args.port), host="127.0.0.1", port=args.port, access_log=False, proxy_headers=False)


if __name__ == "__main__":
    main()
