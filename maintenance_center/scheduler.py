"""One coalescing wakeup; durable due times remain owned by Core."""

from apscheduler.schedulers.background import BackgroundScheduler


def start_scheduler(core):
    scheduler = BackgroundScheduler(timezone="Asia/Shanghai")
    def tick():
        core.management.run_initial()
        return core.run_due()
    scheduler.add_job(tick, "interval", seconds=30, id="maintenance",
                      max_instances=1, coalesce=True, misfire_grace_time=30)
    scheduler.start()
    core.management.wake = lambda: scheduler.add_job(core.management.run_initial, "date", id="initial-check", replace_existing=True, max_instances=1)
    return scheduler
