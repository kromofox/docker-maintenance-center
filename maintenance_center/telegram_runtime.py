"""Serialized async Telegram lifecycle; transport errors never expose URLs."""

import asyncio
import logging
import time

from telegram import Bot, BotCommand, BotCommandScopeDefault, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.error import TelegramError, TimedOut

from .core import MaintenanceError
from .notices import Notices
from .telegram_control import TelegramControl, Reply


COMMANDS = (
    ("status", "查看白名单项目状态与维护入口"),
    ("projects", "添加项目、维护策略与解除接管"),
    ("set", "设置统一自动更新计划"),
    ("check", "选择项目检查更新"),
    ("resume", "恢复故障暂停的自动更新"),
    ("help", "显示命令说明"),
)


class TelegramRuntime:
    def __init__(self, core, store, directory, bot_factory=Bot, demo=True):
        self.core, self.store, self.bot_factory = core, store, bot_factory
        self.demo = demo
        self.control = TelegramControl(core, store)
        self.notices = Notices(directory)
        self.lock = asyncio.Lock()
        self.stop_event = asyncio.Event()
        self.bot = None
        self.bot_revision = None
        self.offset = None
        self.task = None
        self.connection = "not_configured"
        self.menu_synced = False
        self.menu_retry_at = 0
        # Bot HTTP URLs contain credentials, and debug updates contain bind codes.
        for name in list(logging.Logger.manager.loggerDict) + ["telegram", "httpx", "httpcore"]:
            if name.split(".")[0] in {"telegram", "httpx", "httpcore"}:
                logging.getLogger(name).disabled = True

    async def replace(self, token, revision):
        self.store.validate_token(token)
        self.store._cipher()
        try:
            async with self.bot_factory(token) as candidate:
                identity = await candidate.get_me()
                if identity.is_bot is not True:
                    raise ValueError("not_bot")
        except Exception:
            raise MaintenanceError("telegram_verification_failed") from None
        async with self.lock:
            self.store.replace_verified(token, identity.id, identity.username, revision)
            self.control.pending.clear()
            await self._disconnect()
            self.connection = "verified"

    async def change_binding(self, action, revision):
        async with self.lock:
            if action == "delete":
                self.store.delete(revision)
                await self._disconnect()
                self.connection = "not_configured"
            elif action == "bind":
                result = self.store.begin_binding(revision)
                self.control.pending.clear()
                return result
            elif action == "unbind":
                self.store.unbind(revision)
            else:
                raise MaintenanceError("action_not_allowed")
            self.control.pending.clear()

    async def _disconnect(self):
        bot, self.bot = self.bot, None
        self.bot_revision = None
        self.offset = None
        self.menu_synced = False
        self.menu_retry_at = 0
        if bot is not None:
            try:
                await bot.shutdown()
            except Exception:
                pass

    def start(self):
        self.task = asyncio.create_task(self._run())

    async def stop(self):
        self.stop_event.set()
        if self.task:
            # Do not cancel a thread that may already have dispatched a host write.
            await self.task
        async with self.lock:
            await self._disconnect()
            self.notices.close()

    def _presentation(self, reply):
        markup = InlineKeyboardMarkup([[InlineKeyboardButton(title, callback_data=handle)] for title, handle in reply.buttons]) if reply.buttons else None
        return ("本地演示 · 未连接 NAS\n" if self.demo else "") + reply.text, markup

    async def _reply(self, chat_id, reply):
        text, markup = self._presentation(reply)
        # Retry only this frozen presentation, never the command or callback.
        # A timed-out send may have arrived: duplicates share the same handles.
        for attempt in range(2):
            try:
                async with asyncio.timeout(10):
                    return await self.bot.send_message(chat_id, text, reply_markup=markup)
            except (TimedOut, TimeoutError) as error:
                logging.getLogger(__name__).warning(
                    "telegram_reply_failure stage=reply_send type=%s attempt=%s",
                    type(error).__name__, attempt + 1)
                if attempt == 1:
                    raise
                await asyncio.sleep(0.5)

    def _retire_keyboard(self, query):
        # The clicked handle is consumed by control.callback. Other handles in
        # the superseded keyboard must not remain actionable after an edit fails.
        markup = getattr(getattr(query, "message", None), "reply_markup", None)
        for row in getattr(markup, "inline_keyboard", ()):
            for button in row:
                handle = getattr(button, "callback_data", None)
                if isinstance(handle, str) and handle != query.data:
                    self.control.pending.pop(handle, None)

    async def _edit_reply(self, query, chat_id, reply):
        text, markup = self._presentation(reply)
        try:
            await query.edit_message_text(text, reply_markup=markup)
        except Exception:
            # The action already ran. Only repair presentation, never repeat it.
            try:
                await query.edit_message_reply_markup(reply_markup=None)
            except Exception:
                pass
            await self._reply(chat_id, reply)

    async def _update(self, update):
        user, chat = update.effective_user, update.effective_chat
        if not user or not chat:
            return
        editable_query = None
        progress_message = None
        stage = "authorize"
        try:
            if update.callback_query:
                query = update.callback_query
                if not self.store.authorized(user.id, chat.id, chat.type):
                    await query.answer("无权访问。", show_alert=True)
                    return
                editable_query = query
                stage = "callback_answer"
                try:
                    await query.answer()
                except TelegramError as error:
                    self._retire_keyboard(query)
                    self.control.pending.pop(query.data, None)
                    logging.getLogger(__name__).warning("telegram_callback_failure stage=%s type=%s",
                                                        stage, type(error).__name__)
                    await self._edit_reply(query, chat.id, Reply("按钮应答失败，本次未执行操作。请重新发送 /projects 打开菜单后重试。"))
                    return
                stage = "callback_progress"
                progress = self.control.progress(user.id, chat.id, chat.type, handle=query.data)
                if progress:
                    try:
                        text, _ = self._presentation(Reply(progress))
                        await query.edit_message_text(text, reply_markup=None)
                    except Exception:
                        pass
                self._retire_keyboard(query)
                stage = "callback_execute"
                reply = await asyncio.to_thread(self.control.callback, query.data, user.id, chat.id, chat.type)
                stage = "callback_render"
                await self._edit_reply(query, chat.id, reply)
                return
            elif update.message and update.message.text:
                stage = "message_progress"
                if self.store.authorized(user.id, chat.id, chat.type):
                    progress = self.control.progress(user.id, chat.id, chat.type, text=update.message.text)
                    if progress:
                        try:
                            progress_message = await self._reply(chat.id, Reply(progress))
                        except Exception:
                            pass
                stage = "message_execute"
                reply = await asyncio.to_thread(self.control.command, update.message.text, user.id, chat.id, chat.type)
            else:
                return
            stage = "message_render"
            await self._finish_message(progress_message, chat.id, reply)
        except MaintenanceError as error:
            # Never echo incoming text, binding codes, or raw gateway errors.
            code = str(error)
            if code == "query_timeout":
                reply = Reply("检查失败：查询超时。未执行更新，请稍后重试。")
            elif code in {"planning_unavailable", "plan_rejected"}:
                reply = Reply("检查失败：更新源或宿主网关暂时不可用。未执行更新，请稍后重试。")
            elif code == "writes_paused":
                reply = Reply("检查暂不可用：系统正在核对写操作状态。请稍后重试或在 Web 查看门禁状态。")
            else:
                reply = Reply("请求未执行：无权访问、菜单已失效或操作条件不满足。请在 Web 核对。")
            if editable_query is not None:
                await self._edit_reply(editable_query, chat.id, reply)
            else:
                await self._finish_message(progress_message, chat.id, reply)
        except (TelegramError, TimeoutError) as error:
            # Failed presentation does not make a completed operation uncertain.
            # Do not replace its result with a generic error or rerun the action.
            logging.getLogger(__name__).warning("telegram_update_failure stage=%s type=%s",
                                                stage, type(error).__name__)
            raise
        except Exception as error:
            # Never log exception text, incoming updates, IDs, URLs or credentials.
            logging.getLogger(__name__).warning("telegram_update_failure stage=%s type=%s",
                                                stage, type(error).__name__)
            if editable_query is not None:
                await self._edit_reply(editable_query, chat.id, Reply("菜单处理失败，不能据此判断是否完成。请先在 Web 核对项目状态；不要重复确认接管。"))
            else:
                raise

    async def _finish_message(self, message, chat_id, reply):
        if message is not None:
            try:
                text, markup = self._presentation(reply)
                await message.edit_text(text, reply_markup=markup)
                return
            except Exception:
                pass
        await self._reply(chat_id, reply)

    async def _sync_command_menu(self):
        if self.menu_synced or time.monotonic() < self.menu_retry_at:
            return
        self.menu_retry_at = time.monotonic() + 60
        try:
            commands = [BotCommand(name, description) for name, description in COMMANDS]
            scope = BotCommandScopeDefault()
            if await self.bot.set_my_commands(commands, scope=scope, language_code="") is not True:
                return
            actual = await self.bot.get_my_commands(scope=scope, language_code="")
            self.menu_synced = tuple((item.command, item.description) for item in actual) == COMMANDS
        except Exception:
            # Menu metadata failure must not stop polling or maintenance notices.
            # Retry later without exposing Bot API URLs or credential details.
            self.menu_synced = False

    async def tick(self):
        async with self.lock:
            self.notices.collect(self.core)
            token = self.store.token()
            if not token:
                self.connection = "not_configured"
                await self._disconnect()
                return
            state = self.store.state()
            # Binding revisions invalidate menu actions, but do not restart polling.
            identity = (state["bot_id"], token)
            if self.bot_revision != identity:
                await self._disconnect()
                self.bot = self.bot_factory(token)
                await self.bot.initialize()
                # Drop queued commands on every new polling session; old intents
                # must never execute after an offline period or credential change.
                previous = await self.bot.get_updates(offset=-1, timeout=0, allowed_updates=["message", "callback_query"])
                self.offset = previous[-1].update_id + 1 if previous else None
                self.bot_revision = identity
            await self._sync_command_menu()
            updates = await self.bot.get_updates(offset=self.offset, timeout=5, read_timeout=10, allowed_updates=["message", "callback_query"])
            self.connection = "connected"
            for update in updates:
                self.offset = update.update_id + 1
                try:
                    await self._update(update)
                except (TelegramError, TimeoutError):
                    # The reply budget is exhausted; continue the batch without
                    # replaying an already consumed intent or starving later ones.
                    self.connection = "disconnected"
            self.notices.collect(self.core)
            state = self.store.state()
            if state["bound"]:
                for notice_id, item in self.notices.pending():
                    await self.bot.send_message(state["chat_id"], ("本地演示 · 未连接 NAS\n" if self.demo else "") + self.notices.text(item))
                    self.notices.sent(notice_id)

    async def _run(self):
        while not self.stop_event.is_set():
            try:
                await self.tick()
            except MaintenanceError:
                self.connection = "key_unavailable"
                async with self.lock:
                    await self._disconnect()
            except Exception:
                self.connection = "disconnected"
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=2)
            except TimeoutError:
                pass
