from copy import deepcopy
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from maintenance_center.core import Core
from maintenance_center.demo import DemoGateway
from maintenance_center.telegram_runtime import TelegramRuntime
from test_telegram import Fixture, FakeBot


class InlineMenuTests(Fixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.setup_files(); self.bound()
        self.core = Core(self.directory, DemoGateway()); self.core.reconcile()
        self.runtime = TelegramRuntime(self.core, self.store, self.directory, FakeBot)
        self.runtime.bot = FakeBot(self.store.token())
        FakeBot.sends = []

    async def asyncTearDown(self):
        await self.runtime.stop(); self.core.close(); self.store.close(); self.tmp.cleanup()

    def query(self, reply, label, user=42):
        handle = next(value for title, value in reply.buttons if title == label)
        markup = self.runtime._presentation(reply)[1]
        query = SimpleNamespace(data=handle, message=SimpleNamespace(reply_markup=markup),
                                answer=AsyncMock(), edit_message_text=AsyncMock(), edit_message_reply_markup=AsyncMock())
        update = SimpleNamespace(effective_user=SimpleNamespace(id=user), effective_chat=SimpleNamespace(id=user,type='private'), callback_query=query)
        return query, update

    async def test_navigation_replaces_original_message_and_retires_old_keyboard(self):
        reply = self.runtime.control.command('/set',42,42,'private')
        old_handles = {value for _, value in reply.buttons}
        query, update = self.query(reply, '启用')
        await self.runtime._update(update)
        query.edit_message_text.assert_awaited_once()
        self.assertIn('状态：启用', query.edit_message_text.call_args.args[0])
        self.assertIsNotNone(query.edit_message_text.call_args.kwargs['reply_markup'])
        self.assertFalse(old_handles & self.runtime.control.pending.keys())
        self.assertFalse(self.core.state()['enabled'])
        self.assertEqual(FakeBot.sends, [])

    async def test_save_replaces_menu_with_result_without_buttons_or_duplicate_send(self):
        reply = self.runtime.control.command('/set 2 PLEX',42,42,'private')
        query, update = self.query(reply, '确认保存')
        await self.runtime._update(update)
        self.assertTrue(self.core.state()['enabled'])
        self.assertIn('已保存', query.edit_message_text.call_args.args[0])
        self.assertIsNone(query.edit_message_text.call_args.kwargs['reply_markup'])
        self.assertEqual(FakeBot.sends, [])
        self.assertFalse(self.runtime.control.pending)

    async def test_edit_failure_does_not_repeat_save_and_stale_click_does_not_write(self):
        reply = self.runtime.control.command('/set 2 PLEX',42,42,'private')
        query, update = self.query(reply, '确认保存')
        query.edit_message_text.side_effect = RuntimeError('transport uncertain')
        with patch.object(self.core, 'configure', wraps=self.core.configure) as configure:
            await self.runtime._update(update)
            self.assertEqual(configure.call_count, 1)
            query.edit_message_reply_markup.assert_awaited_once_with(reply_markup=None)
            self.assertEqual(len(FakeBot.sends), 1)
            self.assertIn('已保存', FakeBot.sends[0][1])
            query.edit_message_text.side_effect = None
            await self.runtime._update(update)
            self.assertEqual(configure.call_count, 1)
            self.assertIsNone(query.edit_message_text.call_args.kwargs['reply_markup'])

    async def test_unauthorized_click_does_not_edit_or_consume_menu(self):
        reply = self.runtime.control.command('/set 2 PLEX',42,42,'private')
        before = set(self.runtime.control.pending)
        query, update = self.query(reply, '确认保存',user=43)
        await self.runtime._update(update)
        query.edit_message_text.assert_not_awaited()
        query.edit_message_reply_markup.assert_not_awaited()
        self.assertEqual(set(self.runtime.control.pending),before)
        self.assertFalse(self.core.state()['enabled'])

    async def test_check_menu_and_callback_show_progress_before_slow_work(self):
        reply = self.runtime.control.command('/check',42,42,'private')
        query, update = self.query(reply,'检查 EMBY')
        def plan(project, action):
            self.assertIn('正在检查 EMBY',query.edit_message_text.call_args.args[0])
            self.assertIsNone(query.edit_message_text.call_args.kwargs['reply_markup'])
            from maintenance_center.telegram_control import Reply
            return Reply('EMBY：当前没有更新。')
        with patch.object(self.runtime.control,'plan',side_effect=plan) as call:
            await self.runtime._update(update)
            call.assert_called_once_with('EMBY','update')
        self.assertEqual(query.edit_message_text.await_count,2)
        self.assertIn('当前没有更新',query.edit_message_text.call_args.args[0])
        self.assertEqual(FakeBot.sends,[])

    async def test_direct_lowercase_check_updates_progress_message(self):
        message=SimpleNamespace(edit_text=AsyncMock())
        update=SimpleNamespace(effective_user=SimpleNamespace(id=42),effective_chat=SimpleNamespace(id=42,type='private'),callback_query=None,message=SimpleNamespace(text='/check plex'))
        with patch.object(self.runtime.bot,'send_message',new=AsyncMock(return_value=message)) as send:
            with patch.object(self.runtime.control,'plan',return_value=__import__('maintenance_center.telegram_control',fromlist=['Reply']).Reply('检查完成')) as plan:
                await self.runtime._update(update)
            plan.assert_called_once_with('PLEX','update')
            send.assert_awaited_once()
            self.assertIn('正在检查 PLEX',send.call_args.args[1])
            message.edit_text.assert_awaited_once()

    async def test_progress_transport_failure_still_runs_check_only_once(self):
        reply=self.runtime.control.command('/check',42,42,'private')
        query,update=self.query(reply,'检查 EMBY')
        query.edit_message_text.side_effect=[RuntimeError('temporary'),None]
        with patch.object(self.runtime.control,'plan',wraps=self.runtime.control.plan) as plan:
            await self.runtime._update(update)
            self.assertEqual(plan.call_count,1)
        self.assertEqual(FakeBot.sends,[])

    async def test_discovery_close_removes_keyboard_and_invalidates_candidate_buttons(self):
        control = self.runtime.control
        reply = control.project_callback('registry_discover', {})
        before = self.core.state()
        handles = {handle for _, handle in reply.buttons}
        query, update = self.query(reply, '关闭菜单')
        await self.runtime._update(update)
        self.assertIsNone(query.edit_message_text.call_args.kwargs['reply_markup'])
        self.assertFalse(handles & control.pending.keys())
        self.assertEqual(self.core.state(), before)
        self.assertEqual(FakeBot.sends, [])

    async def test_project_close_retires_actions_without_changing_project(self):
        control = self.runtime.control
        reply = control.project_callback('registry_project', {'project': 'PLEX'})
        before = self.core.state()
        catalog_before = deepcopy(self.core.gateway.catalog)
        query, update = self.query(reply, '关闭菜单')
        stale_query, stale_update = self.query(reply, '解除接管')
        await self.runtime._update(update)
        self.assertIsNone(query.edit_message_text.call_args.kwargs['reply_markup'])
        self.assertFalse({handle for _, handle in reply.buttons} & control.pending.keys())
        await self.runtime._update(stale_update)
        self.assertIsNone(stale_query.edit_message_text.call_args.kwargs['reply_markup'])
        self.assertEqual(self.core.gateway.catalog, catalog_before)
        self.assertEqual(self.core.state(), before)
        self.assertEqual(FakeBot.sends, [])

    async def test_empty_discovery_menu_can_still_be_closed(self):
        gateway = self.core.gateway
        gateway.catalog['MEDIAVAULT3'] = gateway.definition('MEDIAVAULT3')
        reply = self.runtime.control.project_callback('registry_discover', {})
        self.assertEqual([title for title, _ in reply.buttons], ['关闭菜单'])
        query, update = self.query(reply, '关闭菜单')
        await self.runtime._update(update)
        self.assertIsNone(query.edit_message_text.call_args.kwargs['reply_markup'])

    async def test_preview_reports_progress_then_confirmation_without_enrollment(self):
        control = self.runtime.control
        menu = control.project_callback('registry_discover', {})
        label = next(title for title, _ in menu.buttons if title != '关闭菜单')
        query, update = self.query(menu, label)
        await self.runtime._update(update)
        self.assertEqual(query.edit_message_text.await_count, 2)
        self.assertIn('预检', query.edit_message_text.await_args_list[0].args[0])
        self.assertIsNotNone(query.edit_message_text.call_args.kwargs['reply_markup'])
        self.assertNotIn('MEDIAVAULT3', self.core.projects)

    async def test_callback_ack_failure_does_not_silently_drop_or_execute(self):
        from telegram.error import BadRequest
        menu = self.runtime.control.project_callback('registry_discover', {})
        label = next(title for title, _ in menu.buttons if title != '关闭菜单')
        query, update = self.query(menu, label)
        query.answer.side_effect = BadRequest('query is too old')
        with patch.object(self.core.management, 'preview') as preview:
            await self.runtime._update(update)
        preview.assert_not_called()
        self.assertIsNone(query.edit_message_text.call_args.kwargs['reply_markup'])
        self.assertFalse({handle for _, handle in menu.buttons} & self.runtime.control.pending.keys())

    async def test_unexpected_preview_error_shows_failure_without_enrollment(self):
        menu = self.runtime.control.project_callback('registry_discover', {})
        label = next(title for title, _ in menu.buttons if title != '关闭菜单')
        query, update = self.query(menu, label)
        with patch.object(self.core.management, 'preview', side_effect=RuntimeError('private-secret')):
            await self.runtime._update(update)
        self.assertIsNone(query.edit_message_text.call_args.kwargs['reply_markup'])
        self.assertNotIn('private-secret', query.edit_message_text.call_args.args[0])
        self.assertNotIn('MEDIAVAULT3', self.core.projects)

    async def test_reply_timeout_retries_menu_without_rerunning_command(self):
        from telegram.error import TimedOut
        update = SimpleNamespace(effective_user=SimpleNamespace(id=42),
                                 effective_chat=SimpleNamespace(id=42, type='private'),
                                 callback_query=None, message=SimpleNamespace(text='/projects'))
        delivered = []
        async def send(chat_id, text, **kwargs):
            if not delivered:
                delivered.append(None)
                raise TimedOut('private-secret')
            delivered.append(text)
        with patch.object(self.runtime.bot, 'send_message', side_effect=send):
            with patch.object(self.runtime.control, 'command', wraps=self.runtime.control.command) as command:
                await self.runtime._update(update)
        command.assert_called_once()
        self.assertIn('项目', delivered[-1])

    async def test_result_send_timeout_never_repeats_committed_save(self):
        from telegram.error import TimedOut
        reply = self.runtime.control.command('/set 2 PLEX', 42, 42, 'private')
        query, update = self.query(reply, '确认保存')
        query.edit_message_text.side_effect = TimedOut()
        with patch.object(self.runtime.bot, 'send_message', new=AsyncMock(side_effect=[TimedOut(), None])) as send:
            with patch.object(self.core, 'configure', wraps=self.core.configure) as configure:
                await self.runtime._update(update)
        configure.assert_called_once()
        self.assertTrue(self.core.state()['enabled'])
        self.assertIn('已保存', send.call_args.args[1])
        self.assertEqual(send.await_count, 2)

    async def test_exhausted_reply_timeout_does_not_block_next_polled_command(self):
        from telegram.error import TimedOut
        updates = [SimpleNamespace(update_id=i, effective_user=SimpleNamespace(id=42),
                                   effective_chat=SimpleNamespace(id=42, type='private'),
                                   callback_query=None, message=SimpleNamespace(text=text))
                   for i, text in [(101, '/projects'), (102, '/status')]]
        self.runtime.bot_revision = (self.store.state()['bot_id'], self.store.token())
        self.runtime.menu_synced = True
        with patch.object(self.runtime.bot, 'get_updates', new=AsyncMock(return_value=updates)):
            with patch.object(self.runtime.bot, 'send_message', new=AsyncMock(side_effect=[TimedOut('private-secret'), TimedOut('private-secret'), None])) as send:
                with self.assertLogs('maintenance_center.telegram_runtime', level='WARNING') as logs:
                    await self.runtime.tick()
        self.assertIn('白名单 Docker 维护中心', send.call_args.args[1])
        self.assertEqual(self.runtime.offset, 103)
        self.assertNotIn('private-secret', '\n'.join(logs.output))
        self.assertIn('stage=message_render', '\n'.join(logs.output))

    async def test_callback_timeout_retires_approval_without_executing(self):
        from telegram.error import TimedOut
        reply = self.runtime.control.command('/set 2 PLEX', 42, 42, 'private')
        query, update = self.query(reply, '确认保存')
        query.answer.side_effect = TimedOut()
        await self.runtime._update(update)
        self.assertFalse(self.core.state()['enabled'])
        self.assertFalse(self.runtime.control.pending)
        self.assertIsNone(query.edit_message_text.call_args.kwargs['reply_markup'])

    async def test_permanent_send_error_is_not_retried_or_replaced(self):
        from telegram.error import BadRequest
        reply = self.runtime.control.command('/set 2 PLEX', 42, 42, 'private')
        query, update = self.query(reply, '确认保存')
        query.edit_message_text.side_effect = BadRequest('cannot edit')
        with patch.object(self.runtime.bot, 'send_message', new=AsyncMock(side_effect=BadRequest('cannot send'))) as send:
            with self.assertRaises(BadRequest):
                await self.runtime._update(update)
        self.assertTrue(self.core.state()['enabled'])
        send.assert_awaited_once()
