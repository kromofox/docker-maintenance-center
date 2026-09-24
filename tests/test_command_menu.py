import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from maintenance_center.core import Core
from maintenance_center.demo import DemoGateway
from maintenance_center.telegram_runtime import COMMANDS, TelegramRuntime
from test_telegram import Fixture, FakeBot


class MenuBot(FakeBot):
    async def set_my_commands(self, commands, **kwargs):
        self.calls += 1
        self.scope = kwargs
        if self.menu_failure:
            raise RuntimeError('secret URL must not escape')
        self.commands = commands
        return True

    async def get_my_commands(self, **kwargs):
        if self.stale_read:
            return [SimpleNamespace(command='new', description='legacy')]
        return self.commands

    def __init__(self, token):
        super().__init__(token)
        self.calls = 0
        self.menu_failure = False
        self.stale_read = False
        self.commands = []


class MenuTests(Fixture, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.setup_files()
        self.bound()
        self.core = Core(self.directory, DemoGateway())
        self.core.reconcile()
        MenuBot.polls, MenuBot.updates, MenuBot.sends = [], [], []
        self.runtime = TelegramRuntime(self.core, self.store, self.directory, MenuBot)

    async def asyncTearDown(self):
        await self.runtime.stop()
        self.core.close()
        self.store.close()
        self.tmp.cleanup()

    async def test_startup_registers_verified_menu_once_and_reconnect_repeats(self):
        await self.runtime.tick()
        bot = self.runtime.bot
        self.assertTrue(self.runtime.menu_synced)
        self.assertEqual(tuple((x.command, x.description) for x in bot.commands), COMMANDS)
        self.assertEqual(bot.scope['scope'].type, 'default')
        self.assertEqual(bot.scope['language_code'], '')
        self.assertNotIn('new', [x.command for x in bot.commands])
        self.assertNotIn('update', [x.command for x in bot.commands])
        await self.runtime.tick()
        self.assertEqual(bot.calls, 1)
        await self.runtime._disconnect()
        await self.runtime.tick()
        self.assertTrue(self.runtime.menu_synced)
        self.assertIsNot(bot, self.runtime.bot)
        self.assertEqual(self.runtime.bot.calls, 1)
        self.assertEqual(MenuBot.polls.count(-1), 2)
        self.assertEqual(self.core.db.execute('SELECT count(*) FROM operations').fetchone()[0], 0)

    async def test_menu_failure_is_throttled_and_does_not_block_polling_then_recovers(self):
        await self.runtime.tick()
        bot = self.runtime.bot
        self.runtime.menu_synced = False
        self.runtime.menu_retry_at = 0
        bot.menu_failure = True
        await self.runtime.tick()
        self.assertFalse(self.runtime.menu_synced)
        self.assertEqual(self.runtime.connection, 'connected')
        calls, polls = bot.calls, len(MenuBot.polls)
        await self.runtime.tick()
        self.assertEqual(bot.calls, calls)
        self.assertGreater(len(MenuBot.polls), polls)
        bot.menu_failure = False
        self.runtime.menu_retry_at = 0
        await self.runtime.tick()
        self.assertTrue(self.runtime.menu_synced)

    async def test_success_response_with_stale_server_menu_is_not_marked_synced(self):
        await self.runtime.tick()
        self.runtime.bot.stale_read = True
        self.runtime.menu_synced = False
        self.runtime.menu_retry_at = 0
        await self.runtime.tick()
        self.assertFalse(self.runtime.menu_synced)
        self.assertEqual(self.runtime.connection, 'connected')
