import unittest
from types import SimpleNamespace
from unittest import mock
from maintenance_center.telegram_control import TelegramControl


class CurrentVersionTests(unittest.TestCase):
    def test_current_version_and_untrusted_or_unavailable_fallback(self):
        for value, expected in [('1.2.3','1.2.3'), (None,'未知'), ('secret token\nhttps://example.test','未知')]:
            with self.subTest(value=value):
                gateway=SimpleNamespace(current_metadata=mock.Mock(return_value={'current_version':value}))
                core=SimpleNamespace(prepare_manual=mock.Mock(return_value=None),gateway=gateway,names={"PLEX":"PLEX"})
                reply=TelegramControl(core,None).plan('PLEX','update')
                self.assertIn(expected, reply.text)
                self.assertEqual(reply.buttons,[])
        gateway.current_metadata.side_effect=RuntimeError('private remote detail')
        reply=TelegramControl(core,None).plan('PLEX','update')
        self.assertIn("未知", reply.text)
        self.assertNotIn("private remote detail", reply.text)
