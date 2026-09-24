"""Host trust boundaries and durable uncertainty contracts (no Docker/root required)."""
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HOST = Path(__file__).resolve().parents[1] / 'host'
sys.path.insert(0, str(HOST))
import host_config
import project_registry
import recover


class HostPublicTrustTests(unittest.TestCase):
    def test_sudo_identity_must_match_configured_account(self):
        user = SimpleNamespace(pw_uid=2042, pw_gid=2042, pw_name='gateway')
        with patch.object(host_config, 'account', return_value=user), \
             patch.object(os, 'getuid', return_value=0), patch.object(os, 'geteuid', return_value=0), \
             patch.dict(os.environ, {'SUDO_USER':'gateway', 'SUDO_UID':'2042', 'SUDO_GID':'2042'}, clear=True):
            host_config.check_caller({'gateway_user':'gateway'}, root=True)
            os.environ['SUDO_UID'] = '999'
            with self.assertRaises(host_config.ConfigError):
                host_config.check_caller({'gateway_user':'gateway'}, root=True)

    def test_trust_rejects_symlink_and_writable_parent(self):
        def info(path):
            mode = stat.S_IFREG | 0o644 if str(path) == '/srv/policy.json' else stat.S_IFDIR | 0o755
            return SimpleNamespace(st_uid=0, st_mode=mode)
        with patch.object(Path, 'lstat', info):
            self.assertEqual(host_config.trusted_path('/srv/policy.json'), Path('/srv/policy.json'))
        for bad_mode in (stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o777):
            def bad_info(path):
                return SimpleNamespace(st_uid=0, st_mode=bad_mode) if str(path) == '/srv' else info(path)
            with patch.object(Path, 'lstat', bad_info), self.assertRaises(host_config.ConfigError):
                host_config.trusted_path('/srv/policy.json')

    def test_discovery_roots_cannot_contain_installation(self):
        config = {'gateway_user':'gateway', 'docker_path':'/usr/bin/docker',
                  'allowed_roots':['/usr/local'], 'state_dir':'/var/lib/docker-maintenance-center/host'}
        with patch.object(host_config, 'account'), patch.object(host_config, 'trusted_path', side_effect=lambda p, **kw: Path(p)), \
             patch.object(os, 'access', return_value=True), self.assertRaises(host_config.ConfigError):
            host_config.validate(config)

    def test_compose_path_cannot_escape_root_or_follow_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / 'projects'
            root.mkdir()
            outside = base / 'compose.yaml'
            outside.write_text('services: {}')
            link = root / 'compose.yaml'
            link.symlink_to(outside)
            registry = project_registry.Registry(owner=-1)
            data = {'allowed_roots':[str(root)]}
            for value in (outside, link, root):
                with self.assertRaises(project_registry.RegistryError):
                    registry.safe_path(str(value), data, file=True)


class HostPublicRecoveryTests(unittest.TestCase):
    def test_unknown_blocks_changes_and_review_retains_failed_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = project_registry.Registry(state=directory, owner=os.getuid())
            for name in ('operations', 'audit'):
                (Path(directory) / name).mkdir()
            before = {'status':'unknown', 'operation_ref':'a'*16, 'code':'operation_uncertain'}
            project_registry.atomic(Path(directory) / 'operations' / 'P1.json', before)
            with patch.object(registry, 'trusted'), self.assertRaises(project_registry.RegistryError):
                registry.clear_to_change({'projects':{'P1':{}}})
            observed = {'operation':before, 'health':{'overall':'healthy'}}
            with patch.object(recover, 'snapshot', return_value=observed):
                with self.assertRaises(project_registry.RegistryError):
                    recover.resolve(registry, 'P1', 'a'*16, 'wrong', 'Operator inspected containers and verified external data.')
                self.assertEqual(list((Path(directory) / 'audit').iterdir()), [])
                result = recover.resolve(registry, 'P1', 'a'*16, project_registry.digest(observed),
                                         'Operator inspected containers and verified external data.')
            self.assertEqual(result['status'], 'failed')
            self.assertFalse(result['resolution']['operation_replayed'])
            import json
            audit = json.loads(next((Path(directory) / 'audit').iterdir()).read_text())
            self.assertEqual(audit['before'], before)
            with patch.object(registry, 'trusted'):
                registry.clear_to_change({'projects':{'P1':{}}})


if __name__ == '__main__':
    unittest.main()
