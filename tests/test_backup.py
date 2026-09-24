import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from maintenance_center.auth import Auth
from maintenance_center.backup import snapshot, verify
from maintenance_center.core import Core
from maintenance_center.demo import DemoGateway
from maintenance_center.telegram_store import TelegramStore
from maintenance_center.notices import Notices


class BackupTests(unittest.TestCase):
    def test_snapshot_excludes_codes_sessions_and_rotates_verified_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state, destination = root / "state", root / "backup"
            core = Core(state, DemoGateway())
            auth = Auth(state)
            auth.set_password(auth.issue_code("initialize"), "admin", "test-only-password")
            session = auth.login("admin", "test-only-password", "fixture")
            code = auth.issue_code("recover")
            store = TelegramStore(state)
            notices = Notices(state)
            compose = root / "compose.yaml"
            compose.write_text("services: {}\n")
            compose.chmod(0o600)
            try:
                with self.assertRaises(BlockingIOError):
                    snapshot(state, compose, destination)
            finally:
                notices.close()
                store.close()
                auth.close()
                core.close()
            current = snapshot(state, compose, destination)
            verify(current)
            raw = (current / "auth.sqlite3").read_bytes()
            self.assertNotIn(Auth.digest(session).encode(), raw)
            self.assertNotIn(Auth.digest(code).encode(), raw)
            with sqlite3.connect(current / "auth.sqlite3") as db:
                self.assertEqual(db.execute("SELECT count(*) FROM admin").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT count(*) FROM codes").fetchone()[0], 0)
            snapshot(state, compose, destination)
            self.assertEqual(sorted(p.name for p in destination.iterdir()), ["current"])
            original_rename = Path.rename
            def fail_candidate(path, target):
                if path.name.startswith("candidate-"):
                    raise OSError("injected_rotation_failure")
                return original_rename(path, target)
            with patch.object(Path, "rename", fail_candidate):
                with self.assertRaisesRegex(OSError, "injected_rotation_failure"):
                    snapshot(state, compose, destination)
            verify(destination / "previous")
            snapshot(state, compose, destination)
            self.assertEqual(sorted(p.name for p in destination.iterdir()), ["current"])
            destination.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "private_owned_directory_required"):
                snapshot(state, compose, destination)
            destination.chmod(0o700)
            (current / "compose.yaml").write_text("changed")
            with self.assertRaisesRegex(ValueError, "backup_hash_mismatch"):
                snapshot(state, compose, destination)

    def test_arbitrary_manifest_paths_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "manifest.json").write_text(json.dumps({"../secret": "x"}))
            with self.assertRaisesRegex(ValueError, "invalid_backup_manifest"):
                verify(root)
