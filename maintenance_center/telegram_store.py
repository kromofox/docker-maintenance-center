"""Encrypted Telegram configuration and single private-chat authorization."""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .core import MaintenanceError


class TelegramStore:
    def __init__(self, directory: Path, key_file: Path | None = None, clock=time.time):
        self.clock = clock
        self.lock = threading.RLock()
        self.key_file = key_file
        self.directory = directory.resolve()
        self.binding_code = None
        self.db = sqlite3.connect(directory / "telegram.sqlite3", check_same_thread=False)
        (directory / "telegram.sqlite3").chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS config(
                id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL DEFAULT 0,
                encrypted BLOB, bot_id INTEGER, username TEXT,
                user_id INTEGER, chat_id INTEGER);
            INSERT OR IGNORE INTO config(id) VALUES(1);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, stamp REAL,
                action TEXT NOT NULL, code TEXT NOT NULL);
        """)

    def _cipher(self):
        if self.key_file is None:
            raise MaintenanceError("telegram_key_unavailable")
        fd = None
        try:
            resolved = self.key_file.resolve()
            if resolved.is_relative_to(self.directory):
                raise ValueError("key_in_state")
            fd = os.open(self.key_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size != 44:
                raise ValueError("key_permissions_or_size")
            return Fernet(os.read(fd, 45))
        except (OSError, ValueError):
            raise MaintenanceError("telegram_key_unavailable") from None
        finally:
            if fd is not None:
                os.close(fd)

    @staticmethod
    def validate_token(token):
        if not isinstance(token, str) or not re.fullmatch(r"[0-9]{5,20}:[A-Za-z0-9_-]{30,100}", token):
            raise MaintenanceError("telegram_token_invalid")

    def _audit(self, action, code="ok"):
        self.db.execute("INSERT INTO audit(stamp,action,code) VALUES(?,?,?)", (self.clock(), action, code))

    def state(self):
        with self.lock:
            row = dict(self.db.execute("SELECT * FROM config").fetchone())
            error = None
            key_ready = False
            try:
                cipher = self._cipher()
                key_ready = True
                if row["encrypted"]:
                    cipher.decrypt(row["encrypted"])
            except (MaintenanceError, InvalidToken):
                error = "telegram_key_unavailable"
            return {"revision": row["revision"], "configured": row["encrypted"] is not None,
                    "bot_id": row["bot_id"], "username": row["username"],
                    "bound": row["user_id"] is not None, "user_id": row["user_id"],
                    "chat_id": row["chat_id"], "error": error, "key_ready": key_ready}

    def token(self):
        with self.lock:
            encrypted = self.db.execute("SELECT encrypted FROM config").fetchone()[0]
            if encrypted is None:
                return None
            try:
                return self._cipher().decrypt(encrypted).decode("ascii")
            except (InvalidToken, UnicodeError):
                raise MaintenanceError("telegram_key_unavailable") from None

    def replace_verified(self, token, bot_id, username, revision):
        """Trusted controller only: identity must come from successful getMe."""
        self.validate_token(token)
        if type(bot_id) is not int or bot_id <= 0 or not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_]{5,64}", username):
            raise MaintenanceError("telegram_identity_invalid")
        with self.lock, self.db:
            encrypted = self._cipher().encrypt(token.encode("ascii"))
            row = self.db.execute("SELECT * FROM config").fetchone()
            if row["revision"] != revision:
                raise MaintenanceError("telegram_stale_settings")
            same_bot = row["bot_id"] == bot_id
            self.db.execute("""UPDATE config SET revision=revision+1,encrypted=?,bot_id=?,username=?,
                user_id=?,chat_id=?""", (encrypted, bot_id, username,
                                       row["user_id"] if same_bot else None,
                                       row["chat_id"] if same_bot else None))
            self.binding_code = None
            self._audit("token_replaced")

    def delete(self, revision):
        with self.lock, self.db:
            if not self.db.execute("""UPDATE config SET revision=revision+1,encrypted=NULL,
                bot_id=NULL,username=NULL,user_id=NULL,chat_id=NULL WHERE revision=?""", (revision,)).rowcount:
                raise MaintenanceError("telegram_stale_settings")
            self.binding_code = None
            self._audit("token_deleted")

    def begin_binding(self, revision):
        with self.lock, self.db:
            if not self.token():
                raise MaintenanceError("telegram_not_configured")
            if not self.db.execute("UPDATE config SET revision=revision+1,user_id=NULL,chat_id=NULL WHERE revision=?", (revision,)).rowcount:
                raise MaintenanceError("telegram_stale_settings")
            code = secrets.token_urlsafe(24)
            self.binding_code = (hashlib.sha256(code.encode()).digest(), self.clock() + 600)
            self._audit("binding_started")
            return code

    def bind(self, code, user_id, chat_id, chat_type):
        with self.lock, self.db:
            if not self._private(user_id, chat_id, chat_type) or not isinstance(code, str) or len(code) > 100:
                raise MaintenanceError("telegram_access_denied")
            if not self.binding_code or self.binding_code[1] <= self.clock() or not hmac.compare_digest(self.binding_code[0], hashlib.sha256(code.encode()).digest()):
                raise MaintenanceError("telegram_binding_invalid")
            if not self.token():
                raise MaintenanceError("telegram_not_configured")
            self.db.execute("UPDATE config SET revision=revision+1,user_id=?,chat_id=?", (user_id, chat_id))
            self.binding_code = None
            self._audit("administrator_bound")

    def unbind(self, revision):
        with self.lock, self.db:
            if not self.db.execute("UPDATE config SET revision=revision+1,user_id=NULL,chat_id=NULL WHERE revision=?", (revision,)).rowcount:
                raise MaintenanceError("telegram_stale_settings")
            self.binding_code = None
            self._audit("administrator_unbound")

    @staticmethod
    def _private(user_id, chat_id, chat_type):
        return type(user_id) is int and type(chat_id) is int and user_id > 0 and user_id == chat_id and chat_type == "private"

    def authorized(self, user_id, chat_id, chat_type):
        with self.lock:
            row = self.db.execute("SELECT user_id,chat_id,encrypted FROM config").fetchone()
            return bool(self._private(user_id, chat_id, chat_type) and row["encrypted"] and
                        row["user_id"] == user_id and row["chat_id"] == chat_id)

    def close(self):
        self.db.close()
