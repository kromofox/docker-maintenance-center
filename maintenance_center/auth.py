"""Single administrator authentication; secrets are returned only to callers."""

import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError

from .core import MaintenanceError


class Auth:
    def __init__(self, directory: Path, clock=time.time):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.clock = clock
        self.lock = threading.RLock()
        self.hasher = PasswordHasher()
        self.dummy_hash = self.hasher.hash(secrets.token_urlsafe(32))
        self.csrf_key = secrets.token_bytes(32)
        self.db = sqlite3.connect(directory / "auth.sqlite3", check_same_thread=False)
        (directory / "auth.sqlite3").chmod(0o600)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY CHECK(id=1), name TEXT, password_hash TEXT);
            CREATE TABLE IF NOT EXISTS codes(kind TEXT PRIMARY KEY, digest TEXT, expires REAL);
            CREATE TABLE IF NOT EXISTS sessions(digest TEXT PRIMARY KEY, seen REAL);
            CREATE TABLE IF NOT EXISTS attempts(source TEXT, stamp REAL);
            DELETE FROM sessions;
        """)

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def issue_code(self, kind):
        if kind not in {"initialize", "recover"}:
            raise MaintenanceError("invalid_code_kind")
        token = secrets.token_urlsafe(32)
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO codes VALUES(?,?,?)",
                            (kind, self.digest(token), self.clock() + 600))
        return token

    def set_password(self, code, name, password, kind="initialize"):
        if kind not in {"initialize", "recover"}:
            raise MaintenanceError("invalid_code_kind")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", name) or not 12 <= len(password) <= 256:
            raise MaintenanceError("invalid_credentials_format")
        with self.lock, self.db:
            admin = self.db.execute("SELECT name FROM admin").fetchone()
            if (kind == "initialize" and admin) or (kind == "recover" and not admin):
                raise MaintenanceError("code_invalid")
            row = self.db.execute("SELECT digest,expires FROM codes WHERE kind=?", (kind,)).fetchone()
            if not row or row[1] <= self.clock() or not hmac.compare_digest(row[0], self.digest(code)):
                raise MaintenanceError("code_invalid")
            self.db.execute("INSERT OR REPLACE INTO admin VALUES(1,?,?)", (name, self.hasher.hash(password)))
            self.db.execute("DELETE FROM codes")
            self.db.execute("DELETE FROM sessions")

    def login(self, name, password, source):
        if len(name) > 40 or len(password) > 256:
            raise MaintenanceError("login_failed")
        with self.lock, self.db:
            self.db.execute("DELETE FROM attempts WHERE stamp<=?", (self.clock() - 300,))
            if self.db.execute("SELECT count(*) FROM attempts WHERE source=?", (source,)).fetchone()[0] >= 5:
                raise MaintenanceError("login_limited")
            # Record attempts in a committed transaction, including failed attempts.
            self.db.execute("INSERT INTO attempts VALUES(?,?)", (source, self.clock()))
        with self.lock:
            row = self.db.execute("SELECT name,password_hash FROM admin").fetchone()
            encoded = row[1] if row else self.dummy_hash
            try:
                valid = self.hasher.verify(encoded, password)
            except (VerificationError, InvalidHashError):
                valid = False
            if not row or row[0] != name or not valid:
                raise MaintenanceError("login_failed")
            token = secrets.token_urlsafe(32)
            with self.db:
                if self.hasher.check_needs_rehash(encoded):
                    self.db.execute("UPDATE admin SET password_hash=? WHERE id=1", (self.hasher.hash(password),))
                self.db.execute("INSERT INTO sessions VALUES(?,?)", (self.digest(token), self.clock()))
            return token

    def check(self, token, touch=True):
        if not isinstance(token, str) or len(token) > 100:
            return False
        with self.lock, self.db:
            self.db.execute("DELETE FROM sessions WHERE seen<=?", (self.clock() - 1800,))
            row = self.db.execute("SELECT seen FROM sessions WHERE digest=?", (self.digest(token),)).fetchone()
            if row and touch:
                self.db.execute("UPDATE sessions SET seen=? WHERE digest=?", (self.clock(), self.digest(token)))
            return row is not None

    def csrf(self, token):
        return hmac.new(self.csrf_key, token.encode(), hashlib.sha256).hexdigest()

    def logout(self, token):
        with self.lock, self.db:
            self.db.execute("DELETE FROM sessions WHERE digest=?", (self.digest(token),))

    def close(self):
        self.db.close()
