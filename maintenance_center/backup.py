"""Stopped-service SQLite snapshot; never copies external keys or approvals."""

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
from contextlib import closing
from pathlib import Path

DATABASES = ("state.sqlite3", "auth.sqlite3", "telegram.sqlite3", "notices.sqlite3")


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("private_regular_file_required")


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise ValueError("private_owned_directory_required")


def verify(directory):
    private_directory(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    if set(manifest) != set(DATABASES) | {"compose.yaml"}:
        raise ValueError("invalid_backup_manifest")
    for name, digest in manifest.items():
        target = directory / name
        regular(target)
        if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            raise ValueError("backup_hash_mismatch")
        if name in DATABASES:
            with closing(sqlite3.connect(target.as_uri() + "?mode=ro", uri=True)) as db:
                if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("backup_integrity_failed")
    return manifest


def snapshot(state, compose, destination):
    state, compose, destination = state.absolute(), compose.absolute(), destination.absolute()
    if state.is_symlink() or compose.is_symlink() or destination.is_symlink():
        raise ValueError("symlink_not_allowed")
    state, compose, destination = state.resolve(), compose.resolve(), destination.resolve()
    if state == destination or state in destination.parents or destination in state.parents:
        raise ValueError("backup_must_be_separate")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(state)
    private_directory(destination)
    regular(compose)
    # A missing lock is not proof the service is stopped.
    regular(state / "controller.lock")
    with (state / "controller.lock").open("r+") as guard:
        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current, previous = destination / "current", destination / "previous"
        for slot in (current, previous):
            if slot.exists() or slot.is_symlink():
                private_directory(slot)
        if current.exists() and previous.exists():
            verify(current)
            shutil.rmtree(previous)
            sync_directory(destination)
        elif previous.exists():
            verify(previous)
            previous.rename(current)
            sync_directory(destination)
        with tempfile.TemporaryDirectory(prefix="candidate-", dir=destination) as tmp:
            candidate = Path(tmp)
            candidate.chmod(0o700)
            for name in DATABASES:
                source = state / name
                regular(source)
                with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as src:
                    with closing(sqlite3.connect(candidate / name)) as dst:
                        src.backup(dst)
                        if name == "auth.sqlite3":
                            dst.execute("PRAGMA secure_delete=ON")
                            dst.execute("DELETE FROM sessions")
                            dst.execute("DELETE FROM codes")
                            dst.execute("DELETE FROM attempts")
                            dst.commit()
                            dst.execute("VACUUM")
                (candidate / name).chmod(0o600)
            shutil.copyfile(compose, candidate / "compose.yaml")
            (candidate / "compose.yaml").chmod(0o600)
            manifest = {name: hashlib.sha256((candidate / name).read_bytes()).hexdigest() for name in DATABASES + ("compose.yaml",)}
            (candidate / "manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
            (candidate / "manifest.json").chmod(0o600)
            verify(candidate)
            for path in candidate.iterdir():
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
            sync_directory(candidate)
            if current.exists():
                verify(current)
                current.rename(previous)
                sync_directory(destination)
            candidate.rename(current)
            sync_directory(destination)
            verify(current)
            # TemporaryDirectory can clean an absent candidate after rename.
            if previous.exists():
                shutil.rmtree(previous)
                sync_directory(destination)
    return current


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    snapshot(args.state_dir, args.compose, args.destination)
    print("backup_verified")


if __name__ == "__main__":
    main()
