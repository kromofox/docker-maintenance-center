#!/usr/bin/python3
"""Copyright (c) docker-maintenance-center contributors. MIT licensed.
Trusted host configuration shared by the unprivileged dispatcher and root tools.
"""
import json
import os
from pathlib import Path
import pwd
import re
import stat

INSTALL = Path('/usr/local/libexec/docker-maintenance-center')
CONFIG = Path('/etc/docker-maintenance-center/host.json')
REGISTRY = CONFIG.parent / 'registry.json'
STATE = Path('/var/lib/docker-maintenance-center/host')
LOCK = Path('/run/lock/docker-maintenance-center.lock')


class ConfigError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(value, code):
    if not value:
        raise ConfigError(code)


def trusted_path(value, directory=False, missing=False):
    path = Path(value)
    require(path.is_absolute() and str(path) == str(value) and '..' not in path.parts, 'path_invalid')
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            require(missing, 'path_missing')
            continue
        expected_dir = component != path or directory
        require((stat.S_ISDIR(info.st_mode) if expected_dir else stat.S_ISREG(info.st_mode))
                and info.st_uid == 0 and not info.st_mode & 0o022, 'path_untrusted')
    return path


def lock_directory():
    trusted_path(LOCK.parent.parent, directory=True)
    info = LOCK.parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), 'lock_directory_untrusted')


def python_executable():
    # Distribution /usr/bin/python3 is commonly a symlink, not an operator input.
    path = Path('/usr/bin/python3')
    trusted_path(path.parent, directory=True)
    info = path.lstat()
    require(info.st_uid == 0, 'python_untrusted')
    target = path.resolve(strict=True)
    trusted_path(target)
    return str(target)


def account(name):
    require(isinstance(name, str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name), 'gateway_user_invalid')
    user = pwd.getpwnam(name)
    require(user.pw_uid != 0, 'gateway_user_invalid')
    return user


def validate(config):
    require(isinstance(config, dict) and set(config) == {'gateway_user', 'docker_path', 'allowed_roots', 'state_dir'}, 'config_invalid')
    account(config['gateway_user'])
    docker = trusted_path(config['docker_path'])
    require(os.access(docker, os.X_OK), 'docker_not_executable')
    roots = config['allowed_roots']
    require(isinstance(roots, list) and roots and all(isinstance(r, str) for r in roots)
            and len(roots) == len(set(roots)), 'roots_invalid')
    state = trusted_path(config['state_dir'], directory=True, missing=True)
    require(state.name == 'host' and len(state.parts) >= 4, 'dedicated_state_required')
    for protected_path in (INSTALL, CONFIG.parent, LOCK.parent):
        require(state != protected_path and state not in protected_path.parents
                and protected_path not in state.parents, 'state_overlap_installation')
    protected = (INSTALL, CONFIG.parent, state)
    for value in roots:
        root = trusted_path(value, directory=True)
        require(root != Path('/') and all(root != p and root not in p.parents and p not in root.parents
                for p in protected), 'roots_overlap_installation')
    return config


def load_config():
    trusted_path(CONFIG)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'config_duplicate_key')
            result[key] = value
        return result
    with CONFIG.open() as stream:
        return validate(json.load(stream, object_pairs_hook=unique))


def check_caller(config, root=False):
    user = account(config['gateway_user'])
    if root:
        require(os.getuid() == 0 and os.geteuid() == 0 and os.environ.get('SUDO_USER') == user.pw_name
                and os.environ.get('SUDO_UID') == str(user.pw_uid)
                and os.environ.get('SUDO_GID') == str(user.pw_gid), 'caller_forbidden')
    else:
        require(os.getuid() == user.pw_uid and os.geteuid() == user.pw_uid, 'caller_forbidden')
