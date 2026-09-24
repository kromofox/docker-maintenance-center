#!/usr/bin/python3
"""Copyright (c) docker-maintenance-center contributors. MIT licensed.
Offline, explicit root installation. check never writes; install never enrolls or updates.
"""
import argparse
import grp
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from host_config import CONFIG, INSTALL, REGISTRY, STATE, LOCK, account, trusted_path, validate, require, python_executable, lock_directory
from project_registry import atomic

FILES = ('host_config.py', 'compose_inputs.py', 'project_registry.py', 'active_dispatch.py', 'host_gateway.py', 'recover.py', 'install.py')
SUDOERS = Path('/etc/sudoers.d/docker-maintenance-center')
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'HOME':'/root', 'LANG':'C.UTF-8'}


def command(argv):
    result = subprocess.run(argv, env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, check=True)
    return result.stdout.decode().strip()


def preflight(config):
    require(sys.platform == 'linux' and sys.version_info >= (3, 12), 'linux_python312_required')
    require(os.getuid() == 0 and os.geteuid() == 0, 'root_required')
    validate(config)
    user = account(config['gateway_user'])
    groups = {grp.getgrgid(gid).gr_name for gid in os.getgrouplist(user.pw_name, user.pw_gid)}
    require(not groups & {'root', 'docker', 'sudo', 'wheel', 'admin'}, 'gateway_privileged_group')
    for executable in ('/usr/bin/sudo', '/usr/sbin/visudo'):
        trusted_path(executable)
        require(os.access(executable, os.X_OK), 'executable_missing')
    python = python_executable()
    version = command([python, '-I', '-c', 'import sys; print(sys.version_info >= (3,12))'])
    require(version == 'True', 'system_python312_required')
    require(command([python, '-I', '-c', 'import yaml; print(hasattr(yaml, "safe_load"))']) == 'True', 'system_pyyaml_required')
    require(command([config['docker_path'], 'compose', 'version', '--short']).lstrip('v').startswith('2.'), 'compose_v2_required')
    command([config['docker_path'], 'info', '--format', '{{.ServerVersion}}'])
    trusted_path('/etc/sudoers')
    trusted_path(SUDOERS.parent, directory=True)
    command(['/usr/sbin/visudo', '-c'])
    # sudoers must actually enable this directory; never silently install an inert rule.
    require(any(line.strip().startswith(('@includedir /etc/sudoers.d', '#includedir /etc/sudoers.d'))
                for line in Path('/etc/sudoers').read_text().splitlines()), 'sudoers_include_required')
    lock_directory()
    for target in (INSTALL, CONFIG.parent, Path(config['state_dir'])):
        trusted_path(target, directory=True, missing=True)
    require(not CONFIG.exists() and not REGISTRY.exists() and not SUDOERS.exists(), 'already_installed')
    require(not INSTALL.exists() or not any(INSTALL.iterdir()), 'install_directory_not_empty')
    require(not Path(config['state_dir']).exists() or not any(Path(config['state_dir']).iterdir()), 'state_directory_not_empty')
    source = Path(__file__).resolve().parent
    for name in FILES:
        require((source / name).is_file() and not (source / name).is_symlink(), 'source_missing')


def install(config):
    preflight(config)
    user = config['gateway_user']
    rule = (f'Defaults:{user} env_reset, !setenv\n'
            f'{user} ALL=(root) NOPASSWD: {INSTALL}/host_gateway.py ""\n')
    # Validate before activation. A hidden fragment is ignored by sudo includedir.
    fd, temporary = tempfile.mkstemp(prefix='.dmc-', dir=SUDOERS.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(rule)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o440)
        command(['/usr/sbin/visudo', '-cf', str(temporary)])
        INSTALL.mkdir(mode=0o755, parents=True, exist_ok=True)
        CONFIG.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        state = Path(config['state_dir'])
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(state, 0o700)
        source = Path(__file__).resolve().parent
        for name in FILES:
            destination = INSTALL / name
            # Ignore ambient Python environment/user site in privileged entrypoints.
            content = (source / name).read_text().splitlines(keepends=True)
            content[0] = f'#!{python_executable()} -Es\n'
            with destination.open('x') as stream:
                stream.write(''.join(content))
            os.chmod(destination, 0o755)
        atomic(CONFIG, config)
        os.chmod(CONFIG, 0o644)  # Dispatcher must read this non-secret policy.
        atomic(REGISTRY, {'schema':2, 'revision':0, 'allowed_roots':config['allowed_roots'], 'projects':{}})
        # Last step grants access, only once every dependency exists.
        os.replace(temporary, SUDOERS)
        directory = os.open(str(SUDOERS.parent), os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'install'))
    parser.add_argument('--gateway-user', required=True, help='Dedicated existing nonroot account; no Docker/sudo groups')
    parser.add_argument('--docker-path', required=True, help='Absolute real path to root-owned Docker binary (no symlinks)')
    parser.add_argument('--allowed-root', action='append', required=True, help='Existing root-owned Compose discovery root; repeatable')
    parser.add_argument('--state-dir', default=str(STATE))
    args = parser.parse_args()
    config = {'gateway_user':args.gateway_user, 'docker_path':args.docker_path,
              'allowed_roots':args.allowed_root, 'state_dir':args.state_dir}
    try:
        (install if args.action == 'install' else preflight)(config)
    except Exception as error:
        print(f'Installation refused: {getattr(error, "code", str(error))}', file=sys.stderr)
        return 1
    print(json.dumps({'action':args.action, 'config':config, 'registry':str(REGISTRY)}))
    print('Administrator: lock password authentication for this dedicated account and remove all other keys/grants.')
    print('Place your actual public key after this authorized_keys prefix (do not install the placeholder):')
    print(f'restrict,command="{INSTALL}/active_dispatch.py" <YOUR_PUBLIC_KEY>')
    print('Use SSH alias docker-maintenance-center with explicit HostName, User, Port, IdentityFile and pinned known_hosts.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
