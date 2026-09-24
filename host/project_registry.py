#!/usr/bin/python3
"""Copyright (c) docker-maintenance-center contributors. MIT licensed.
Root-owned registry and real Compose transactions; no shell or raw Docker route.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import selectors
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

PROTOCOL = 'project007-v2'
DOCKER = '/usr/bin/docker'
ID = re.compile(r'[A-Z][A-Z0-9]{1,31}')
SERVICE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
DIGEST = re.compile(r'sha256:[a-f0-9]{64}')
REF = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,254}')
FIELDS = {'id','name','compose_path','compose_project','services','adapter','active','policy','backup_exempt','backup_paths','health','revision'}
ARGS = {'list':set(), 'discover':set(), 'preview':{'compose_path','services'},
        'enroll':{'token','name','policy','backup_exempt','backup_paths','health','expected_revision'},
        'configure':{'project','expected_revision','policy','backup_exempt','backup_paths','health'},
        'remove':{'project','expected_revision'}, 'status':{'project'}, 'health':{'project'},
        'logs':{'project'}, 'operation-status':{'project'}, 'plan-update':{'project'},
        'apply-update':{'project','plan_id'}}

class RegistryError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

def require(condition, code):
    if not condition:
        raise RegistryError(code)

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_key')
        result[key] = value
    return result

def parse(raw):
    require(len(raw) <= 65536, 'request_limit')
    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict), 'request_invalid')
    action = value.get('action')
    require(isinstance(action, str) and action in ARGS, 'action_invalid')
    keys = set(value) - {'action','request_id'}
    if action in {'status','health','logs'} and 'tail' in keys:
        require(type(value['tail']) is int and value['tail'] in {20,50,100,200}, 'tail_invalid')
        keys.remove('tail')
    require(keys == ARGS[action], 'request_invalid')
    require(isinstance(value.get('request_id'), str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value['request_id']), 'request_id_invalid')
    return value

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',',':')).encode()).hexdigest()

def atomic(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8))
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()

def redact_logs(text):
    # Redact before truncation: a bounded response must not expose a cut PEM block.
    text = re.sub(r'(?s)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?(?:-----END [^-\r\n]*PRIVATE KEY-----|$)', '<redacted-private-key>', text)
    text = re.sub(r'(?s)^.*?-----END [^-\r\n]*PRIVATE KEY-----', '<redacted-private-key>', text)
    text = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer <redacted>', text)
    text = re.sub(r'\bsk-[A-Za-z0-9_-]{8,}\b', '<redacted-key>', text)
    text = re.sub(r'''(?i)(\b(?:authorization|api[_-]?key|token|password|passwd|secret|cookie)\b\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\r\n,;]+)''', r'\1<redacted>', text)
    return re.sub(r'(?i)(https?://)[^\s/@]+:[^\s/@]+@', r'\1<redacted>@', text)

def canonical_mounts(container):
    # Docker inspect does not guarantee Mounts order. Preserve every field.
    return sorted(container.get('Mounts') or [],
                  key=lambda mount: json.dumps(mount, sort_keys=True, separators=(',', ':')))

def runtime_contract(container, definition):
    config = dict(container['Config'])
    for key in ('Image','Hostname','Labels'):
        config.pop(key, None)
    # Image defaults may legitimately change with the approved image. Explicit
    # Compose overrides remain in the contract; implicit defaults do not.
    for source,target in (('command','Cmd'),('entrypoint','Entrypoint'),('user','User'),
                          ('working_dir','WorkingDir'),('stop_signal','StopSignal'),
                          ('healthcheck','Healthcheck')):
        if source not in definition:
            config.pop(target, None)
    explicit_env = definition.get('environment') or {}
    config['Env'] = sorted(item for item in config.get('Env') or [] if item.split('=',1)[0] in explicit_env)
    host = dict(container.get('HostConfig') or {})
    # Engine-generated links to this container are not deployment policy.
    host.pop('ContainerIDFile', None)
    networks = {}
    for name, network in container.get('NetworkSettings',{}).get('Networks',{}).items():
        aliases = sorted(value for value in network.get('Aliases') or []
                         if value not in {container['Id'],container['Id'][:12]})
        networks[name] = {'aliases':aliases,'ipam':network.get('IPAMConfig'),
                          'links':network.get('Links'),'driver_options':network.get('DriverOpts')}
    return {'config':config,'host':host,'mounts':canonical_mounts(container),'networks':networks}

def literal_config(value, encode=True):
    if isinstance(value, str):
        return value.replace('$', '$$') if encode else value.replace('$$','$')
    if isinstance(value, list):
        return [literal_config(item,encode) for item in value]
    if isinstance(value, dict):
        return {key:literal_config(item,encode) for key,item in value.items()}
    return value

def validate_mutable_runtime(container, definition):
    # Docker update can change these without changing Compose's creation hash.
    host = container.get('HostConfig') or {}
    limits = definition.get('deploy',{}).get('resources',{}).get('limits',{})
    reservations = definition.get('deploy',{}).get('resources',{}).get('reservations',{})
    memory = int(definition.get('mem_limit',limits.get('memory',0)))
    expected = {
        'Memory':memory, 'MemoryReservation':int(definition.get('mem_reservation',reservations.get('memory',0))),
        'MemorySwap':int(definition.get('memswap_limit',memory*2 if memory else 0)),
        'NanoCpus':int(float(definition.get('cpus',limits.get('cpus',0)))*1000000000),
        'CpuShares':int(definition.get('cpu_shares',0)),
        'CpuPeriod':int(definition.get('cpu_period',0)), 'CpuQuota':int(definition.get('cpu_quota',0)),
        'CpuRealtimePeriod':int(definition.get('cpu_rt_period',0)),
        'CpuRealtimeRuntime':int(definition.get('cpu_rt_runtime',0)),
        'CpusetCpus':definition.get('cpuset',''), 'CpusetMems':'',
        'BlkioWeight':int(definition.get('blkio_config',{}).get('weight',0)),
    }
    require(all(host.get(key,0 if isinstance(value,int) else '') == value for key,value in expected.items()), 'runtime_policy_drift')
    pids = definition.get('pids_limit',limits.get('pids'))
    require(host.get('PidsLimit') in (None,0,-1) if pids in (None,0,-1) else host.get('PidsLimit') == int(pids), 'runtime_policy_drift')
    restart = definition.get('restart','no').split(':',1)
    require(host.get('RestartPolicy',{}).get('Name','no') == restart[0] and
            host.get('RestartPolicy',{}).get('MaximumRetryCount',0) == (int(restart[1]) if len(restart)>1 else 0), 'runtime_policy_drift')



def non_image_config(config):
    result = json.loads(json.dumps(config))
    for service in result['services'].values():
        service.pop('image', None)
        service.pop('pull_policy', None)
    return result


class Runner:
    def __init__(self, docker=DOCKER):
        self.descriptors = ()
        self.docker = docker

    def run(self, argv, timeout=180):
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={'PATH':'/usr/bin:/bin','HOME':'/var/empty','LANG':'C.UTF-8',
                                     'DOCKER_CONFIG':'/etc/docker-maintenance-center/docker-auth'},
                                pass_fds=self.descriptors, timeout=timeout)
        require(result.returncode == 0, 'command_failed')
        require(len(result.stdout) <= 8 * 1024 * 1024, 'command_output_limit')
        return result.stdout.decode('utf-8')

    def logs(self, identifier, tail):
        # Read both Docker log streams with a hard memory/time ceiling. On limit,
        # return no partial raw material (it may start inside a credential block).
        with subprocess.Popen([self.docker,'logs','--tail',str(tail),identifier],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={'PATH':'/usr/bin:/bin','HOME':'/var/empty','LANG':'C.UTF-8',
                     'DOCKER_CONFIG':'/etc/docker-maintenance-center/docker-auth'},
                pass_fds=self.descriptors) as process:
            chunks, size, deadline = {process.stdout:[],process.stderr:[]}, 0, time.monotonic() + 30
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                selector.register(process.stderr, selectors.EVENT_READ)
                try:
                    while selector.get_map():
                        require(time.monotonic() < deadline, 'log_timeout')
                        for key, _ in selector.select(min(1, max(0, deadline-time.monotonic()))):
                            chunk = os.read(key.fileobj.fileno(), 8192)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            size += len(chunk)
                            require(size <= 1024*1024, 'log_output_limit')
                            chunks[key.fileobj].append(chunk)
                    require(process.wait(timeout=max(.1, deadline-time.monotonic())) == 0, 'command_failed')
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
            streams = [redact_logs(b''.join(chunks[stream]).decode('utf-8', errors='replace'))[-8192:]
                       for stream in (process.stdout,process.stderr)]
            return '\n'.join(streams)

class Registry:
    def __init__(self, path='/etc/docker-maintenance-center/registry.json',
                 state='/var/lib/docker-maintenance-center/host', runner=None,
                 lock_paths=None, clock=time.time, sleeper=time.sleep, owner=0,
                 docker=DOCKER, allowed_roots=None):
        self.path, self.state = Path(path), Path(state)
        self.docker_path = docker
        self.runner, self.clock, self.sleeper = runner or Runner(docker), clock, sleeper
        self.owner, self.allowed_roots = owner, allowed_roots
        self.lock_paths = lock_paths if lock_paths is not None else ['/run/lock/docker-maintenance-center.lock']
        self.held = ()

    @classmethod
    def configured(cls, config):
        return cls(state=config['state_dir'], docker=config['docker_path'], allowed_roots=config['allowed_roots'])

    def trusted(self, path, directory=False):
        if self.owner == 0:
            from host_config import trusted_path
            trusted_path(path, directory=directory)
        info = Path(path).lstat()
        require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and
                info.st_uid == self.owner and not info.st_mode & 0o022, 'untrusted_state')

    def load(self):
        self.trusted(self.path)
        with self.path.open() as stream:
            data = json.load(stream, object_pairs_hook=unique)
        require(set(data) == {'schema','revision','allowed_roots','projects'} and data['schema'] == 2 and
                type(data['revision']) is int and data['revision'] >= 0, 'registry_invalid')
        require(isinstance(data['allowed_roots'], list) and data['allowed_roots'], 'roots_invalid')
        for root in data['allowed_roots']:
            require(isinstance(root, str) and root != '/' and os.path.realpath(root) == root and os.path.isdir(root), 'roots_invalid')
        if self.allowed_roots is not None:
            require(data['allowed_roots'] == self.allowed_roots, 'roots_config_mismatch')
        require(isinstance(data['projects'], dict), 'registry_invalid')
        for key, item in data['projects'].items():
            require(isinstance(item, dict) and set(item) in (FIELDS, FIELDS | {'last_change_ref'}) and key == item['id'] and ID.fullmatch(key), 'registry_invalid')
            require(type(item['active']) is bool and type(item['revision']) is int and item['revision'] >= 1, 'registry_invalid')
            require(item['adapter'] == 'compose', 'adapter_unsupported')
        return data

    def ensure_state(self):
        if self.owner == 0:
            from host_config import trusted_path
            trusted_path(self.state, directory=True, missing=True)
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.trusted(self.state, True)
        require(stat.S_IMODE(self.state.stat().st_mode) == 0o700, 'untrusted_state')
        for name in ('plans','previews','operations','audit','recovery'):
            child = self.state / name
            child.mkdir(mode=0o700, exist_ok=True)
            self.trusted(child, True)

    @contextlib.contextmanager
    def locked(self):
        descriptors = []
        try:
            for path in self.lock_paths:
                if self.owner == 0:
                    from host_config import LOCK, lock_directory, trusted_path
                    if Path(path) == LOCK:
                        lock_directory()
                    else:
                        trusted_path(Path(path).parent, directory=True)
                fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                descriptors.append(fd)
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner and not info.st_mode & 0o022, 'lock_invalid')
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RegistryError('operation_busy')
            self.held = tuple(descriptors)
            if hasattr(self.runner, 'descriptors'):
                self.runner.descriptors = self.held
            yield
        finally:
            self.held = ()
            if hasattr(self.runner, 'descriptors'):
                self.runner.descriptors = ()
            for fd in reversed(descriptors):
                os.close(fd)

    def safe_path(self, value, data, file=False):
        require(isinstance(value, str) and os.path.isabs(value) and os.path.realpath(value) == value, 'path_boundary')
        path = Path(value)
        require(any(path != Path(root) and Path(root) in path.parents for root in data['allowed_roots']), 'path_boundary')
        blocked = {'docker-maintenance-center','host-state','releases','release','history','historical','backups','.git'}
        require(not any(part.lower() in blocked for part in path.parts), 'path_boundary')
        require(path != self.state and self.state not in path.parents, 'path_boundary')
        require(path.is_file() if file else path.exists(), 'path_missing')
        if self.owner == 0:
            from host_config import trusted_path
            trusted_path(path, directory=not file)
        return path

    def docker(self, *args):
        return self.runner.run([self.docker_path] + list(args))

    def containers(self):
        identifiers = self.docker('ps','-aq','--filter','label=com.docker.compose.project').split()
        if not identifiers:
            return []
        require(all(re.fullmatch(r'[a-f0-9]{12,64}', value) for value in identifiers), 'docker_output_invalid')
        return json.loads(self.docker('inspect', *identifiers))

    def compose_files(self, container, data):
        files = container['Config']['Labels']['com.docker.compose.project.config_files'].split(',')
        if len(files) == 1:
            execution = Path(files[0])
            if (execution.name == 'execution.json' and execution.parent.parent == self.state / 'recovery'
                    and re.fullmatch(r'[a-f0-9]{16}',execution.parent.name)):
                self.trusted(execution)
                self.trusted(execution.parent / 'material.json')
                saved = json.loads((execution.parent / 'material.json').read_text())
                service = container['Config']['Labels'].get('com.docker.compose.service')
                require(service in saved['material']['services'] and saved['project']['compose_path'] == saved['material']['compose_files'][0], 'deployment_ambiguous')
                require(container['Config']['Labels']['com.docker.compose.project'] == saved['material']['compose_project'], 'deployment_ambiguous')
                files = saved['material']['compose_files']
        if len(files) > 1:
            override = Path(files[-1])
            if (override.name == 'override.json' and override.parent.parent == self.state / 'recovery'
                    and re.fullmatch(r'[a-f0-9]{16}',override.parent.name)):
                self.trusted(override)
                files.pop()
        require(files and len(files) == len(set(files)), 'compose_files_invalid')
        for path in files:
            self.safe_path(path,data,True)
        return files

    def deployed(self, data):
        groups = {}
        for container in self.containers():
            labels = container.get('Config',{}).get('Labels') or {}
            path = labels.get('com.docker.compose.project.config_files','')
            project = labels.get('com.docker.compose.project','')
            service = labels.get('com.docker.compose.service','')
            if (not SERVICE.fullmatch(project) or not SERVICE.fullmatch(service)
                    or project == 'docker-maintenance-center'
                    or labels.get('io.docker-maintenance-center.protected') == 'true'):
                continue
            try:
                path = self.compose_files(container,data)[0]
            except (OSError, RegistryError):
                continue
            if labels.get('com.docker.compose.oneoff','False').lower() == 'true':
                continue
            groups.setdefault((path,project), []).append(container)
        return groups
    def frozen_args(self, project, path, execution):
        return [self.docker_path,'compose','--env-file','/dev/null','--project-directory',str(Path(path).parent),
                '-p',project,'-f',str(execution)]

    def config_hashes(self, project, path, config):
        with tempfile.TemporaryDirectory(prefix='config-', dir=str(self.state)) as directory:
            execution = Path(directory) / 'config.json'
            atomic(execution, literal_config(config))
            output = self.runner.run(self.frozen_args(project,path,execution) + ['config','--hash','*'])
        hashes = {}
        for line in output.splitlines():
            fields = line.split()
            require(len(fields) == 2 and SERVICE.fullmatch(fields[0]) and re.fullmatch(r'[a-f0-9]{64}',fields[1]), 'compose_hash_invalid')
            hashes[fields[0]] = fields[1]
        return hashes


    def inspect(self, path, services, data, project=None):
        self.safe_path(path, data, True)
        require(isinstance(services,list) and services and len(services) == len(set(services)) and
                all(isinstance(s,str) and SERVICE.fullmatch(s) for s in services), 'services_invalid')
        matches = [(p,cs) for (f,p),cs in self.deployed(data).items() if f == path and (project is None or p == project)]
        require(len(matches) == 1, 'deployment_ambiguous')
        project, containers = matches[0]
        files = self.compose_files(containers[0],data)
        require(all(self.compose_files(c,data) == files for c in containers),'compose_files_drift')
        from compose_inputs import validate_source
        for filename in files:
            validate_source(filename, require)
        file_args = [arg for filename in files for arg in ('-f',filename)]
        raw = self.runner.run([self.docker_path,'compose','--env-file','/dev/null','-p',project] + file_args + ['config','--format','json'])
        # Compose renders literal dollars as $$ so its output can be reloaded.
        # Keep the in-memory model decoded; freeze it exactly once on disk.
        config = literal_config(json.loads(raw, object_pairs_hook=unique), False)
        require(isinstance(config.get('services'),dict) and set(services) <= set(config['services']), 'services_invalid')
        # Hash the captured render, never a second read of mutable includes/env.
        hashes = self.config_hashes(project,path,config)
        scoped = [c for c in self.containers() if c.get('Config',{}).get('Labels',{}).get('com.docker.compose.project') == project
                  and c.get('Config',{}).get('Labels',{}).get('com.docker.compose.service') in services]
        require({c['Id'] for c in scoped} == {c['Id'] for c in containers if c['Config']['Labels'].get('com.docker.compose.service') in services}, 'deployment_ambiguous')
        require(not config.get('include'), 'compose_input_unbound')
        for group in ('configs','secrets'):
            require(all(not item.get('file') and not item.get('environment') for item in config.get(group,{}).values()), 'compose_input_unbound')
        selected, mounts, refs = {}, [], {}
        for service in sorted(services):
            definition = config['services'][service]
            reference = definition.get('image','')
            require(isinstance(reference,str) and REF.fullmatch(reference) and not reference.startswith('sha256:') and not definition.get('build'), 'image_ref_invalid')
            require(not definition.get('post_start') and not definition.get('pre_stop') and not definition.get('develop'), 'hooks_forbidden')
            require(not definition.get('env_file') and not definition.get('label_file'), 'compose_input_unbound')
            items = [c for c in containers if c['Config']['Labels'].get('com.docker.compose.service') == service]
            require(len(items) == 1, 'service_identity_invalid')
            c = items[0]
            require(DIGEST.fullmatch(c['Image']) and c['State']['Status'] == 'running', 'service_not_running')
            validate_mutable_runtime(c,definition)
            if not definition.get('network_mode'):
                expected_networks = {config.get('networks',{}).get(name,{}).get('name',project+'_'+name)
                                     for name in definition.get('networks',{'default':{}})}
                require(set(c.get('NetworkSettings',{}).get('Networks',{})) == expected_networks, 'runtime_policy_drift')
            labels = c['Config']['Labels']
            execution = Path(labels['com.docker.compose.project.config_files'].split(',')[-1])
            if execution.name == 'execution.json' and execution.parent.parent == self.state / 'recovery':
                self.trusted(execution)
                frozen = json.loads(execution.read_text())
                frozen = literal_config(frozen,False)
                require(non_image_config(frozen) == non_image_config(config), 'compose_runtime_drift')
                require(c['Image'] == frozen['services'][service]['image']
                        and c['Config']['Image'] == c['Image'], 'image_ref_drift')
                expected_hash = self.config_hashes(project,path,frozen).get(service)
                saved = json.loads((execution.parent / 'material.json').read_text())
                require(runtime_contract(c,definition) == saved['material']['services'][service]['contract'], 'runtime_policy_drift')
            else:
                expected_hash = hashes.get(service)
            require(expected_hash is not None and labels.get('com.docker.compose.config-hash') == expected_hash, 'compose_runtime_drift')
            # Container refs must still be the original ref, or a digest of that repository.
            actual = c['Config']['Image']
            repository = reference.split('@')[0].rsplit(':',1)[0] if ':' in reference.rsplit('/',1)[-1] else reference.split('@')[0]
            frozen_execution = (execution.name == 'execution.json' and
                                execution.parent.parent == self.state / 'recovery')
            require(actual == reference or
                    '@' not in reference and actual.startswith(repository + '@sha256:') or
                    frozen_execution and actual == c['Image'], 'image_ref_drift')
            selected[service] = {'id':c['Id'],'image':c['Image'],'started':c['State'].get('StartedAt'),
                                 'restarts':c.get('RestartCount',0), 'runtime':digest({'config':c['Config'],'host':c.get('HostConfig'),'mounts':canonical_mounts(c)}),
                                 'contract':runtime_contract(c,definition)}
            refs[service] = reference
            for mount in c.get('Mounts',[]):
                mounts.append({'service':service,'source':mount.get('Source',''),'target':mount.get('Destination',''),'type':mount.get('Type','')})
        material = {'compose_hash':hashlib.sha256(Path(path).read_bytes()).hexdigest(),'canonical_hash':digest(config),
                    'compose_project':project,'services':selected,'refs':refs,'compose_files':files,'effective_config':config,
                    'file_hashes':{filename:hashlib.sha256(Path(filename).read_bytes()).hexdigest() for filename in files}}
        return material, mounts

    def options(self, request, definition, material, mounts, data):
        require(request['policy'] in {'auto','manual','notify'} and type(request['backup_exempt']) is bool, 'policy_invalid')
        health = request['health']
        require(isinstance(health,dict) and health.get('mode') in {'docker','running','http'}, 'health_invalid')
        require(set(health) == ({'mode','url'} if health['mode'] == 'http' else {'mode'}), 'health_invalid')
        if health['mode'] == 'http':
            url = urlsplit(health['url'])
            require(url.scheme in {'http','https'} and url.hostname in {'127.0.0.1','localhost','::1'} and not url.username and not url.password and not url.fragment, 'health_url_invalid')
        paths = request['backup_paths']
        require(isinstance(paths,list) and not paths, 'backup_unsupported')
        require(request['backup_exempt'] is True, 'backup_exemption_required')
        definition.update(policy=request['policy'], backup_exempt=request['backup_exempt'], backup_paths=paths, health=health)

    def record(self, kind, key):
        path = self.state / kind / (key + '.json')
        if not path.exists():
            return None
        self.trusted(path)
        with path.open() as stream:
            return json.load(stream, object_pairs_hook=unique)

    def operation(self, project):
        value = self.record('operations',project)
        if value is None:
            return {'status':'idle','code':'idle','operation_ref':None,'action':None,'recovery':'not_required','recovery_point':None}
        return {key:value.get(key) for key in ('status','code','operation_ref','action','recovery','recovery_point','current_version','target_version')}

    def clear_to_change(self, data):
        for project in data['projects']:
            require(self.operation(project)['status'] not in {'running','unknown'}, 'operation_unresolved')

    def token_record(self, kind, token):
        require(isinstance(token,str) and re.fullmatch(r'[A-Za-z0-9_-]{32,64}',token), 'token_invalid')
        key = hashlib.sha256(token.encode()).hexdigest()
        value = self.record(kind,key)
        require(value is not None and not value.get('consumed'), 'token_invalid')
        require(value['expires_at'] > self.clock(), 'plan_expired')
        return key, value

    def targets(self, material):
        result = {}
        arch = {'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine(),platform.machine())
        for service, reference in material['refs'].items():
            value = json.loads(self.docker('manifest','inspect','--verbose',reference))
            identity = self.manifest_identity(value)
            entries = value if isinstance(value,list) else [value]
            matches = []
            for item in entries:
                desc = item.get('Descriptor',{})
                p = desc.get('platform',{})
                if p.get('os') == 'linux' and p.get('architecture') == arch:
                    bodies = [item[k] for k in ('SchemaV2Manifest', 'OCIManifest') if k in item]
                    require(len(bodies) == 1 and isinstance(bodies[0], dict), 'manifest_invalid')
                    image = bodies[0].get('config',{}).get('digest','')
                    manifest = desc.get('digest','')
                    if DIGEST.fullmatch(image) and DIGEST.fullmatch(manifest):
                        matches.append({'image':image,'manifest':manifest,'original_identity':identity})
            require(len(matches) == 1,'registry_platform_invalid')
            result[service] = matches[0]
        return result

    def manifest_identity(self, value):
        entries = value if isinstance(value,list) else [value]
        descriptors = [item.get('Descriptor',{}) for item in entries]
        require(descriptors and all(DIGEST.fullmatch(item.get('digest','')) for item in descriptors), 'manifest_invalid')
        return digest(sorted(descriptors, key=lambda item:item['digest']))

    def readonly(self, definition, action, tail=50):
        rows = []
        for (path, project), containers in self.deployed(self.load()).items():
            if (path,project) != (definition['compose_path'],definition['compose_project']):
                continue
            for c in containers:
                service = c['Config']['Labels'].get('com.docker.compose.service')
                if service not in definition['services']:
                    continue
                row = {'id':c['Id'],'name':c.get('Name','').lstrip('/'),'service':service,
                       'image_id':c['Image'],'image_ref':c['Config']['Image'],'status':c['State']['Status'],
                       'health':c['State'].get('Health',{}).get('Status','none'),'restart_count':c.get('RestartCount',0)}
                row['version'] = None
                if action == 'logs':
                    row['logs'] = self.runner.logs(c['Id'],tail)
                rows.append(row)
        mode = definition['health']['mode']
        healthy = len(rows) == len(definition['services']) and all(r['status'] == 'running' and (mode != 'docker' or r['health'] == 'healthy') for r in rows)
        if healthy and mode == 'http':
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
                with opener.open(definition['health']['url'],timeout=5) as response:
                    healthy = response.status == 200
            except Exception:
                healthy = False
        return {'project':definition['id'],'containers':rows,'overall':'healthy' if healthy else 'unhealthy',
                'health_mode':mode,'warnings':['running_only_health'] if mode == 'running' else []}

    def wait_healthy(self, definition, expected):
        stable, previous = 0, None
        for _ in range(60):
            status = self.readonly(definition,'health')
            identity = [(r['service'],r['id'],r['image_id'],r['restart_count']) for r in sorted(status['containers'],key=lambda r:r['service'])]
            good = status['overall'] == 'healthy' and {r['service']:r['image_id'] for r in status['containers']} == expected
            stable = stable + 1 if good and identity == previous else (1 if good else 0)
            if stable >= 4:
                return status
            previous = identity
            self.sleeper(3)
        raise RegistryError('health_failed')

    def generic_apply(self, definition, plan, reference):
        recovery = self.state / 'recovery' / reference
        recovery.mkdir(mode=0o700)
        current = {s:v['image'] for s,v in plan['material']['services'].items()}
        atomic(recovery / 'material.json', {'project':definition,'current':current,'material':plan['material'],'data_recovery':False})
        for service, image in current.items():
            self.docker('image','tag',image,'docker-maintenance-center-recovery/' + definition['id'].lower() + '-' + digest(service)[:12] + ':' + reference)
        effective = json.loads(json.dumps(plan['material']['effective_config']))
        for service, target in plan['targets'].items():
            original = plan['material']['refs'][service]
            self.runner.run([self.docker_path,'pull',original],timeout=900)
            inspected = json.loads(self.docker('image','inspect',original))[0]
            require(inspected['Id'] == target['image'], 'manifest_drift')
            repo = original.split('@')[0]
            if ':' in repo.rsplit('/',1)[-1]:
                repo = repo.rsplit(':',1)[0]
            identities = []
            for pinned in inspected.get('RepoDigests',[]):
                if pinned.startswith(repo + '@') and DIGEST.fullmatch(pinned.split('@')[-1]):
                    identities.append(self.manifest_identity(json.loads(self.docker('manifest','inspect','--verbose',pinned))))
            require(target['original_identity'] in identities, 'manifest_drift')
            # Config digest: immutable and locally resolvable after a tag pull.
            require(json.loads(self.docker('image','inspect',target['image']))[0]['Id'] == target['image'], 'manifest_drift')
            effective['services'][service].update(image=target['image'],pull_policy='never')
        fresh, _ = self.inspect(definition['compose_path'],definition['services'],self.load(),definition['compose_project'])
        require(fresh == plan['material'], 'plan_stale')
        execution = recovery / 'execution.json'
        atomic(execution, literal_config(effective))
        # A lost response after this boundary is uncertain. No original input is
        # read by Compose, and automatic pulls/builds/dependency starts are off.
        plan['recreation_started'] = True
        self.runner.run(self.frozen_args(definition['compose_project'],definition['compose_path'],execution) +
                        ['up','-d','--no-deps','--no-build','--pull','never','--force-recreate'] + definition['services'],timeout=900)
        status = self.wait_healthy(definition,{s:v['image'] for s,v in plan['targets'].items()})
        verified, _ = self.inspect(definition['compose_path'],definition['services'],self.load(),definition['compose_project'])
        require(all(verified['services'][s]['contract'] == plan['material']['services'][s]['contract'] for s in definition['services']), 'runtime_policy_drift')
        return status

    def handle(self, request):
        request = parse(json.dumps(request).encode())
        if request['action'] == 'list':
            data = self.load()
            return {'revision':data['revision'],'allowed_roots':data['allowed_roots'],'projects':list(data['projects'].values())}
        self.ensure_state()
        if request['action'] == 'operation-status':
            data = self.load()
            project = request['project']
            require(isinstance(project,str) and ID.fullmatch(project) and project in data['projects'],'project_not_allowed')
            # Atomic records remain readable while a worker holds the locks.
            return self.operation(project)
        with self.locked():
            return self._handle(request)

    def _handle(self, request):
        data, action = self.load(), request['action']
        if action == 'discover':
            managed = {(item['compose_path'], item['compose_project'])
                       for item in data['projects'].values() if item['active']}
            return {'candidates':[{'compose_path':path,'compose_project':project,'name':project,
                    'services':sorted({c['Config']['Labels']['com.docker.compose.service'] for c in cs})}
                    for (path,project),cs in sorted(self.deployed(data).items())
                    if (path,project) not in managed]}
        if action == 'preview':
            material, mounts = self.inspect(request['compose_path'],request['services'],data)
            identity = {'compose_path':request['compose_path'],'compose_project':material['compose_project']}
            identifier = 'P' + digest(identity)[:24].upper()
            for existing in data['projects'].values():
                if all(existing[k] == v for k,v in identity.items()):
                    identifier = existing['id']
            definition = dict(identity,id=identifier,name=material['compose_project'],services=sorted(request['services']),
                              active=True,policy='auto',backup_exempt=False,backup_paths=[],health={'mode':'docker'},revision=1)
            definition['adapter'] = 'compose'
            token = secrets.token_urlsafe(32)
            expires = int(self.clock()) + 300
            atomic(self.state / 'previews' / (hashlib.sha256(token.encode()).hexdigest()+'.json'),
                   {'definition':definition,'material':material,'expires_at':expires})
            return {'token':token,'expires_at':expires,'definition':definition,'mounts':mounts,
                    'backup_supported':False,'warnings':['backup_exemption_required']}
        if action == 'enroll':
            self.clear_to_change(data)
            require(type(request['expected_revision']) is int and request['expected_revision'] == data['revision'],'revision_conflict')
            key, preview = self.token_record('previews',request['token'])
            definition = preview['definition']
            material, mounts = self.inspect(definition['compose_path'],definition['services'],data,definition['compose_project'])
            require(material == preview['material'],'preview_stale')
            old = data['projects'].get(definition['id'])
            require(not old or not old['active'] and old['compose_path'] == definition['compose_path'] and old['compose_project'] == definition['compose_project'], 'project_conflict')
            require(isinstance(request['name'],str) and 1 <= len(request['name']) <= 80 and not any(ord(c)<32 for c in request['name']), 'name_invalid')
            definition['name'] = request['name']
            definition['revision'] = old['revision'] + 1 if old else 1
            self.options(request,definition,material,mounts,data)
            preview['consumed'] = True
            atomic(self.state / 'previews' / (key+'.json'),preview)
            return self.commit(data,definition,request['request_id'])
        project = request.get('project')
        require(isinstance(project,str) and ID.fullmatch(project) and project in data['projects'],'project_not_allowed')
        definition = data['projects'][project]
        if action == 'operation-status':
            return self.operation(project)
        require(definition['active'],'project_inactive')
        if action in {'status','health','logs'}:
            return self.readonly(definition,action,request.get('tail',50))
        self.clear_to_change(data)
        if action in {'configure','remove'}:
            require(type(request['expected_revision']) is int and request['expected_revision'] == data['revision'],'revision_conflict')
            if action == 'configure':
                material,mounts = self.inspect(definition['compose_path'],definition['services'],data,definition['compose_project'])
                self.options(request,definition,material,mounts,data)
            else:
                definition['active'] = False
            definition['revision'] += 1
            return self.commit(data,definition,request['request_id'])
        material,mounts = self.inspect(definition['compose_path'],definition['services'],data,definition['compose_project'])
        self.options(definition,definition,material,mounts,data)
        require(definition['adapter'] == 'compose', 'adapter_unsupported')
        operation_action = 'update'
        if action.startswith('plan-'):
            targets = self.targets(material)
            current = {s:v['image'] for s,v in material['services'].items()}
            target = {s:v['image'] for s,v in targets.items()}
            if current == target:
                return {'no_update':True}
            token,expires = secrets.token_urlsafe(32),int(self.clock())+300
            versions = {'current_version':None,'target_version':None,'latest_version':None}
            recovery_point = {'images':{},'data_backup':False,'backup_identity':None,
                              'backup_capable':False,'backup_planned':False,'backup_exempt':True}
            stored = {'project':project,'action':operation_action,'revision':definition['revision'],'material':material,
                      'targets':targets,'expires_at':expires,'recovery':'unknown','recovery_point':recovery_point,
                      'versions':versions,'current':current,'target':target,'consumed':False}
            atomic(self.state / 'plans' / (hashlib.sha256(token.encode()).hexdigest()+'.json'),stored)
            return {'project':project,'action':operation_action,'plan_id':token,'expires_at':expires,
                    'current':'sha256:'+digest(current),'target':'sha256:'+digest(target),
                    'details':dict(versions,images=[{'service':s,'current':current[s],'target':target[s]} for s in current],
                                   recovery='unknown',recovery_point=recovery_point),
                    'image_ids':{s:{'current':current[s],'target':target[s]} for s in current}}
        require(action != 'apply-update' or definition['policy'] != 'notify','policy_notify_only')
        key, plan = self.token_record('plans',request['plan_id'])
        require(plan['project'] == project and plan['action'] == operation_action and plan['revision'] == definition['revision'], 'plan_stale')
        plan['consumed'] = True
        atomic(self.state / 'plans' / (key+'.json'),plan)
        require(material == plan['material'],'plan_stale')
        require(self.targets(material) == plan['targets'],'manifest_drift')
        require(plan['expires_at'] > self.clock(),'plan_expired')
        reference = key[:16]
        outcome = {'status':'unknown','code':'operation_uncertain','operation_ref':reference,'action':operation_action,
                   'recovery':'unknown','recovery_point':{'images':{},'data_backup':False,'backup_identity':None},
                   **plan.get('versions',{})}
        atomic(self.state / 'operations' / (project+'.json'),outcome)
        atomic(self.state / 'audit' / (reference+'.json'),dict(outcome,project=project,started_at=self.clock(),revision=definition['revision']))
        try:
            self.generic_apply(definition,plan,reference)
            outcome.update(status='succeeded',code='ok',recovery='not_required',
                           recovery_point={'images':plan['current'],'data_backup':False,'backup_identity':reference})
        except Exception as error:
            # A lost command response is not proof that business state stayed unchanged.
            outcome.update(status='unknown',code=getattr(error,'code','operation_uncertain'),recovery='unknown')
            if not plan.get('recreation_started'):
                # Pull/tag/snapshot failures cannot have recreated the business
                # service; unlike an interrupted Compose up, rejection is known.
                outcome.update(status='failed',recovery='not_required')
        atomic(self.state / 'operations' / (project+'.json'),outcome)
        atomic(self.state / 'audit' / (reference+'-result.json'),dict(outcome,project=project,finished_at=self.clock()))
        return outcome

    def commit(self, data, definition, request_id):
        definition['last_change_ref'] = request_id
        data['revision'] += 1
        data['projects'][definition['id']] = definition
        atomic(self.path,data)
        return {'revision':data['revision'],'project':definition}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RegistryError('health_redirect_forbidden')
