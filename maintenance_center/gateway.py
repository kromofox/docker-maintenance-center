"""Restricted SSH transport for the maintenance host protocol."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import selectors
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .core import MaintenanceError

ALLOWED_PROTOCOLS = frozenset({"project007-v2"})


class GatewayFailure(MaintenanceError):
    pass


@dataclass(frozen=True)
class SSHConfig:
    address: str
    key_file: Path
    known_hosts: Path
    user: str = "maintenance"
    port: int = 22
    host_key_alias: str = "docker-maintenance-center"

    def argv(self, protocol):
        try:
            address = ipaddress.ip_address(self.address)
        except ValueError:
            raise GatewayFailure("invalid_gateway_address") from None
        if (not address.is_private or address.is_loopback or address.is_link_local
                or address.is_multicast or address.is_unspecified):
            raise GatewayFailure("invalid_gateway_address")
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", self.user):
            raise GatewayFailure("invalid_gateway_user")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise GatewayFailure("invalid_gateway_port")
        if not re.fullmatch(r"[a-zA-Z0-9._-]{1,100}", self.host_key_alias):
            raise GatewayFailure("invalid_host_key_alias")
        if not self.key_file.is_absolute() or not self.known_hosts.is_absolute():
            raise GatewayFailure("invalid_gateway_key_paths")
        if protocol not in ALLOWED_PROTOCOLS:
            raise GatewayFailure("protocol_not_allowed")
        return ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-i", str(self.key_file), "-p", str(self.port),
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "PermitLocalCommand=no",
                "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                "-o", "HostKeyAlias=" + self.host_key_alias,
                "-o", "UserKnownHostsFile=" + str(self.known_hosts),
                self.user + "@" + self.address, protocol]


class SSHTransport:
    """JSON on stdin; bounded output and fixed remote command.

    Terminating local ssh does not mean a remote operation was cancelled.
    All transport failures are uncertain to the calling execution layer.
    """

    def __init__(self, config: SSHConfig, popen=subprocess.Popen):
        self.config, self.popen = config, popen

    def __call__(self, protocol, request, timeout):
        encoded = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > 65536:
            raise GatewayFailure("request_too_large")
        process = self.popen(self.config.argv(protocol), stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                             start_new_session=True)
        output = bytearray()
        total = 0
        selector = selectors.DefaultSelector()
        deadline = time.monotonic() + timeout
        try:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
            sent = 0
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GatewayFailure("transport_timeout")
                for key, _ in selector.select(min(remaining, 0.5)):
                    if key.fileobj is process.stdin:
                        sent += os.write(process.stdin.fileno(), encoded[sent:])
                        if sent == len(encoded):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                        continue
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(data)
                    if total > 1024 * 1024:
                        raise GatewayFailure("response_too_large")
                    if key.fileobj is process.stdout:
                        output.extend(data)
            status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            # Existing gateways use nonzero exit codes for structured failures.
            if status == 255 or not output:
                raise GatewayFailure("transport_failed")
            return json.loads(output)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            raise GatewayFailure("transport_failed") from None
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


