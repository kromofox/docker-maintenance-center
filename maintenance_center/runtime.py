"""Explicit deployment configuration and transport-level shadow restrictions."""

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path

from .core import MaintenanceError
from .gateway import SSHConfig, SSHTransport
from .managed_gateway import ManagedGateway, PROTOCOL


class ShadowTransport:
    def __init__(self, transport):
        self.transport = transport

    def __call__(self, protocol, request, timeout):
        action = request.get("action")
        allowed = protocol == PROTOCOL and action in {"list", "status", "health", "logs", "operation-status"}
        if not allowed:
            raise MaintenanceError("shadow_readonly")
        return self.transport(protocol, request, timeout)


@dataclass(frozen=True)
class RuntimeConfig:
    address: str
    port: int
    gateway: SSHConfig
    mode: str = "shadow"
    observe_enabled: bool = False

    @classmethod
    def load(cls, path):
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate_config_key")
                result[key] = value
            return result
        if path.stat().st_size > 8192:
            raise ValueError("config_too_large")
        data = json.loads(path.read_text(), object_pairs_hook=unique)
        if not isinstance(data, dict):
            raise ValueError("invalid_runtime_config")
        observe_enabled = data.pop("observe_enabled", False)
        if type(observe_enabled) is not bool or set(data) != {"address", "port", "gateway_address", "gateway_port", "gateway_user", "host_key_alias", "key_file", "known_hosts", "mode"}:
            raise ValueError("invalid_runtime_config")
        address = ipaddress.IPv4Address(data["address"])
        if not any(address in network for network in (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))):
            raise ValueError("lan_address_required")
        if type(data["port"]) is not int or not 1024 <= data["port"] <= 65535:
            raise ValueError("invalid_listen_port")
        if data["mode"] not in {"shadow", "active"}:
            raise ValueError("invalid_runtime_mode")
        gateway = SSHConfig(data["gateway_address"], Path(data["key_file"]), Path(data["known_hosts"]),
                            user=data["gateway_user"], port=data["gateway_port"], host_key_alias=data["host_key_alias"])
        gateway.argv(PROTOCOL)
        return cls(str(address), data["port"], gateway, data["mode"], observe_enabled)

    def make_gateway(self):
        transport = SSHTransport(self.gateway)
        if self.mode == "shadow":
            transport = ShadowTransport(transport)
        gateway = ManagedGateway(transport)
        gateway.refresh()
        gateway.observe_enabled = self.observe_enabled
        return gateway
