"""Validate path-bearing Compose inputs before invoking the privileged renderer."""
import json
from pathlib import Path


def validate_source(path, require):
    raw = Path(path).read_bytes()
    require(len(raw) <= 1024 * 1024, 'compose_input_limit')
    try:
        value = json.loads(raw)
    except ValueError:
        import yaml
        value = yaml.safe_load(raw)
    require(isinstance(value, dict), 'compose_input_invalid')
    # Limit aliases/cycles/depth before traversing normalized service definitions.
    stack = [(value, 0)]
    seen = set()
    while stack:
        item, depth = stack.pop()
        require(depth <= 32 and len(seen) < 10000, 'compose_input_limit')
        if isinstance(item, (dict, list)):
            require(id(item) not in seen, 'compose_alias_unsupported')
            seen.add(id(item))
            stack.extend((v, depth + 1) for v in (item.values() if isinstance(item, dict) else item))
    require(not value.get('include'), 'compose_input_unbound')
    services = value.get('services')
    require(isinstance(services, dict), 'services_invalid')
    for service in services.values():
        require(isinstance(service, dict), 'services_invalid')
        require(not any(service.get(key) for key in ('extends', 'env_file', 'label_file', 'build', 'develop', 'post_start', 'pre_stop')), 'compose_input_unbound')
    for group in ('configs', 'secrets'):
        definitions = value.get(group) or {}
        require(isinstance(definitions, dict), 'compose_input_invalid')
        for definition in definitions.values():
            require(isinstance(definition, dict) and not definition.get('file') and not definition.get('environment'), 'compose_input_unbound')
