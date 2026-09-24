import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'host'))
from compose_inputs import validate_source
from project_registry import require, RegistryError
import host_config


class ComposeBoundaryTests(unittest.TestCase):
    def test_external_inputs_are_rejected_before_renderer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'compose.json'
            for model in (
                {'include':['/etc/private.yaml'], 'services':{'web':{'image':'example/web:latest'}}},
                {'services':{'web':{'image':'example/web:latest', 'env_file':'/etc/private.env'}}},
                {'services':{'web':{'image':'example/web:latest', 'extends':{'file':'/etc/private.yaml','service':'web'}}}},
                {'services':{'web':{'image':'example/web:latest'}}, 'secrets':{'key':{'file':'/etc/private'}}},
            ):
                path.write_text(json.dumps(model))
                with self.assertRaisesRegex(RegistryError, 'compose_input_unbound'):
                    validate_source(path, require)
            path.write_text(json.dumps({'services':{'web':{'image':'example/web:latest','environment':{'VALUE':'literal'}}}}))
            validate_source(path, require)

    def test_state_cannot_hide_config_or_gateway(self):
        with patch.object(host_config, 'account'), patch.object(host_config, 'trusted_path', side_effect=lambda p, **kw: Path(p)), patch.object(host_config.os, 'access', return_value=True):
            for path in ('/', '/etc', str(host_config.INSTALL), str(host_config.CONFIG.parent), str(host_config.INSTALL/'host')):
                config = {'gateway_user':'maintenance','docker_path':'/usr/bin/docker','allowed_roots':['/srv/compose'],'state_dir':path}
                with self.assertRaises(host_config.ConfigError):
                    host_config.validate(config)
