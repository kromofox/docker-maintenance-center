import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'host'))
from project_registry import Registry, RegistryError


class ManifestTests(unittest.TestCase):
    def test_oci_manifest_selects_runtime_not_attestation_and_rejects_ambiguity(self):
        image = 'sha256:' + 'a'*64
        selected = {'Descriptor':{'platform':{'os':'linux','architecture':'arm64','variant':'v8'},'digest':'sha256:'+'b'*64},
                    'OCIManifest':{'config':{'digest':image}}}
        attestation = {'Descriptor':{'platform':{'os':'unknown','architecture':'unknown'},'digest':'sha256:'+'c'*64},
                       'OCIManifest':{'config':{'digest':'sha256:'+'d'*64}}}
        registry=Registry()
        with patch('project_registry.platform.machine',return_value='aarch64'), patch.object(registry,'docker',return_value=json.dumps([selected,attestation])):
            self.assertEqual(registry.targets({'refs':{'web':'example/web:latest'}})['web']['image'],image)
        with patch('project_registry.platform.machine',return_value='aarch64'), patch.object(registry,'docker',return_value=json.dumps([selected,selected])):
            with self.assertRaisesRegex(RegistryError,'registry_platform_invalid'):
                registry.targets({'refs':{'web':'example/web:latest'}})
