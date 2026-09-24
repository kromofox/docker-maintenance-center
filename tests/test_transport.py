import json
import subprocess
import sys
import unittest
from pathlib import Path

from maintenance_center.gateway import GatewayFailure, SSHConfig, SSHTransport


class TransportTests(unittest.TestCase):
    def transport(self, script):
        self.captured = {}
        def launch(argv, **kwargs):
            self.captured["argv"] = argv
            process = subprocess.Popen([sys.executable, "-c", script], **kwargs)
            self.captured["process"] = process
            return process
        return SSHTransport(SSHConfig("192.168.50.10", Path("/run/secrets/key"),
                                      Path("/run/secrets/known_hosts")), popen=launch)

    def test_json_uses_stdin_and_structured_failure_survives_exit_code(self):
        transport = self.transport("import json,sys; p=json.load(sys.stdin); print(json.dumps(p)); sys.exit(1)")
        request = {"action": "apply-update", "plan_id": "secret-plan"}
        self.assertEqual(transport("project007-v2", request, 3), request)
        self.assertNotIn("secret-plan", " ".join(self.captured["argv"]))
        self.assertIsNotNone(self.captured["process"].returncode)

    def test_output_limit_terminates_local_process(self):
        transport = self.transport("import sys; sys.stdin.read(); sys.stdout.write('x' * (2 * 1024 * 1024)); sys.stdout.flush()")
        with self.assertRaisesRegex(GatewayFailure, "response_too_large"):
            transport("project007-v2", {}, 3)
        self.assertIsNotNone(self.captured["process"].returncode)

    def test_timeout_does_not_expose_stderr(self):
        transport = self.transport("import sys,time; sys.stderr.write('Bearer secret-test'); sys.stderr.flush(); time.sleep(10)")
        with self.assertRaisesRegex(GatewayFailure, "transport_timeout") as error:
            transport("project007-v2", {}, 0.1)
        self.assertNotIn("secret-test", str(error.exception))
        self.assertIsNotNone(self.captured["process"].returncode)

    def test_invalid_json_and_ssh_failure_are_rejected(self):
        for script in ("print('invalid json')", "import sys; print('{}'); sys.exit(255)"):
            transport = self.transport(script)
            with self.assertRaises(GatewayFailure):
                transport("project007-v2", {}, 3)


if __name__ == "__main__":
    unittest.main()
