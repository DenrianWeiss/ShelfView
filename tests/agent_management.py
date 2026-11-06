import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import agent_api
NODE = sys.argv.pop(1)


class Management(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        agent_api.AgentAPI.setUpClass()
        cls.helper = agent_api.AgentAPI()

    @classmethod
    def tearDownClass(cls):
        agent_api.AgentAPI.tearDownClass()

    def test_web_client_uses_real_agent_connection(self):
        with self.helper.running(device_mode='session') as (secret, _):
            env = os.environ.copy()
            env['BC_TEST_PAIR_SECRET'] = secret
            script = Path(__file__).resolve().parents[1] / 'frontends/web/tests/agent-management-client.mjs'
            result = subprocess.run([NODE, str(script), 'http://127.0.0.1:' + str(self.helper.port)],
                                    env=env, capture_output=True, text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(all(json.loads(result.stdout).values()))
            self.assertEqual(self.helper.device.session_posts, 1)
            self.assertEqual(self.helper.device.session_deletes, 1)
            self.assertEqual(self.helper.device.reset_posts, 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
