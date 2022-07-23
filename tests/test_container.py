import unittest
import os
from verify_container import (
    check_environment,
    check_ssh
)
from connect3r.objects import IP


class SSHServer(unittest.TestCase):
    # self.assertEqual(EXPECTED, ACTUAL)

    def test_environment(self):
        self.assertTrue(check_environment(), "Not all environment variables are set")

    def test_ssh_server(self):
        self.assertTrue(check_ssh(IP(os.getenv("DOCKER_IP"))), "SSH server is not open")  # add assertion here


if __name__ == '__main__':
    unittest.main()
