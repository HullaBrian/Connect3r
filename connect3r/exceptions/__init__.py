import sys
import os
sys.path.append(os.path.dirname(__file__))


class ConnectionRefusedException(Exception):
    pass


class ConnectionTimeoutException(Exception):
    pass


class AuthenticationException(Exception):
    pass


class SSHException(Exception):
    pass