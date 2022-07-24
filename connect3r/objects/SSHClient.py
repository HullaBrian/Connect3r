from connect3r.objects.data_classes import IP
from connect3r.exceptions import AuthenticationException
import socket
from loguru import logger


class SSHClient(socket.socket):
    def __init__(self,
                 ip: IP | str,
                 username: str = "",
                 password: str = "",
                 port: int = 22,
                 internet_address_family: socket = socket.AF_INET,
                 socket_type: socket = socket.SOCK_STREAM,
                 *args,
                 **kwargs
                 ):
        socket.socket.__init__(self, internet_address_family, socket_type, *args, **kwargs)
        self.ip: IP = ip
        self._username: str = username
        self._password: str = password
        self._port: int = port

        try:
            super().connect((self.ip, self._port))
            # super().send(self._password)
            initial_response = super().recv(1024)
            logger.info("received: " + str(initial_response))
            super().sendall(b"EEE")
            super().close()
        except Exception as exception:
            logger.critical("Error during connection: " + str(exception))
            exit()

