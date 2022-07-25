from connect3r.objects.data_classes import IP
from connect3r.exceptions import *
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

        if self._has_ssh():
            # copy public key to remote server using ssh-copy-id command?????
            pass
        else:
            exception_str: str = "Could not verify that device has ssh connections available!"
            logger.critical(exception_str)
            raise SSHException(exception_str)

    def _has_ssh(self) -> bool:
        logger.debug("verifying that device has ssh")
        response = ""
        try:
            super().connect((self.ip, self._port))
            logger.debug("connected to device!")
            response = super().recv(1024)
            logger.info("received: " + str(response))
            logger.debug("closing connection")
            super().close()
        except OSError as exception:
            logger.critical("connection refused. Is the device on? Error: " + str(exception))
        except Exception as exception:
            logger.critical("Error during connection: " + str(exception))

        if str(response):
            return True
        return False

