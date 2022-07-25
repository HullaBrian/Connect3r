from scapy.layers.inet import TCP
from scapy.sendrecv import send

from connect3r.objects.data_classes import IP
from connect3r.objects.data_classes import Host
from connect3r.objects.data_classes import Server

from connect3r.exceptions import *
import socket
from loguru import logger
import subprocess
import random
from scapy import *


class SSHClient(socket.socket):
    def __init__(self,
                 ip: IP | str,
                 username: str = "",
                 password: str = "",
                 internet_address_family: socket = socket.AF_INET,
                 socket_type: socket = socket.SOCK_STREAM,
                 *args,
                 **kwargs
                 ):
        socket.socket.__init__(self, internet_address_family, socket_type, *args, **kwargs)

        source_ip: IP = IP(socket.gethostbyname(socket.gethostname()))
        ssh_version: str = subprocess.check_output(
                        ["ssh", "-V"]
                        , stderr=subprocess.STDOUT)\
                        .decode("utf-8")\
                        .replace("\r", "")\
                        .replace("\n", "")
        local_port: int = random.randint(1024, 65535)
        self.host: Host = Host(source_ip, "", "", local_port, username, password, ssh_version)

        self.server: Server = Server(ip, "", "", 22)

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

    def connect(self, **kwargs):
        # Synchronize
        ip = IP(src=self.source_ip, dst=dst)
        SYN = TCP(sport=sport, dport=dport, flags='S', seq=1000)
        SYNACK = sr1(ip / SYN)

        # ACK
        ACK = TCP(sport=sport, dport=dport, flags='A', seq=SYNACK.ack, ack=SYNACK.seq + 1)
        send(ip / ACK)