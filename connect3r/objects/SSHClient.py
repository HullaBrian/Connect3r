from connect3r.objects.data_classes import IP as oIP
from connect3r.objects.data_classes import Host
from connect3r.objects.data_classes import Server

from connect3r.exceptions import *

import socket
from subprocess import check_output
from subprocess import STDOUT
from random import randint

from loguru import logger

from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.all import TCPSession
from scapy.all import sr1
from scapy.all import send
from scapy.all import Packet
from scapy.all import sniff


class SSHClient(socket.socket):
    def __init__(self,
                 ip: oIP | str,
                 username: str = "",
                 password: str = "",
                 internet_address_family: socket = socket.AF_INET,
                 socket_type: socket = socket.SOCK_STREAM,
                 *args,
                 **kwargs
                 ):
        socket.socket.__init__(self, internet_address_family, socket_type, *args, **kwargs)

        source_ip: oIP = oIP(socket.gethostbyname(socket.gethostname()))
        ssh_version: str = check_output(
            ["ssh", "-V"]
            , stderr=STDOUT) \
            .decode("utf-8") \
            .replace("\r", "") \
            .replace("\n", "")
        local_port: int = randint(1024, 65535)
        self.host: Host = Host(source_ip, "", "", local_port, username, password, ssh_version)

        self.server: Server = Server(ip, "", "", 22)

        if self._has_ssh():
            sniff(count=0, stop_filter=lambda packet: packet.hasLayer(TCP) and packet.dst == self.server.ip)
            pass
        else:
            exception_str: str = "Could not verify that device has ssh connections available!"
            logger.critical(exception_str)
            raise SSHException(exception_str)

    def _has_ssh(self) -> bool:
        logger.info("verifying that device has ssh")
        logger.debug("Source ip: " + str(self.host.ip))
        logger.debug("Source port: " + str(self.host.port))
        logger.debug("Destination ip: " + str(self.server.ip))
        logger.debug("Destination port: " + str(self.server.port))
        response = ""
        try:
            super().connect((str(self.server.ip), self.server.port))
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
        ip = IP(src=self.host.ip, dst=self.server.ip)
        syn = TCP(sport=self.host.port, dport=self.server.port, flags='S', seq=1000)
        synack: Packet | None = sr1(ip / syn)

        # ack
        ack = TCP(sport=self.host.port, dport=self.server.port, flags='A', seq=synack.ack, ack=synack.seq + 1)
        send(ip / ack)
