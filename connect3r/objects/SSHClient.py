from connect3r.objects.data_classes import IP
from connect3r.objects.data_classes import KEX_PACKET
from connect3r.objects.data_classes import Host
from connect3r.objects.data_classes import Server

from connect3r.exceptions import *

import socket
from subprocess import check_output
from subprocess import STDOUT
from random import randint

from loguru import logger


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
        ssh_version: str = check_output(
            ["ssh", "-V"]
            , stderr=STDOUT) \
            .decode("utf-8") \
            .replace("\r", "") \
            .replace("\n", "")
        local_port: int = randint(1024, 65535)
        supported_kex_algorithms = [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "diffie-hellman-group-exchange-sha256"
        ]
        supported_encryption_algorithms = [
            "aes256-ctr"
        ]
        supported_mac_algorithms = [
            "hmac-sha2-512"
        ]
        supported_compression_algorithms = [
            "none",
            "zlib@openssh.com",
            "zlib"
        ]
        self.host: Host = Host(
            source_ip
            , ""
            , ""
            , local_port
            , username
            , password
            , ssh_version
            , supported_kex_algorithms
            , supported_encryption_algorithms
            , supported_mac_algorithms
            , supported_compression_algorithms
        )

        supported_server_host_key_algorithms = [
            "rsa-sha2-512"
        ]
        self.server: Server = Server(ip, "", "", 22, "", supported_server_host_key_algorithms)

        if self._has_ssh():
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
        logger.info("verifying that device has ssh")
        logger.debug("Source ip: " + str(self.host.ip))
        logger.debug("Source port: " + str(self.host.port))
        logger.debug("Destination ip: " + str(self.server.ip))
        logger.debug("Destination port: " + str(self.server.port))
        try:
            super().connect((str(self.server.ip), self.server.port))

            # Send SSH version
            super().send(b"SSH-2.0-" + bytes(self.host.ssh_version.split("p1")[0]) + bytearray.fromhex("0d0a"))
            # Receive SSH Version
            response = super().recv(1024)

            # Initiate key exchange
            self._kex()

            super().close()
        except OSError as exception:
            logger.critical("connection refused. Is the device on? Error: " + str(exception))
        except Exception as exception:
            logger.critical("Error during connection: " + str(exception))

    def _kex(self):
        kex_packet = KEX_PACKET(
            packet_length=0,
            padding_length=0,
            message_code_kex_init=0,
            cookie="",
            kex_algorithms_length=0,
            kex_algorithms_string_truncated="",
            server_host_key_algorithms_length=0,
            server_host_key_algorithms_string="",
            encryption_algorithms_client_to_server_length=0,
            encryption_algorithms_client_to_server_string="",
            encryption_algorithms_server_to_client_length=0,
            encryption_algorithms_server_to_client_string="",
            mac_algorithms_client_to_server_length=0,
            mac_algorithms_client_to_server_string="",
            mac_algorithms_server_to_client_length=0,
            mac_algorithms_server_to_client_string="",
            compression_algorithms_client_to_server_length=0,
            compression_algorithms_client_to_server_string="",
            compression_algorithms_server_to_client_length=0,
            compression_algorithms_server_to_client_string="",
            languages_client_to_server_length=0,
            languages_client_to_server_string="",
            languages_server_to_client_length=0,
            languages_server_to_client_string="",
            first_kex_packet_follows=0,
            reserved="",
            padding_string=""
        )
        packet: bytes = bytearray.fromhex("00000105")  # 4
        packet += bytearray.fromhex("05")  # 1
        packet += bytearray.fromhex("14")  # 1
        packet += bytearray.fromhex("9388d38ee73c2a5dc6808fd2dcd2ebd7")  # 16
        packet += bytearray.fromhex("00000053")  # 4  20
        packet += b"curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"  # 17
        packet += bytearray.fromhex("0000000C")  # 4
        packet += b"rsa-sha2-512"  # 12
        packet += bytearray.fromhex("0000000A")  # 4
        packet += b"aes256-ctr"  # 10
        packet += bytearray.fromhex("0000000A")  # 4
        packet += b"aes256-ctr"  # 10
        packet += bytearray.fromhex("0000000D")  # 4
        packet += b"hmac-sha2-512"  # 13
        packet += bytearray.fromhex("0000000D")  # 4
        packet += b"hmac-sha2-512"  # 13
        packet += bytearray.fromhex("0000001A")  # 4
        packet += b"none,zlib@openssh.com,zlib"  # 26
        packet += bytearray.fromhex("0000001A")  # 4
        packet += b"none,zlib@openssh.com,zlib"  # 26
        packet += bytearray.fromhex("00" * 18)  # footer/padding  # 9
