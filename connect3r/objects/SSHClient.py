from connect3r.objects.data_classes import IP
from connect3r.objects.data_classes import KEX_PACKET
from connect3r.objects.data_classes import KEX_PACKET_DECODE
from connect3r.objects.data_classes import Host
from connect3r.objects.data_classes import Server

from connect3r.exceptions import *

import socket
from subprocess import check_output
from subprocess import STDOUT
import time
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

        self.packet_bytes: list[bytes] = []
        """
        if self._has_ssh():
            # do something...
            pass
        else:
            exception_str: str = "Could not verify that device has ssh connections available!"
            logger.critical(exception_str)
            raise SSHException(exception_str)
        """

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
            response = super().recv(32768)
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
        logger.debug("Source ip: " + str(self.host.ip))
        logger.debug("Source port: " + str(self.host.port))
        logger.debug("Destination ip: " + str(self.server.ip))
        logger.debug("Destination port: " + str(self.server.port))

        try:
            super().connect((str(self.server.ip), self.server.port))
            logger.success("connected to device!")

            # Exchange ssh versions
            logger.warning("exchanging ssh versions")
            self._exchange_ssh_versions()
            logger.success("successfully exchanged ssh version")

            # Initiate key exchange
            logger.warning("initiating key exchange...")
            self._kex_init()
            logger.success("key exchange successful!")

            super().close()
        except OSError as exception:
            logger.critical("connection refused. Is the device on? Error: " + str(exception))

    def _exchange_ssh_versions(self):
        # Send SSH version
        super().send(b"SSH-2.0-" + self.host.ssh_version.split("p1")[0].encode() + bytearray.fromhex("0d0a"))
        logger.debug(f"sent client ssh version as SSH-2.0-{self.host.ssh_version.split('p1')[0]}")
        # Receive SSH Version
        logger.warning("waiting for server ssh version")
        self.server.ssh_version = super().recv(32768).decode("utf-8")
        logger.debug("received server ssh version as " + self.server.ssh_version.replace("\n", ""))

    def _kex_init(self):
        kex_packet: bytes = KEX_PACKET(
            kex_algorithm=",".join(self.host.supported_kex_algorithms)
            , server_host_key_algorithms=",".join(self.server.supported_server_host_key_algorithms)
            , encryption_algorithms_client_to_server=",".join(self.host.supported_encryption_algorithms)
            , encryption_algorithms_server_to_client=",".join(self.server.supported_server_host_key_algorithms)
            , mac_algorithms_client_to_server=",".join(self.host.supported_mac_algorithms)
            , mac_algorithms_server_to_client=",".join(self.host.supported_mac_algorithms)
            , compression_algorithms_client_to_server=",".join(self.host.supported_mac_algorithms)
            , compression_algorithms_server_to_client=",".join(self.host.supported_mac_algorithms)
        ).representation
        super().sendall(kex_packet)

        logger.info("sent client key exchange packet")

        logger.warning("reading server key exchange packet...")
        self.packet_bytes = [bytes([b]) for b in super().recv(32768)]
        server_key_exchange_init: KEX_PACKET_DECODE = self._decode_kex_packet()

    def _decode_kex_packet(self) -> KEX_PACKET_DECODE:
        decoded_packet: KEX_PACKET_DECODE = KEX_PACKET_DECODE(
            b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
            , b""
        )

        decoded_packet.packet_length = self._pop_range(4)
        decoded_packet.padding_length = self._pop_range(1)
        decoded_packet.message_code_kex_init = self._pop_range(1)
        decoded_packet.cookie = self._pop_range(16)

        decoded_packet.kex_algorithms_length = self._pop_range(4)
        decoded_packet.kex_algorithms_string = self._pop_range(int.from_bytes(decoded_packet.kex_algorithms_length, "big"))

        decoded_packet.server_host_key_algorithms_length = self._pop_range(4)
        decoded_packet.server_host_key_algorithms_string = self._pop_range(int.from_bytes(decoded_packet.server_host_key_algorithms_length, "big"))

        decoded_packet.encryption_algorithms_client_to_server_length = self._pop_range(4)
        decoded_packet.encryption_algorithms_client_to_server_string = self._pop_range(int.from_bytes(decoded_packet.encryption_algorithms_client_to_server_length, "big"))
        decoded_packet.encryption_algorithms_server_to_client_length = self._pop_range(4)
        decoded_packet.encryption_algorithms_server_to_client_string = self._pop_range(int.from_bytes(decoded_packet.encryption_algorithms_server_to_client_length, "big"))

        decoded_packet.compression_algorithms_client_to_server_length = self._pop_range(4)
        decoded_packet.compression_algorithms_client_to_server_string = self._pop_range(int.from_bytes(decoded_packet.compression_algorithms_client_to_server_length, "big"))
        decoded_packet.compression_algorithms_server_to_client_length = self._pop_range(4)
        decoded_packet.compression_algorithms_server_to_client_string = self._pop_range(int.from_bytes(decoded_packet.compression_algorithms_server_to_client_length, "big"))

        decoded_packet.languages_client_to_server_length = self._pop_range(4)
        decoded_packet.languages_client_to_server_string = self._pop_range(int.from_bytes(decoded_packet.languages_client_to_server_length, "big"))
        decoded_packet.languages_server_to_client_length = self._pop_range(4)
        decoded_packet.languages_server_to_client_string = self._pop_range(int.from_bytes(decoded_packet.languages_server_to_client_length, "big"))

        decoded_packet.first_kex_packet_follows = self._pop_range(1)

        decoded_packet.reserved = self._pop_range(4)

        decoded_packet.padding_string = self._pop_range(int.from_bytes(decoded_packet.padding_length, "big"))

        decoded_packet.build_packet()
        return decoded_packet

    def _pop_range(self, end_index: int) -> bytes:
        out: list[bytes] = []

        for byt in self.packet_bytes[:end_index]:
            out.append(byt)
            self.packet_bytes.remove(byt)

        return b"".join(out)
