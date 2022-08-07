from connect3r.objects.data_classes import IP
from connect3r.objects.data_classes import Host
from connect3r.objects.data_classes import Server
from connect3r.exceptions import *
from connect3r.objects.Packetizer import Packetizer
from connect3r.templates import get_templates

import socket
from subprocess import check_output
from subprocess import STDOUT
import time
from random import randint

from loguru import logger
import secrets  # self.cookie = bytearray.fromhex(secrets.token_hex(16))


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

        self.TEMPLATES = None
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

        logger.info("loading packet templates")
        self.TEMPLATES = get_templates()
        logger.success("loaded packet templates")

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
        kex_algs_string = ",".join(self.host.supported_kex_algorithms)
        server_host_key_algs = ",".join(self.server.supported_server_host_key_algorithms)
        encryption_algs = ",".join(self.host.supported_encryption_algorithms)
        mac_algs = ",".join(self.host.supported_mac_algorithms)
        compression_algs = ",".join(self.host.supported_compression_algorithms)
        languages = ",".join([])

        kex_packet = Packetizer(self.TEMPLATES["kex"], data={
            "PACKET LENGTH": 0,
            "PADDING LENGTH": 0,
            "MESSAGE CODE KEX INIT": 20,
            "COOKIE": bytearray.fromhex(secrets.token_hex(16)),
            "KEX ALGORITHMS LENGTH": len(kex_algs_string),
            "KEX ALGORITHMS STRING": kex_algs_string,
            "SERVER HOST KEY ALGORITHMS LENGTH": len(server_host_key_algs),
            "SERVER HOST KEY ALGORITHMS STRING": server_host_key_algs,
            "ENCRYPTION ALGORITHMS CLIENT TO SERVER LENGTH": len(encryption_algs),
            "ENCRYPTION ALGORITHMS CLIENT TO SERVER STRING": encryption_algs,
            "ENCRYPTION ALGORITHMS SERVER TO CLIENT LENGTH": len(encryption_algs),
            "ENCRYPTION ALGORITHMS SERVER TO CLIENT STRING": encryption_algs,
            "MAC ALGORITHMS CLIENT TO SERVER LENGTH": len(mac_algs),
            "MAC ALGORITHMS CLIENT TO SERVER STRING": mac_algs,
            "MAC ALGORITHMS SERVER TO CLIENT LENGTH": len(mac_algs),
            "MAC ALGORITHMS SERVER TO CLIENT STRING": mac_algs,
            "COMPRESSION ALGORITHMS CLIENT TO SERVER LENGTH": len(compression_algs),
            "COMPRESSION ALGORITHMS CLIENT TO SERVER STRING": compression_algs,
            "COMPRESSION ALGORITHMS SERVER TO CLIENT LENGTH": len(compression_algs),
            "COMPRESSION ALGORITHMS SERVER TO CLIENT STRING": compression_algs,
            "LANGUAGES CLIENT TO SERVER LENGTH": len(languages),
            "LANGUAGES CLIENT TO SERVER STRING": languages,
            "LANGUAGES SERVER TO CLIENT LENGTH": len(languages),
            "LANGUAGES SERVER TO CLIENT STRING": languages,
            "FIRST KEX PACKET FOLLOWS": 0,
            "RESERVED": 0,
            "PADDING STRING": 0
        })
        super().sendall(kex_packet.encode_packet())

        logger.info("sent client key exchange packet")

        logger.warning("reading server key exchange packet...")
        self.packet_bytes = super().recv(32768)
        server_key_exchange_init: dict = self._decode_kex_packet()

    def _decode_kex_packet(self) -> dict:
        packetizer = Packetizer(self.TEMPLATES["kex"], self.packet_bytes)
        return packetizer.decode_packet()
