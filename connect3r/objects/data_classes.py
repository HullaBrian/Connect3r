from dataclasses import dataclass
import secrets
from threading import Thread

from loguru import logger

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

from connect3r.exceptions import PacketOverflowException
from connect3r.exceptions import MissingPacketFieldException
from connect3r.exceptions import MalformedPacketException


@dataclass
class IP:
    rep: str

    def __str__(self):
        return self.rep


@dataclass
class Host:
    ip: str | IP
    mac_address: str
    key_cache: str
    port: int
    username: str
    password: str
    ssh_version: str
    supported_kex_algorithms: list[str]
    supported_encryption_algorithms: list[str]
    supported_mac_algorithms: list[str]
    supported_compression_algorithms: list[str]


@dataclass
class Server:
    ip: str | IP
    mac_address: str
    key_cache: str
    port: int
    ssh_version: str
    supported_server_host_key_algorithms: list[str]


def _get_hex_padding(num: int) -> bytes:
    return bytearray.fromhex(str(hex(num)).zfill(8))


def _generate_key_pair() -> tuple[bytes, bytes]:
    logger.warning("generating new kay rsa keypair")
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=256
    )

    private_key = key.private_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption()
    )
    logger.debug("generated private key")

    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )
    logger.debug("generated public key")

    return private_key, public_key


def num_to_bytes(num: int, num_of_bytes: int) -> bytes:
    try:
        return num.to_bytes(num_of_bytes, 'big')
    except OverflowError:
        raise PacketOverflowException(f"Number '{num}' could not be converted to byte array of size '{num_of_bytes}'")


def _get_padding(size: int) -> int:
    val = size % 16
    if val > 8:
        return 16 - (val - 8)
    elif val < 8:
        return 8 - val
    elif val == 0:
        return 8
    elif val == 8:
        return 8
    else:
        logger.critical("SIZE:" + str(size))
        logger.critical("HELP ME PLEASE IT BROKE")


def _construct(self: object) -> bytes:
    if not isinstance(self, KEX_PACKET) and not isinstance(self, KEX_PACKET_DECODE):
        raise MalformedPacketException("Tried to construct Key Exchange Packet. ")
    logger.info("building packet")
    self.representation += self.packet_length
    self.representation += self.padding_length
    self.representation += self.message_code_kex_init
    self.representation += self.cookie
    self.representation += self.kex_algorithms_length
    self.representation += self.kex_algorithms_string
    self.representation += self.server_host_key_algorithms_length
    self.representation += self.server_host_key_algorithms_string
    self.representation += self.encryption_algorithms_client_to_server_length
    self.representation += self.encryption_algorithms_client_to_server_string
    self.representation += self.encryption_algorithms_server_to_client_length
    self.representation += self.encryption_algorithms_server_to_client_string
    self.representation += self.mac_algorithms_client_to_server_length
    self.representation += self.mac_algorithms_client_to_server_string
    self.representation += self.mac_algorithms_server_to_client_length
    self.representation += self.mac_algorithms_server_to_client_string
    self.representation += self.compression_algorithms_client_to_server_length
    self.representation += self.compression_algorithms_client_to_server_string
    self.representation += self.compression_algorithms_server_to_client_length
    self.representation += self.compression_algorithms_server_to_client_string
    self.representation += self.languages_client_to_server_length
    self.representation += self.languages_client_to_server_string
    self.representation += self.languages_server_to_client_length
    self.representation += self.languages_server_to_client_string
    self.representation += self.first_kex_packet_follows
    self.representation += self.reserved
    self.representation += self.padding_string
    logger.success("built packet!")

    return self.representation


class KEX_PACKET(object):
    """
    Object that constructs the TCP payload necessary for client key exchange
    """

    def __init__(
            self
            , kex_algorithm: str
            , server_host_key_algorithms: str
            , encryption_algorithms_client_to_server: str
            , encryption_algorithms_server_to_client: str
            , mac_algorithms_client_to_server: str
            , mac_algorithms_server_to_client: str
            , compression_algorithms_client_to_server: str
            , compression_algorithms_server_to_client: str
            , languages_client_to_server: str = ""
            , languages_server_to_client: str = ""
    ):
        """
        :param kex_algorithm:
        :param server_host_key_algorithms:
        :param encryption_algorithms_client_to_server:
        :param encryption_algorithms_server_to_client:
        :param mac_algorithms_client_to_server:
        :param mac_algorithms_server_to_client:
        :param compression_algorithms_client_to_server:
        :param compression_algorithms_server_to_client:
        :param languages_client_to_server:
        :param languages_server_to_client:
        """
        logger.info("constructing client key exchange packet...")
        # Cannot calculate until everything else has been
        self.packet_length: bytes = b""  # 4 hex pairs: num < 4294967295
        self.padding_length: bytes = b""  # 1 hex pair: num < 255

        self.message_code_kex_init: bytes = num_to_bytes(20, 1)  # 1 hex pair: num < 255
        self.cookie: bytes = self._generate_cookie()  # 16 hex pairs

        self.kex_algorithms_string: str | bytes = kex_algorithm  # <kex_algorithms_length> hex pairs
        self.kex_algorithms_length: bytes = num_to_bytes(len(kex_algorithm),
                                                         4)  # (Length of ASCII text) 4 hex pairs: num < 4294967295

        self.server_host_key_algorithms_string: str | bytes = server_host_key_algorithms
        self.server_host_key_algorithms_length: bytes = num_to_bytes(len(server_host_key_algorithms),
                                                                     4)  # 4 hex pairs: num < 4294967295

        self.encryption_algorithms_client_to_server_string: str | bytes = encryption_algorithms_client_to_server
        self.encryption_algorithms_client_to_server_length: bytes = num_to_bytes(
            len(encryption_algorithms_client_to_server), 4)  # 4 hex pairs: num < 4294967295
        self.encryption_algorithms_server_to_client_string: str | bytes = encryption_algorithms_server_to_client
        self.encryption_algorithms_server_to_client_length: bytes = num_to_bytes(
            len(encryption_algorithms_server_to_client), 4)  # 4 hex pairs: num < 4294967295

        self.mac_algorithms_client_to_server_string: str | bytes = mac_algorithms_client_to_server
        self.mac_algorithms_client_to_server_length: bytes = num_to_bytes(len(mac_algorithms_client_to_server),
                                                                          4)  # 4 hex pairs: num < 4294967295
        self.mac_algorithms_server_to_client_string: str | bytes = mac_algorithms_server_to_client
        self.mac_algorithms_server_to_client_length: bytes = num_to_bytes(len(mac_algorithms_server_to_client),
                                                                          4)  # 4 hex pairs: num < 4294967295

        self.compression_algorithms_client_to_server_string: str | bytes = compression_algorithms_client_to_server
        self.compression_algorithms_client_to_server_length: bytes = num_to_bytes(
            len(compression_algorithms_client_to_server), 4)  # 4 hex pairs: num < 4294967295
        self.compression_algorithms_server_to_client_string: str | bytes = compression_algorithms_server_to_client
        self.compression_algorithms_server_to_client_length: bytes = num_to_bytes(
            len(compression_algorithms_server_to_client), 4)  # 4 hex pairs: num < 4294967295

        self.languages_client_to_server_string: str | bytes = languages_client_to_server
        self.languages_client_to_server_length: bytes = num_to_bytes(len(languages_client_to_server),
                                                                     4)  # 4 hex pairs: num < 4294967295
        self.languages_server_to_client_string: str | bytes = languages_server_to_client
        self.languages_server_to_client_length: bytes = num_to_bytes(len(languages_server_to_client),
                                                                     4)  # 4 hex pairs: num < 4294967295

        # Hard-coded for now...
        self.first_kex_packet_follows: bytes = num_to_bytes(0, 1)  # 1 hex pair: num < 255. Default 0
        self.reserved: bytes = bytearray.fromhex("00" * 4)  # 4 hex pairs: "00 00 00 00"

        self.padding_string: bytes = b""  # n hex pairs: "00 00 00 00 00"

        self.representation: bytes = b""  # bytes representing packet as w whole. Used to calculate total packet length

        logger.success("constructed client key exchange packet")

        self._serialize_strings()
        logger.success("serialized packet entries")

        self._compute_packet_length()
        logger.success("calculated packet length")

        _construct(self)

    def _serialize_strings(self) -> None:
        if type(self.kex_algorithms_string) is str:
            self.kex_algorithms_string = self.kex_algorithms_string.encode()

        if type(self.server_host_key_algorithms_string) is str:
            self.server_host_key_algorithms_string = self.server_host_key_algorithms_string.encode()

        if type(self.encryption_algorithms_client_to_server_string) is str:
            self.encryption_algorithms_client_to_server_string = self.encryption_algorithms_client_to_server_string.encode()
        if type(self.encryption_algorithms_server_to_client_string) is str:
            self.encryption_algorithms_server_to_client_string = self.encryption_algorithms_server_to_client_string.encode()

        if type(self.mac_algorithms_client_to_server_string) is str:
            self.mac_algorithms_client_to_server_string = self.mac_algorithms_client_to_server_string.encode()
        if type(self.mac_algorithms_server_to_client_string) is str:
            self.mac_algorithms_server_to_client_string = self.mac_algorithms_server_to_client_string.encode()

        if type(self.compression_algorithms_client_to_server_string) is str:
            self.compression_algorithms_client_to_server_string = self.compression_algorithms_client_to_server_string.encode()
        if type(self.compression_algorithms_server_to_client_string) is str:
            self.compression_algorithms_server_to_client_string = self.compression_algorithms_server_to_client_string.encode()

        if type(self.languages_client_to_server_string) is str:
            self.languages_client_to_server_string = self.languages_client_to_server_string.encode()
        if type(self.languages_server_to_client_string) is str:
            self.languages_server_to_client_string = self.languages_server_to_client_string.encode()

    def _generate_cookie(self) -> bytes:
        self.cookie = bytearray.fromhex(secrets.token_hex(16))
        return self.cookie

    def _compute_packet_length(self):
        total_length: int = 75  # Minimum number of bytes for payload
        total_length += int.from_bytes(self.kex_algorithms_length, "big")

        total_length += int.from_bytes(self.encryption_algorithms_client_to_server_length, "big")
        total_length += int.from_bytes(self.encryption_algorithms_server_to_client_length, "big")

        total_length += int.from_bytes(self.mac_algorithms_client_to_server_length, "big")
        total_length += int.from_bytes(self.mac_algorithms_server_to_client_length, "big")

        total_length += int.from_bytes(self.compression_algorithms_client_to_server_length, "big")
        total_length += int.from_bytes(self.compression_algorithms_server_to_client_length, "big")

        total_length += int.from_bytes(self.languages_client_to_server_length, "big")
        total_length += int.from_bytes(self.languages_server_to_client_length, "big")

        self.padding_length = 0
        # TODO: ensure that padding_length is up to standard with the openssh RFC
        self.padding_string = bytearray.fromhex("00" * self.padding_length)
        total_length += self.padding_length
        self.padding_length = num_to_bytes(self.padding_length, 1)

        self.packet_length = num_to_bytes(total_length, 4)


@dataclass
class KEX_PACKET_DECODE:
    packet_length: bytes
    padding_length: bytes
    message_code_kex_init: bytes
    cookie: bytes
    kex_algorithms_string: bytes
    kex_algorithms_length: bytes
    server_host_key_algorithms_string: bytes
    server_host_key_algorithms_length: bytes
    encryption_algorithms_client_to_server_string: bytes
    encryption_algorithms_client_to_server_length: bytes
    encryption_algorithms_server_to_client_string: bytes
    encryption_algorithms_server_to_client_length: bytes
    mac_algorithms_client_to_server_string: bytes
    mac_algorithms_client_to_server_length: bytes
    mac_algorithms_server_to_client_string: bytes
    mac_algorithms_server_to_client_length: bytes
    compression_algorithms_client_to_server_string: bytes
    compression_algorithms_client_to_server_length: bytes
    compression_algorithms_server_to_client_string: bytes
    compression_algorithms_server_to_client_length: bytes
    languages_client_to_server_string: bytes
    languages_client_to_server_length: bytes
    languages_server_to_client_string: bytes
    languages_server_to_client_length: bytes
    first_kex_packet_follows: bytes
    reserved: bytes
    padding_string: bytes
    representation: bytes

    def build_packet(self) -> bytes:
        _construct(self)
        return self.representation
