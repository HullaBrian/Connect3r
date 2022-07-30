import secrets

from Packet import Packet
from connect3r.exceptions import PacketOverflowException

from loguru import logger
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend


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


class Kex_packet(Packet):
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
        super().__init__(self)

        logger.info("constructing client key exchange packet...")
        # Cannot calculate until everything else has been
        self.packet_length: bytes = b""  # 4 hex pairs: num < 4294967295
        self.padding_length: bytes = b""  # 1 hex pair: num < 255

        self.message_code_kex_init: bytes = num_to_bytes(20, 1)  # 1 hex pair: num < 255
        self.cookie: bytes = self._generate_cookie()  # 16 hex pairs

        self.kex_algorithms_string: bytes = kex_algorithm.encode()  # <kex_algorithms_length> hex pairs
        self.kex_algorithms_length: bytes = num_to_bytes(len(kex_algorithm),
                                                         4)  # (Length of ASCII text) 4 hex pairs: num < 4294967295

        self.server_host_key_algorithms_string: bytes = server_host_key_algorithms.encode()
        self.server_host_key_algorithms_length: bytes = num_to_bytes(len(server_host_key_algorithms),
                                                                     4)  # 4 hex pairs: num < 4294967295

        self.encryption_algorithms_client_to_server_string: bytes = encryption_algorithms_client_to_server.encode()
        self.encryption_algorithms_client_to_server_length: bytes = num_to_bytes(
            len(encryption_algorithms_client_to_server), 4)  # 4 hex pairs: num < 4294967295
        self.encryption_algorithms_server_to_client_string: bytes = encryption_algorithms_server_to_client.encode()
        self.encryption_algorithms_server_to_client_length: bytes = num_to_bytes(
            len(encryption_algorithms_server_to_client), 4)  # 4 hex pairs: num < 4294967295

        self.mac_algorithms_client_to_server_string: bytes = mac_algorithms_client_to_server.encode()
        self.mac_algorithms_client_to_server_length: bytes = num_to_bytes(len(mac_algorithms_client_to_server),
                                                                          4)  # 4 hex pairs: num < 4294967295
        self.mac_algorithms_server_to_client_string: bytes = mac_algorithms_server_to_client.encode()
        self.mac_algorithms_server_to_client_length: bytes = num_to_bytes(len(mac_algorithms_server_to_client),
                                                                          4)  # 4 hex pairs: num < 4294967295

        self.compression_algorithms_client_to_server_string: bytes = compression_algorithms_client_to_server.encode()
        self.compression_algorithms_client_to_server_length: bytes = num_to_bytes(
            len(compression_algorithms_client_to_server), 4)  # 4 hex pairs: num < 4294967295
        self.compression_algorithms_server_to_client_string: bytes = compression_algorithms_server_to_client.encode()
        self.compression_algorithms_server_to_client_length: bytes = num_to_bytes(
            len(compression_algorithms_server_to_client), 4)  # 4 hex pairs: num < 4294967295

        self.languages_client_to_server_string: bytes = languages_client_to_server.encode()
        self.languages_client_to_server_length: bytes = num_to_bytes(len(languages_client_to_server),
                                                                     4)  # 4 hex pairs: num < 4294967295
        self.languages_server_to_client_string: bytes = languages_server_to_client.encode()
        self.languages_server_to_client_length: bytes = num_to_bytes(len(languages_server_to_client),
                                                                     4)  # 4 hex pairs: num < 4294967295

        # Hard-coded for now...
        self.first_kex_packet_follows: bytes = num_to_bytes(0, 1)  # 1 hex pair: num < 255. Default 0
        self.reserved: bytes = bytearray.fromhex("00" * 4)  # 4 hex pairs: "00 00 00 00"

        self.padding_string: bytes = b""  # n hex pairs: "00 00 00 00 00"

        self.representation: bytes = b""  # bytes representing packet as w whole. Used to calculate total packet length

        logger.success("constructed client key exchange packet")

        self._compute_packet_length()
        logger.success("calculated packet length")

        super()._construct()

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

    def _generate_cookie(self) -> bytes:
        self.cookie = bytearray.fromhex(secrets.token_hex(16))
        return self.cookie
