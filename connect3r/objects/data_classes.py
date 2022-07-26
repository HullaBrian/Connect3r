from dataclasses import dataclass
import secrets
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend


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

    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )

    return private_key, public_key


@dataclass
class KEX_PACKET:
    packet_length: int  # 4 hex pairs: num < 4294967295
    padding_length: int  # 1 hex pair: num < 255
    message_code_kex_init: int  # 1 hex pair: num < 255
    cookie: str  # 16 hex pairs
    kex_algorithms_length: int  # (Length of ASCII text) 4 hex pairs: num < 4294967295
    kex_algorithms_string_truncated: str  # <kex_algorithms_length> hex pairs
    server_host_key_algorithms_length: int  # 4 hex pairs: num < 4294967295
    server_host_key_algorithms_string: str
    encryption_algorithms_client_to_server_length: int  # 4 hex pairs: num < 4294967295
    encryption_algorithms_client_to_server_string: str
    encryption_algorithms_server_to_client_length: int  # 4 hex pairs: num < 4294967295
    encryption_algorithms_server_to_client_string: str
    mac_algorithms_client_to_server_length: int  # 4 hex pairs: num < 4294967295
    mac_algorithms_client_to_server_string: str
    mac_algorithms_server_to_client_length: int  # 4 hex pairs: num < 4294967295
    mac_algorithms_server_to_client_string: str
    compression_algorithms_client_to_server_length: int  # 4 hex pairs: num < 4294967295
    compression_algorithms_client_to_server_string: str
    compression_algorithms_server_to_client_length: int  # 4 hex pairs: num < 4294967295
    compression_algorithms_server_to_client_string: str
    languages_client_to_server_length: int  # 4 hex pairs: num < 4294967295
    languages_client_to_server_string: str
    languages_server_to_client_length: int  # 4 hex pairs: num < 4294967295
    languages_server_to_client_string: str
    first_kex_packet_follows: int  # 1 hex pair: num < 255. Default 0
    reserved: str  # 4 hex pairs: "00 00 00 00"
    padding_string: str  # 5 hex pairs: "00 00 00 00 00"

    def construct(self):
        self.message_code_kex_init = bytearray.fromhex("14")

    def _generate_cookie(self):
        self.cookie = secrets.token_hex(32)

    def _get_padding(self) -> int:
        return (self.packet_length + 5) % 8



