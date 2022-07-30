from dataclasses import dataclass
from loguru import logger

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