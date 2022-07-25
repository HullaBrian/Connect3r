from dataclasses import dataclass


@dataclass
class IP:
    rep: str


@dataclass
class Host:
    ip: str | IP
    mac_address: str
    key_cache: str
    source_port: int
    username: str
    password: str
    ssh_version: str


@dataclass
class Server:
    ip: str | IP
    mac_address: str
    key_cache: str
    destination_port: int
