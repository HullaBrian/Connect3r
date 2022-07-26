from dataclasses import dataclass


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


@dataclass
class Server:
    ip: str | IP
    mac_address: str
    key_cache: str
    port: int
