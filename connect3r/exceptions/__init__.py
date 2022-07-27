class ConnectionRefusedException(Exception):
    pass


class ConnectionTimeoutException(Exception):
    pass


class AuthenticationException(Exception):
    pass


class SSHException(Exception):
    pass


class PacketOverflowException(Exception):
    pass


class MissingPacketFieldException(Exception):
    pass


class MalformedPacketException(Exception):
    pass


class MaxPacketSizeExceededException(Exception):
    pass
