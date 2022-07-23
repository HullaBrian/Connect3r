import socket
import os
from loguru import logger
from dotenv import load_dotenv, find_dotenv
from connect3r.objects import IP


def check_ssh(server_ip: IP, port=22) -> bool:
    """
    Verifies that an ssh connection is running on the local docker container
    :param server_ip:
    :param port:
    :return:
    """
    logger.info("checking if container is hosting ssh service")
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.connect((server_ip.rep, port))
        logger.success("successfully verified container is running ssh service")
    except Exception as ex:
        logger.error("error verifying container's ssh server: " + str(ex))
        return False
    else:
        test_socket.close()
        logger.success("closed test socket")
    return True


def check_environment() -> bool:
    """
    Checks through .env file in root directory to ensure that necessary variables are set
    :return:
    """
    load_dotenv(find_dotenv())
    logger.success("loaded .env file")

    docker_lst = ["IP", "USERNAME", "PASSWORD"]

    for word in docker_lst:
        logger.info("checking for DOCKER_" + word)
        if os.getenv("DOCKER_" + word) == "":
            return False
    return True
