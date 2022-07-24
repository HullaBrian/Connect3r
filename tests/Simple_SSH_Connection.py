from connect3r.objects.SSHClient import SSHClient
from dotenv import load_dotenv, find_dotenv
import os
from loguru import logger

logger.info("loading environment variables")
load_dotenv(find_dotenv())
IP: str = os.getenv("DOCKER_IP")
logger.info("found docker ip to be: " + IP)
USERNAME: str = os.getenv("DOCKER_USERNAME")
logger.info("found docker username to be: " + USERNAME)
PASSWORD: str = os.getenv("DOCKER_PASSWORD")
logger.info("found docker password to be: " + PASSWORD)
PORT: str = os.getenv("DOCKER_PORT")
logger.info("found docker port to be: " + PORT)

client = SSHClient("127.0.0.1", USERNAME, PASSWORD, port=int(PORT))
