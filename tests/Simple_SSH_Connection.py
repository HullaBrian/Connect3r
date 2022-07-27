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

client = SSHClient("172.17.0.2", USERNAME, PASSWORD)
client.connect()

"""
00 04 00 01 00 06 02 42 98 21 80 45 00 00 08 00
45 00 01 2a 2f 8d 40 00 40 06 b2 1b ac 11 00 01
ac 11 00 02 b9 f2 00 16 01 75 f6 18 1f dc 9f 56
80 18 01 f6 59 42 00 00 01 01 08 0a d0 3a 09 70
a3 50 e3 5f 00 00 00 ee 0a 14 9a cb f1 cb 96 02
d0 ff fe 1b 38 f2 ca 6d 7b 38 00 00 00 53 63 75
72 76 65 32 35 35 31 39 2d 73 68 61 32 35 36 2c
63 75 72 76 65 32 35 35 31 39 2d 73 68 61 32 35
36 40 6c 69 62 73 73 68 2e 6f 72 67 2c 64 69 66
66 69 65 2d 68 65 6c 6c 6d 61 6e 2d 67 72 6f 75
70 2d 65 78 63 68 61 6e 67 65 2d 73 68 61 32 35
36 00 00 00 0c 72 73 61 2d 73 68 61 32 2d 35 31
32 00 00 00 0a 61 65 73 32 35 36 2d 63 74 72 00
00 00 0c 72 73 61 2d 73 68 61 32 2d 35 31 32 00
00 00 0d 68 6d 61 63 2d 73 68 61 32 2d 35 31 32
00 00 00 0d 68 6d 61 63 2d 73 68 61 32 2d 35 31
32 00 00 00 0d 68 6d 61 63 2d 73 68 61 32 2d 35
31 32 00 00 00 0d 68 6d 61 63 2d 73 68 61 32 2d
35 31 32 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00
"""