from detect_platform import detect_platform
from pathlib import Path
import os
import subprocess
from loguru import logger


script_path = os.path.join(str(Path.cwd()), "scripts")
scripts = os.listdir(script_path)

platform = detect_platform()
logger.info("detected current device as: " + platform)
if platform == "unknown":
    logger.critical("could not detect current device platform")
for script in scripts:
    if script.startswith(platform):
        logger.info(f"running '{os.path.join(script_path, script)}' in command line")
        subprocess.run(["./" + os.path.join(script_path, script)])
