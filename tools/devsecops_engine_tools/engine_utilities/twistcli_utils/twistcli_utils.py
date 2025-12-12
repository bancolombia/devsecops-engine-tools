# tools/devsecops_engine_tools/engine_utilities/twistcli_utils/twistcli_utils.py
import os
import stat
import base64
import platform
import logging
import requests

logger = logging.getLogger(__name__)

def download_twistcli(file_path: str, prisma_key: str, prisma_console_url: str, prisma_api_version: str) -> int:
    machine = platform.machine()
    system = platform.system()

    base_url = f"{prisma_console_url}/api/{prisma_api_version}/util"

    os_mapping = {
        "Linux": "twistcli",
        "Windows": "windows/twistcli.exe",
        "Darwin": "osx/twistcli",
    }

    url = f"{base_url}/{os_mapping.get(system, 'twistcli')}"

    if system == "Linux" and machine == "aarch64":
        url = f"{base_url}/arm64/twistcli"
    elif system == "Darwin" and machine == "aarch64":
        url = f"{base_url}/osx/arm64/twistcli"

    credentials = base64.b64encode(prisma_key.encode()).decode()
    headers = {"Authorization": f"Basic {credentials}"}

    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()

        with open(file_path, "wb") as fh:
            fh.write(resp.content)

        os.chmod(file_path, stat.S_IRWXU)
        logger.info("twistcli downloaded and saved to: %s", file_path)
        return 0
    except Exception as e:
        raise ValueError(f"Error downloading twistcli: {e}")
