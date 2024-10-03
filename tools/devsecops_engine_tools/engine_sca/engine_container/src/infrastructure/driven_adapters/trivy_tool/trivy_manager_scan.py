from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

import subprocess
import platform
import requests
import tarfile
import zipfile

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class TrivyScan(ToolGateway):
    def download_tool(self, file, url):
        try:
            response = requests.get(url, allow_redirects=True)
            with open(file, "wb") as compress_file:
                compress_file.write(response.content)
        except Exception as e:
            logger.error(f"Error downloading trivy: {e}")

    def install_tool(self, file, url):
        installed = subprocess.run(
            ["which", "./trivy"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                self.download_tool(file, url)
                with tarfile.open(file, 'r:gz') as tar_file:
                    tar_file.extract(member=tar_file.getmember("trivy"))
            except Exception as e:
                logger.error(f"Error installing trivy: {e}")
        
    def install_tool_windows(self, file, url):
        try:
            subprocess.run(
                ["./trivy.exe", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                self.download_tool(file, url)
                with zipfile.ZipFile(file, 'r') as zip_file:
                    zip_file.extract(member="trivy.exe")
            except Exception as e:
                logger.error(f"Error installing trivy: {e}")

    def scan_image(self, prefix, image_name, result_file):
        command = [
            prefix,
            "--scanners",
            "vuln",
            "-f",
            "json",
            "-o",
            result_file,
        ]
        command.extend(["--quiet", "image", image_name])
        try:
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            print(f"The image {image_name} was scanned")

            return result_file

        except Exception as e:
            logger.error(f"Error during image scan of {image_name}: {e}")

    def run_tool_container_sca(self, remoteconfig, secret_tool, token_engine_container, image_name, result_file):
        trivy_version = remoteconfig["TRIVY"]["TRIVY_VERSION"]
        os_platform = platform.system()
        arch_platform = platform.architecture()[0]
        base_url = f"https://github.com/aquasecurity/trivy/releases/download/v{trivy_version}/"

        if os_platform == "Linux":
            file=f"trivy_{trivy_version}_Linux-{arch_platform}.tar.gz"
            self.install_tool(file, base_url+file)
            command_prefix = "./trivy"
        elif os_platform == "Darwin":
            file=f"trivy_{trivy_version}_macOS-{arch_platform}.tar.gz"
            self.install_tool(file, base_url+file)
            command_prefix = "./trivy"
        elif os_platform == "Windows":
            file=f"trivy_{trivy_version}_windows-{arch_platform}.zip"
            self.install_tool_windows(file, base_url+file)
            command_prefix = "./trivy.exe"
        else:
            logger.warning(f"{os_platform} is not supported.")
            return None

        image_scanned = (
            self.scan_image(command_prefix, image_name, result_file)
        )

        return image_scanned
