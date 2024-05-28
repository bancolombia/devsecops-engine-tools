import subprocess
import re

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.images_scanned import (
    ImagesScanned,
)

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
        except subprocess.CalledProcessError as error:
            logger.error(f"Error downloading trivy: {error}")

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
            except subprocess.CalledProcessError as error:
                logger.error(f"Error installing trivy: {error}")
        
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
            except subprocess.CalledProcessError as error:
                logger.error(f"Error installing trivy: {error}")

    def scan_image(self, prefix, image):
        file_name = "scanned_images.txt"
        image_name = f"{image.tags[0]}"
        result_file = f"{image_name}" + "_scan_result.json"
        image_scanned = []

        if (result_file) in ImagesScanned.get_images_already_scanned(file_name):
            print(f"The image {image_name} has already been scanned previously.")
        else:
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
                image_scanned.append(result_file)
                print(f"The image {image_name} was scanned")
                with open(file_name, "a") as file:
                    file.write(result_file + "\n")
            except subprocess.CalledProcessError as e:
                logger.error(
                    f"Error during image scan of {image_name}: {e.stderr}"
                )

        return image_scanned

    def run_tool_container_sca(self, remoteconfig, token, image):
        image_scanned=[]
        trivy_version = remoteconfig["TRIVY"]["TRIVY_VERSION"]
        os_platform = platform.system()
        base_url = f"https://github.com/aquasecurity/trivy/releases/download/v{trivy_version}/"

        if os_platform == "Linux":
            file=f"trivy_{trivy_version}_Linux-64bit.tar.gz"
            self.install_tool(file, base_url+file)
            command_prefix = "./trivy"
        elif os_platform == "Darwin":
            file=f"trivy_{trivy_version}_macOS-64bit.tar.gz"
            self.install_tool(file, base_url+file)
            command_prefix = "./trivy"
        elif os_platform == "Windows":
            file=f"trivy_{trivy_version}_windows-64bit.zip"
            self.install_tool_windows(file, base_url+file)
            command_prefix = "./trivy.exe"
        else:
            logger.warning(f"{os_platform} is not supported.")
            

        image_scanned.extend(
            self.scan_image(command_prefix, image)
        )

        return image_scanned
