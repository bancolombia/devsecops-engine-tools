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
    def install_tool(self, version, platform):
        installed = subprocess.run(
            ["which", "./trivy"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                file=f"trivy_{version}_{platform}-64bit.tar.gz"
                url=f"https://github.com/aquasecurity/trivy/releases/download/v{version}/{file}"
                response = requests.get(url, allow_redirects=True)
                with open(file, "wb") as tar_file:
                    tar_file.write(response.content)
                with tarfile.open(file, 'r:gz') as tar_file:
                    tar_file.extractall()
            except subprocess.CalledProcessError as error:
                raise RuntimeError(f"Error installing trivy: {error}")
        
    def install_tool_windows(self, version):
        try:
            subprocess.run(
                ["./trivy.exe", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                file=f"trivy_{version}_windows-64bit.zip"
                url=f"https://github.com/aquasecurity/trivy/releases/download/v{version}/{file}"
                response = requests.get(url, allow_redirects=True)
                with open(file, "wb") as zip_file:
                    zip_file.write(response.content)
                with zipfile.ZipFile(file, 'r') as zip_file:
                    zip_file.extractall()
            except subprocess.CalledProcessError as error:
                raise RuntimeError(f"Error installing trivy: {error}")

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

        if os_platform == "Linux":
            self.install_tool(trivy_version, "Linux")
            command_prefix = "./trivy"
        elif os_platform == "Darwin":
            self.install_tool(trivy_version, "macOS")
            command_prefix = "./trivy"
        elif os_platform == "Windows":
            self.install_tool_windows(trivy_version)
            command_prefix = "./trivy.exe"
        else:
            logger.warning(f"{os_platform} is not supported.")
            

        image_scanned.extend(
            self.scan_image(command_prefix, image)
        )

        return image_scanned
