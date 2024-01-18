import subprocess
import re

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.images_scanned import (
    ImagesScanned,
)

from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class TrivyScan(ToolGateway):
    def install_tool(self, version):
        installed = subprocess.run(
            ["which", "trivy"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                command1 = [
                    "wget",
                    "https://github.com/aquasecurity/trivy/releases/download/v"
                    + version
                    + "/trivy_"
                    + version
                    + "_Linux-64bit.deb",
                ]
                subprocess.run(
                    command1, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                command2 = [
                    "sudo",
                    "dpkg",
                    "-i",
                    "trivy_" + version + "_Linux-64bit.deb",
                ]
                subprocess.run(
                    command2, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            except subprocess.CalledProcessError as error:
                raise RuntimeError(f"Error al instalar trivy: {error}")

    def scan_image(self, repository, tag, remoteconfig, release):
        file_name = "scanned_images.txt"
        repo = repository.split("/")[1] if len(repository.split("/")) >= 2 else ""
        image_name = f"{repository}:{tag}"
        result_file = f"{repo}:{tag}" + "_scan_result.json"
        images_scanned = []

        if not ((result_file) in ImagesScanned.get_images_already_scanned(file_name)):
            pattern = remoteconfig["REGEX_EXPRESSION_PROJECTS"]
            match = re.match(pattern, repo.upper())
            if match:
                if match.group() in release.upper():
                    command1 = ["trivy", "image", "--download-db-only"]
                    command2 = [
                        "trivy",
                        "--scanners",
                        "vuln",
                        "-f",
                        "json",
                        "-o",
                        result_file,
                    ]
                    command2.extend(["--quiet", "image", image_name])
                    try:
                        subprocess.run(
                            command1,
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                        subprocess.run(
                            command2,
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                        images_scanned.append(result_file)
                        with open(file_name, "a") as file:
                            file.write(result_file + "\n")
                    except subprocess.CalledProcessError as e:
                        logger.error(
                            f"Error during image scan of {repository}: {e.stderr}"
                        )

        return images_scanned

    def run_tool_container_sca(self, remoteconfig, token, scan_image, release):
        try:
            trivy_version = remoteconfig["TRIVY"]["TRIVY_VERSION"]
            self.install_tool(trivy_version)
            images_scanned = []

            for image in scan_image:
                repository, tag = image["Repository"], image["Tag"]
                images_scanned.extend(
                    self.scan_image(repository, tag, remoteconfig, release)
                )

            return images_scanned

        except Exception as ex:
            logger.error(f"An overall error occurred: {ex}")

        return 0
