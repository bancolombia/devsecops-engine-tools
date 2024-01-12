import subprocess
import re

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.images_scanned import (
    ImagesScanned,
)


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

    def scan_image(self, repository, tag, remoteconfig):
        image_name = f"{repository}:{tag}"
        extensions = "_scan_result.json"
        file_name = "scanned_images.txt"
        images_scanned = []

        if not (
            (image_name + extensions)
            in ImagesScanned.get_images_already_scanned(file_name)
        ):
            pattern = remoteconfig["REGEX_EXPRESSION_PROJECTS"]
            if re.match(pattern, repository.upper()):
                command1 = ["trivy", "image", "--download-db-only"]
                command2 = [
                    "trivy",
                    "--scanners",
                    "vuln",
                    "-f",
                    "json",
                    "-o",
                    image_name + "_scan_result.json",
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
                    images_scanned.append(image_name + extensions)
                    with open(file_name, "a") as file:
                        file.write(image_name + extensions + "\n")
                except subprocess.CalledProcessError as e:
                    print(f"Error during image scan of {repository}: {e.stderr}")

        return images_scanned

    def run_tool_container_sca(self, remoteconfig, token, scan_image):
        try:
            trivy_version = remoteconfig["TRIVY"]["TRIVY_VERSION"]
            self.install_tool(trivy_version)
            images_scanned = []

            for image in scan_image:
                repository, tag = image["Repository"], image["Tag"]
                images_scanned.extend(self.scan_image(repository, tag, remoteconfig))

            return images_scanned

        except Exception as ex:
            print(f"An overall error occurred: {ex}")

        return 0
