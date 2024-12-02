import stat
import requests
import os
import subprocess
import logging
import base64
import json
from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_utilities.sbom.deserealizator import (
    get_list_component,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class PrismaCloudManagerScan(ToolGateway):
    def download_twistcli(
        self,
        file_path,
        prisma_access_key,
        prisma_secret_key,
        prisma_console_url,
        prisma_api_version,
    ):
        url = f"{prisma_console_url}/api/{prisma_api_version}/util/twistcli"
        credentials = base64.b64encode(
            f"{prisma_access_key}:{prisma_secret_key}".encode()
        ).decode()
        headers = {"Authorization": f"Basic {credentials}"}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            with open(file_path, "wb") as file:
                file.write(response.content)

            os.chmod(file_path, stat.S_IRWXU)
            logging.info(f"twistcli downloaded and saved to: {file_path}")
            return 0

        except Exception as e:
            raise ValueError(f"Error downloading twistcli: {e}")

    def scan_image(
        self, file_path, image_name, result_file, remoteconfig, prisma_secret_key
    ):
        command = (
            file_path,
            "images",
            "scan",
            "--address",
            remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
            "--user",
            remoteconfig["PRISMA_CLOUD"]["PRISMA_ACCESS_KEY"],
            "--password",
            prisma_secret_key,
            "--output-file",
            result_file,
            "--details",
            image_name,
        )
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

        except subprocess.CalledProcessError as e:
            logger.error(f"Error during image scan of {image_name}: {e.stderr}")

    def _generate_sbom(self, image_scanned, remoteconfig, prisma_secret_key, image_name):

        url = f"{remoteconfig['PRISMA_CLOUD']['PRISMA_CONSOLE_URL']}/api/{remoteconfig['PRISMA_CLOUD']['PRISMA_API_VERSION']}/sbom/download/cli-images"
        credentials = base64.b64encode(
            f"{remoteconfig['PRISMA_CLOUD']['PRISMA_ACCESS_KEY']}:{prisma_secret_key}".encode()
        ).decode()
        headers = {"Authorization": f"Basic {credentials}"}
        try:

            with open(image_scanned, "rb") as file:
                image_object = file.read()
                json_data = json.loads(image_object)

            response = requests.get(
                url,
                headers=headers,
                params={
                    "id": json_data["results"][0]["scanID"],
                    "sbomFormat": remoteconfig["PRISMA_CLOUD"]["SBOM_FORMAT"],
                },
            )
            response.raise_for_status()

            result_sbom = f"{image_name}_SBOM.json"
            with open(result_sbom, "wb") as file:
                file.write(response.content)
            
            print(f"SBOM generated and saved to: {result_sbom}")

            return get_list_component(result_sbom, remoteconfig["PRISMA_CLOUD"]["SBOM_FORMAT"])
        except Exception as e:
            logger.error(f"Error generating SBOM: {e}")

    def run_tool_container_sca(
        self, remoteconfig, secret_tool, token_engine_container, image_name, result_file, generate_sbom
    ):
        prisma_secret_key = (
            secret_tool["token_prisma_cloud"] if secret_tool else token_engine_container
        )
        file_path = os.path.join(
            os.getcwd(), remoteconfig["PRISMA_CLOUD"]["TWISTCLI_PATH"]
        )
        sbom_components = None

        if not os.path.exists(file_path):
            self.download_twistcli(
                file_path,
                remoteconfig["PRISMA_CLOUD"]["PRISMA_ACCESS_KEY"],
                prisma_secret_key,
                remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
                remoteconfig["PRISMA_CLOUD"]["PRISMA_API_VERSION"],
            )
        image_scanned = self.scan_image(
            file_path,
            image_name,
            result_file,
            remoteconfig,
            prisma_secret_key,
        )
        if generate_sbom:
            sbom_components = self._generate_sbom(
                image_scanned,
                remoteconfig,
                prisma_secret_key,
                image_name
            )

        return image_scanned, sbom_components
