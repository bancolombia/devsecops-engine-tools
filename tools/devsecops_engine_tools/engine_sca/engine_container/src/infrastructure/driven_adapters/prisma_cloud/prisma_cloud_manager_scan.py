import requests
import os
import subprocess
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
from devsecops_engine_tools.engine_utilities.twistcli_utils.twistcli_utils import download_twistcli

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class PrismaCloudManagerScan(ToolGateway):
    def download_twistcli(self, file_path, prisma_key, prisma_console_url, prisma_api_version) -> int:
        """
        Método de instancia separado (lo que usan los tests),
        delega en el util compat 'basic' para no romper aserciones.
        """
        return download_twistcli(file_path, prisma_key, prisma_console_url, prisma_api_version)
    def scan_image(
        self, file_path, image_name, result_file, remoteconfig, prisma_key, docker_address
    ):
        command = [
            file_path,
            "images",
            "scan",
            "--address",
            remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
            "--user",
            self._split_prisma_token(prisma_key)[0],
            "--password",
            self._split_prisma_token(prisma_key)[1],
        ]

        if docker_address:
            command.extend(["--docker-address", docker_address])

        command.extend([
            "--output-file",
            result_file,
            "--details",
            image_name,
        ])

        try:
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            print(f"The image {image_name} was scanned")
            return result_file

        except subprocess.CalledProcessError as e:
            logger.error(f"Error during image scan of {image_name}: {e.stderr}")

    def _write_image_base(self, result_file, base_image, exclusions_data, remoteconfig):
        try:
            with open(result_file, "r") as file:
                data = json.load(file)

            prisma_exclusions = exclusions_data.get("All", {}).get("PRISMA", [])
            modified = False
            base_image_list = base_image[0][0] if base_image and base_image[0][0] else []
            
            
            key_image_exception = remoteconfig.get("GET_IMAGE_BASE", {}).get("LABEL_KEYS", {}).get("key_image_exception", None)
            
            for result in data.get("results", []):
                for vulnerability in result.get("vulnerabilities", []):
                    for exclusion in prisma_exclusions:
                        if (
                            vulnerability.get("id") == exclusion.get("id") and
                            any(b_image.startswith(ex_image) for b_image in base_image_list for ex_image in exclusion.get(key_image_exception, []))
                        ):
                            vulnerability["baseImage"] = str(base_image_list) if base_image_list else ""
                            modified = True

            if modified:
                with open(result_file, "w") as file:
                    json.dump(data, file, indent=4)
        except subprocess.CalledProcessError as e:
             logger.error(f"Error during write image base of {base_image}: {e.stderr}")
            
    def _generate_sbom(self, image_scanned, remoteconfig, prisma_key, image_name):

        url = f"{remoteconfig['PRISMA_CLOUD']['PRISMA_CONSOLE_URL']}/api/{remoteconfig['PRISMA_CLOUD']['PRISMA_API_VERSION']}/sbom/download/cli-images"
        credentials = base64.b64encode(
            prisma_key.encode()
        ).decode()
        headers = {"Authorization": f"Basic {credentials}"}
        try:

            with open(image_scanned, "rb") as file:
                image_object = file.read()
                json_data = json.loads(image_object)

            if not json_data["results"]:
                print("No results found in the scan, SBOM not generated")
                return None

            response = requests.get(
                url,
                headers=headers,
                params={
                    "id": json_data["results"][0]["scanID"],
                    "sbomFormat": remoteconfig["PRISMA_CLOUD"]["SBOM_FORMAT"],
                },
            )
            response.raise_for_status()

            result_sbom = f"{image_name.replace('/', '_')}_SBOM.json"
            with open(result_sbom, "wb") as file:
                file.write(response.content)
            
            print(f"SBOM generated and saved to: {result_sbom}")

            return get_list_component(result_sbom, remoteconfig["PRISMA_CLOUD"]["SBOM_FORMAT"])
        except Exception as e:
            logger.error(f"Error generating SBOM: {e}")

    def _split_prisma_token(self, prisma_key):
        try:
            access_prisma, token_prisma = prisma_key.split(":")
            return access_prisma, token_prisma
        except ValueError:
            raise ValueError("The string is not properly formatted. Make sure it contains a ':'.")
        
    def run_tool_container_sca(
        self, remoteconfig, secret_tool, token_engine_container, image_name, result_file, base_image, exclusions, generate_sbom, docker_address, is_compressed_file=False
    ):
        if is_compressed_file:
            logger.warning("Prisma Cloud does not support compressed file scanning. Skipping.")
            return "", None
            
        prisma_key = (
            f"{secret_tool['access_prisma']}:{secret_tool['token_prisma']}" if secret_tool else token_engine_container
        )
        file_path = os.path.join(
            os.getcwd(), remoteconfig["PRISMA_CLOUD"]["TWISTCLI_PATH"]
        )
        sbom_components = None

        if not os.path.exists(file_path):
            self.download_twistcli(
                file_path,
                prisma_key,
                remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
                remoteconfig["PRISMA_CLOUD"]["PRISMA_API_VERSION"],
            )
        image_scanned = self.scan_image(
            file_path,
            image_name,
            result_file,
            remoteconfig,
            prisma_key,
            docker_address
        )
        if base_image:
            self._write_image_base(result_file, base_image, exclusions, remoteconfig)
        if generate_sbom:
            sbom_components = self._generate_sbom(
                image_scanned,
                remoteconfig,
                prisma_key,
                image_name
            )

        return image_scanned, sbom_components
