import json
import re
import subprocess

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_deserialize_output import (
    CortexDeserealizator,
)
from devsecops_engine_tools.engine_utilities.sbom.deserealizator import (
    get_list_component,
)
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.utils.cortexcli_utils import download_cortexcli
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


SCAN_INTRO_PATTERN = re.compile(r"<SCAN_INTRO_START>.*?<SCAN_INTRO_END>", re.DOTALL)


def extract_scan_json(stdout):
    # cortexcli prefixes the JSON report with an intro block delimited by markers.
    return json.loads(SCAN_INTRO_PATTERN.sub("", stdout).strip())


class CortexCloudManagerScan(ToolGateway):
    def _build_auth_command(self, file_path, cortex_config, secret_tool):
        command = [file_path]
        api_base_url = cortex_config.get("CORTEX_API_URL")
        if api_base_url:
            command.extend(["--api-base-url", api_base_url])
        command.extend(
            [
                "--api-key",
                secret_tool["token_cortex"],
                "--api-key-id",
                secret_tool["access_cortex"],
            ]
        )
        return command

    def scan_image(
        self,
        file_path,
        image_name,
        result_file,
        remoteconfig,
        secret_tool,
        docker_address,
        is_compressed_file,
    ):
        cortex_config = remoteconfig.get("CORTEX_CLOUD", {})
        command = self._build_auth_command(file_path, cortex_config, secret_tool) + [
            "--soft-fail",
            "image",
            "scan",
            "--output-format",
            "json",
        ]
        if docker_address:
            command.extend(["--docker-host", docker_address])
        if is_compressed_file:
            command.append("--archive")
        command.append(image_name)

        try:
            result = subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            with open(result_file, "w", encoding="utf-8") as output_file:
                json.dump(extract_scan_json(result.stdout), output_file, indent=2)
            print(f"The image {image_name} was scanned")
            return result_file
        except subprocess.CalledProcessError as error:
            logger.error("Cortex Cloud scan failed with exit code %s", error.returncode)
        except (json.JSONDecodeError, OSError) as error:
            logger.error("Could not save Cortex Cloud scan results: %s", error)
        return None

    def _generate_sbom(
        self,
        file_path,
        image_name,
        remoteconfig,
        secret_tool,
        docker_address,
        is_compressed_file,
    ):
        cortex_config = remoteconfig.get("CORTEX_CLOUD", {})
        sbom_format = cortex_config.get("SBOM_FORMAT", "cyclonedx_json")
        sbom_type = cortex_config.get("SBOM_TYPE", "cyclonedx1.4")
        sbom_file = f"{image_name.replace('/', '_').replace(':', '_')}_SBOM.json"
        command = self._build_auth_command(file_path, cortex_config, secret_tool) + [
            "image",
            "sbom",
            "--output-format",
            "json",
            "--sbom-type",
            sbom_type,
            "--output-file",
            sbom_file,
        ]
        if docker_address:
            command.extend(["--docker-host", docker_address])
        if is_compressed_file:
            command.append("--archive")
        command.append(image_name)

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
            return get_list_component(sbom_file, sbom_format)
        except (subprocess.CalledProcessError, OSError, ValueError) as error:
            logger.error("Cortex Cloud SBOM generation failed: %s", error)
            return None

    def run_tool_container_sca(
        self,
        remoteconfig,
        secret_tool,
        token_engine_container,
        image_name,
        result_file,
        base_image,
        exclusions,
        generate_sbom,
        docker_address,
        is_compressed_file=False,
        cross_approval_exclusions=None,
    ):
        cortex_config = remoteconfig.get("CORTEX_CLOUD", {})
        version = cortex_config.get("CORTEX_CLI_VERSION", "0.37.0")
        if not secret_tool or not secret_tool.get("token_cortex") or not secret_tool.get("access_cortex"):
            raise ValueError("Cortex Cloud credentials are missing from Secret Manager")
        file_path = download_cortexcli(version)
        image_scanned = self.scan_image(
            file_path,
            image_name,
            result_file,
            remoteconfig,
            secret_tool,
            docker_address,
            is_compressed_file,
        )
        sbom_components = None
        if image_scanned and generate_sbom:
            sbom_components = self._generate_sbom(
                file_path,
                image_name,
                remoteconfig,
                secret_tool,
                docker_address,
                is_compressed_file,
            )
        return image_scanned, sbom_components

    def get_container_context_from_results(self, path_file_results):
        return CortexDeserealizator().get_container_context_from_results(path_file_results)