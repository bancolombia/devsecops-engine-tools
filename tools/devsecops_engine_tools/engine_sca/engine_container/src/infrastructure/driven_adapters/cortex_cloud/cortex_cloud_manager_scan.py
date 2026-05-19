import os
from typing import List

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper import (
    build_scan_base_command,
    get_scan_retry_settings,
    scan_image_with_tarball_fallback,
    split_basic_auth_token,
)
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_postprocess_helper import (
    apply_base_image_exclusions,
    generate_sbom,
)
from devsecops_engine_tools.engine_utilities.twistcli_utils.twistcli_utils import (
    download_twistcli,
)

TOOL_LABEL = "Cortex"
EXCLUSIONS_KEY = "CORTEX"


class CortexCloudManagerScan(ToolGateway):
    def _get_cortex_config(self, remoteconfig):
        return remoteconfig.get("CORTEX_CLOUD", {})

    def download_twistcli(
        self, file_path, cortex_key, cortex_console_url, cortex_api_version
    ) -> int:
        return download_twistcli(
            file_path, cortex_key, cortex_console_url, cortex_api_version
        )

    def _split_cortex_token(self, cortex_key):
        return split_basic_auth_token(cortex_key)

    def scan_image(
        self,
        file_path,
        image_name,
        result_file,
        remoteconfig,
        cortex_key,
        docker_address,
        is_compressed_file,
    ):
        cortex_config = self._get_cortex_config(remoteconfig)
        base_command = build_scan_base_command(
            file_path=file_path,
            console_url=cortex_config["CORTEX_CONSOLE_URL"],
            key=cortex_key,
            docker_address=docker_address,
            result_file=result_file,
        )
        return scan_image_with_tarball_fallback(
            base_command=base_command,
            image_name=image_name,
            result_file=result_file,
            is_compressed_file=is_compressed_file,
            retry_settings=get_scan_retry_settings(cortex_config),
            tool_label=TOOL_LABEL,
        )

    def _write_image_base(self, result_file, base_image, exclusions_data, remoteconfig):
        return apply_base_image_exclusions(
            result_file=result_file,
            base_image=base_image,
            exclusions_data=exclusions_data,
            remoteconfig=remoteconfig,
            exclusions_tool_key=EXCLUSIONS_KEY,
        )

    def _generate_sbom(self, image_scanned, remoteconfig, cortex_key, image_name):
        cortex_config = self._get_cortex_config(remoteconfig)
        return generate_sbom(
            image_scanned=image_scanned,
            console_url=cortex_config["CORTEX_CONSOLE_URL"],
            api_version=cortex_config["CORTEX_API_VERSION"],
            sbom_format=cortex_config["SBOM_FORMAT"],
            key=cortex_key,
            image_name=image_name,
        )

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
    ):
        cortex_config = self._get_cortex_config(remoteconfig)
        if secret_tool:
            cortex_key = (
                f"{secret_tool['access_cortex']}:{secret_tool['token_cortex']}"
            )
        else:
            cortex_key = token_engine_container

        file_path = os.path.join(os.getcwd(), cortex_config["CORTEXCLI_PATH"])
        sbom_components = None

        if not os.path.exists(file_path):
            self.download_twistcli(
                file_path,
                cortex_key,
                cortex_config["CORTEX_CONSOLE_URL"],
                cortex_config["CORTEX_API_VERSION"],
            )

        image_scanned = self.scan_image(
            file_path,
            image_name,
            result_file,
            remoteconfig,
            cortex_key,
            docker_address,
            is_compressed_file,
        )

        if base_image:
            self._write_image_base(result_file, base_image, exclusions, remoteconfig)
        if generate_sbom:
            sbom_components = self._generate_sbom(
                image_scanned, remoteconfig, cortex_key, image_name
            )

        return image_scanned, sbom_components

    def get_container_context_from_results(self, path_file_results: str) -> List:
        return []
