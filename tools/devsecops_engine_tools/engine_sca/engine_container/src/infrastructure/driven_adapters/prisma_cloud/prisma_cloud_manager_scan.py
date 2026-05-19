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

TOOL_LABEL = "Prisma"
EXCLUSIONS_KEY = "PRISMA"


class PrismaCloudManagerScan(ToolGateway):
    def _get_prisma_config(self, remoteconfig):
        return remoteconfig.get("PRISMA_CLOUD", {})

    def download_twistcli(
        self, file_path, prisma_key, prisma_console_url, prisma_api_version
    ) -> int:
        return download_twistcli(
            file_path, prisma_key, prisma_console_url, prisma_api_version
        )

    def _split_prisma_token(self, prisma_key):
        return split_basic_auth_token(
            prisma_key,
            error_message="The string is not properly formatted. Make sure it contains a ':'.",
        )

    def scan_image(
        self,
        file_path,
        image_name,
        result_file,
        remoteconfig,
        prisma_key,
        docker_address,
        is_compressed_file,
    ):
        prisma_config = self._get_prisma_config(remoteconfig)
        base_command = build_scan_base_command(
            file_path=file_path,
            console_url=prisma_config["PRISMA_CONSOLE_URL"],
            key=prisma_key,
            docker_address=docker_address,
            result_file=result_file,
        )
        return scan_image_with_tarball_fallback(
            base_command=base_command,
            image_name=image_name,
            result_file=result_file,
            is_compressed_file=is_compressed_file,
            retry_settings=get_scan_retry_settings(prisma_config),
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

    def _generate_sbom(self, image_scanned, remoteconfig, prisma_key, image_name):
        prisma_config = self._get_prisma_config(remoteconfig)
        return generate_sbom(
            image_scanned=image_scanned,
            console_url=prisma_config["PRISMA_CONSOLE_URL"],
            api_version=prisma_config["PRISMA_API_VERSION"],
            sbom_format=prisma_config["SBOM_FORMAT"],
            key=prisma_key,
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
        prisma_config = self._get_prisma_config(remoteconfig)
        if secret_tool:
            prisma_key = (
                f"{secret_tool['access_prisma']}:{secret_tool['token_prisma']}"
            )
        else:
            prisma_key = token_engine_container

        file_path = os.path.join(os.getcwd(), prisma_config["TWISTCLI_PATH"])
        sbom_components = None

        if not os.path.exists(file_path):
            self.download_twistcli(
                file_path,
                prisma_key,
                prisma_config["PRISMA_CONSOLE_URL"],
                prisma_config["PRISMA_API_VERSION"],
            )

        image_scanned = self.scan_image(
            file_path,
            image_name,
            result_file,
            remoteconfig,
            prisma_key,
            docker_address,
            is_compressed_file,
        )

        if base_image:
            self._write_image_base(result_file, base_image, exclusions, remoteconfig)
        if generate_sbom:
            sbom_components = self._generate_sbom(
                image_scanned, remoteconfig, prisma_key, image_name
            )

        return image_scanned, sbom_components

    def get_container_context_from_results(self, path_file_results: str) -> List:
        return []
