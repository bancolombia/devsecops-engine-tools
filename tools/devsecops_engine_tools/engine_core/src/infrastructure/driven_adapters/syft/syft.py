from dataclasses import dataclass
import requests
import subprocess
import tarfile
import zipfile
import platform
import os

from devsecops_engine_tools.engine_core.src.domain.model.gateway.sbom_manager import (
    SbomManagerGateway,
)
from devsecops_engine_tools.engine_utilities.sbom.deserealizator import (
    get_list_component,
)
from devsecops_engine_tools.engine_core.src.domain.model.component import (
    Component,
)

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

VERSIONED_OUTPUT_FORMATS = (
    "cyclonedx-json",
    "cyclonedx-xml",
    "spdx-json",
    "spdx-tag-value",
)


@dataclass
class Syft(SbomManagerGateway):

    def get_components(self, artifact, config, service_name) -> "list[Component]":
        try:
            syft_version = config["SYFT"]["SYFT_VERSION"]
            os_platform = platform.system()
            base_url = (
                f"https://github.com/anchore/syft/releases/download/v{syft_version}/"
            )

            command_prefix = "syft"
            if os_platform == "Linux":
                file = f"syft_{syft_version}_linux_amd64.tar.gz"
                command_prefix = self._install_tool_unix(
                    file, base_url + file, command_prefix
                )
            elif os_platform == "Darwin":
                file = f"syft_{syft_version}_darwin_amd64.tar.gz"
                command_prefix = self._install_tool_unix(
                    file, base_url + file, command_prefix
                )
            elif os_platform == "Windows":
                file = f"syft_{syft_version}_windows_amd64.zip"
                command_prefix = self._install_tool_windows(
                    file, base_url + file, "syft.exe"
                )
            else:
                logger.warning(f"{os_platform} is not supported.")
                return None

            result_sbom = self._run_syft(command_prefix, artifact, config, service_name)
            return get_list_component(result_sbom, config["SYFT"]["OUTPUT_FORMAT"])
        except Exception as e:
            logger.error(f"Error generating SBOM: {e}")
            return None

    def _run_syft(self, command_prefix, artifact, config, service_name):
        result_file = f"{service_name}_SBOM.json"
        syft_config = config['SYFT']

        output_format = syft_config['OUTPUT_FORMAT']
        spec_version = syft_config.get('SPEC_VERSION', "")
        if spec_version and output_format in VERSIONED_OUTPUT_FORMATS:
            output_format = f"{output_format}@{spec_version}"

        command = [
            command_prefix,
            artifact,
            "-o",
            f"{output_format}={result_file}",
        ]
        
        exclude_paths = syft_config.get('EXCLUDE_PATHS', [])
        for path in exclude_paths:
            command.extend(["--exclude", path])

        exclude_catalogers = syft_config.get('EXCLUDE_CATALOGERS', [])
        if exclude_catalogers:
            catalogers_with_prefix = [f"-{cat}" for cat in exclude_catalogers]
            command.extend(["--select-catalogers", ",".join(catalogers_with_prefix)])

        debug_pipelines = syft_config.get('DEBUG_PIPELINES', [])
        enable_debug = service_name in debug_pipelines if debug_pipelines else False
        
        if enable_debug:
            logger.info(f"Enabling debug mode for pipeline: {service_name}")
            command.append("-v")
        
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            if enable_debug:
                if result.stdout:
                    logger.info(f"SYFT stdout: {result.stdout}")
                if result.stderr:
                    logger.info(f"SYFT stderr: {result.stderr}")
            
            if result.returncode == 0:
                print(f"SBOM generated and saved to: {result_file}")
                return result_file
            else:
                raise Exception(f"Syft command failed with return code: {result.returncode}")
        except Exception as e:
            logger.error(f"Error running syft: {e}")
            raise

    def _install_tool_unix(self, file, url, command_prefix):
        installed = subprocess.run(
            ["which", command_prefix],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                tmp_file = os.path.join("/tmp", file)
                tmp_syft = "/tmp/syft"
                self._download_tool(tmp_file, url)
                with tarfile.open(tmp_file, "r:gz") as tar_file:
                    tar_file.extract(member=tar_file.getmember("syft"), path="/tmp")
                    os.chmod(tmp_syft, 0o755)
                    return tmp_syft
            except Exception as e:
                logger.error(f"Error installing syft: {e}")
        else:
            return installed.stdout.decode("utf-8").strip()

    def _install_tool_windows(self, file, url, command_prefix):
        try:
            installed = subprocess.run(
                [command_prefix, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return installed.stdout.decode("utf-8").strip()
        except:
            try:
                tmp_file = os.path.join("/tmp", file)
                tmp_syft = "/tmp/syft.exe"
                self._download_tool(tmp_file, url)
                with zipfile.ZipFile(tmp_file, "r") as zip_file:
                    zip_file.extract(member="syft.exe", path="/tmp")
                    return tmp_syft
            except Exception as e:
                logger.error(f"Error installing syft: {e}")

    def _download_tool(self, file_path, url):
        try:
            response = requests.get(url, allow_redirects=True)
            with open(file_path, "wb") as compress_file:
                compress_file.write(response.content)
        except Exception as e:
            logger.error(f"Error downloading syft: {e}")
