from dataclasses import dataclass
import requests
import subprocess
import tarfile
import zipfile
import platform

from devsecops_engine_tools.engine_core.src.domain.model.gateway.sbom_manager import (
    SbomManagerGateway,
)
from devsecops_engine_tools.engine_utilities.sbom.deserealizator import (
    get_list_component,
)

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


@dataclass
class Syft(SbomManagerGateway):

    def get_components(self, artifact, config):

        syft_version = config["SYFT"]["SYFT_VERSION"]
        os_platform = platform.system()
        arch_platform = platform.uname().machine
        base_url = f"https://github.com/anchore/syft/releases/download/v{syft_version}/"

        command_prefix = "syft"
        if os_platform == "Linux":
            file = f"syft_{syft_version}_linux_{arch_platform}.tar.gz"
            command_prefix = self._install_tool_unix(file, base_url + file, command_prefix)
        elif os_platform == "Darwin":
            file = f"syft_{syft_version}_darwin_{arch_platform}.tar.gz"
            command_prefix = self._install_tool_unix(file, base_url + file, command_prefix)
        elif os_platform == "Windows":
            file = f"syft_{syft_version}_windows_{arch_platform}.zip"
            command_prefix = self._install_tool_windows(file, base_url + file, "syft.exe")
        else:
            logger.warning(f"{os_platform} is not supported.")
            return None

        result_sbom = self._run_syft(command_prefix, artifact, config)
        return get_list_component(result_sbom, config["SYFT"]["OUTPUT_FORMAT"])

    def _run_syft(self, command_prefix, artifact, config):
        result_file = "syft-sbom.json"
        command = [
            command_prefix,
            artifact,
            "-o",
            f"{config['SYFT']['OUTPUT_FORMAT']}={result_file}",
        ]
        try:
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            print(f"SBOM generated and saved to: {result_file}")
            return result_file
        except Exception as e:
            logger.error(f"Error during sbom generation of {artifact}: {e}")

    def _install_tool_unix(self, file, url, command_prefix):
        installed = subprocess.run(
            ["which", command_prefix],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                self._download_tool(file, url)
                with tarfile.open(file, 'r:gz') as tar_file:
                    tar_file.extract(member=tar_file.getmember("syft"))
                    return "./syft"
            except Exception as e:
                logger.error(f"Error installing syft: {e}")
        else:
            return installed.stdout.decode("utf-8").strip()

    def _install_tool_windows(self, file, url, command_prefix):
        try:
            subprocess.run(
                [command_prefix, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return command_prefix
        except:
            try:
                self._download_tool(file, url)
                with zipfile.ZipFile(file, "r") as zip_file:
                    zip_file.extract(member="syft.exe")
                    return "./syft.exe"
            except Exception as e:
                logger.error(f"Error installing syft: {e}")

    def _download_tool(self, file, url):
        try:
            response = requests.get(url, allow_redirects=True)
            with open(file, "wb") as compress_file:
                compress_file.write(response.content)
        except Exception as e:
            logger.error(f"Error downloading syft: {e}")
