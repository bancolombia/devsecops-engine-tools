from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

import requests
import subprocess
import os
import platform
import shutil

from devsecops_engine_tools.engine_utilities.utils.utils import Utils
from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.helpers.get_artifacts import GetArtifacts
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class DependencyCheckTool(ToolGateway):
    def download_tool(self, cli_version):
        try:
            url = f"https://github.com/jeremylong/DependencyCheck/releases/download/v{cli_version}/dependency-check-{cli_version}-release.zip"
            response = requests.get(url, allow_redirects=True)
            home_directory = os.path.expanduser("~")
            zip_name = os.path.join(home_directory, f"dependency_check_{cli_version}.zip")
            with open(zip_name, "wb") as f:
                f.write(response.content)

            utils = Utils()
            utils.unzip_file(zip_name, home_directory)
        except Exception as ex:
            logger.error(f"An error ocurred downloading dependency-check {ex}")

    def install_tool(self, cli_version, is_windows=False):
        command_prefix = "dependency-check.bat" if is_windows else "dependency-check.sh"

        installed = shutil.which(command_prefix)
        if installed:
            return command_prefix

        home_directory = os.path.expanduser("~")
        bin_route = os.path.join(home_directory, f"dependency-check/bin/{command_prefix}")

        if shutil.which(bin_route):
            return bin_route

        self.download_tool(cli_version)

        try:
            if os.path.exists(bin_route):
                if not is_windows:
                    subprocess.run(["chmod", "+x", bin_route], check=True)
                return bin_route 
        except Exception as e:
            logger.error(f"Error installing OWASP dependency check: {e}")
            return None

    def scan_dependencies(self, command_prefix, file_to_scan, token):
        try:
            command = [command_prefix, "--format", "JSON", "--format", "XML", "--nvdApiKey", token, "--scan", file_to_scan,]

            if not token:
                print("¡¡Remember!!, it is recommended to use the API key for faster vulnerability database downloads.")
                command = [command_prefix, "--format", "JSON", "--format", "XML", "--scan", file_to_scan,]

            subprocess.run(command, capture_output=True, check=True)
        except subprocess.CalledProcessError as error:
            logger.error(f"Error executing OWASP dependency check scan: {error}")

    def select_operative_system(self, cli_version):
        os_platform = platform.system()

        if os_platform in ["Linux", "Darwin"]:
            return self.install_tool(cli_version, is_windows=False)
        elif os_platform == "Windows":
            return self.install_tool(cli_version, is_windows=True)
        else:
            logger.warning(f"{os_platform} is not supported.")
            return None

    def search_result(self):
        try:
            file_result = os.path.join(os.getcwd(), "dependency-check-report.xml")
            return file_result
        except Exception as ex:
            logger.error(f"An error ocurred search dependency-check results {ex}")
            return None
        
    def is_java_installed(self):
        return shutil.which("java") is not None

    def run_tool_dependencies_sca(
        self,
        remote_config,
        dict_args,
        exclusion,
        pipeline_name,
        to_scan,
        token,
        token_engine_dependencies
    ):
        if not self.is_java_installed():
            logger.error("Java is not installed, please install it to run dependency check")
            return None

        cli_version = remote_config["DEPENDENCY_CHECK"]["CLI_VERSION"]

        get_artifacts = GetArtifacts()

        pattern = get_artifacts.excluded_files(remote_config, pipeline_name, exclusion, "DEPENDENCY_CHECK")
        to_scan = get_artifacts.find_artifacts(
            to_scan, pattern, remote_config["DEPENDENCY_CHECK"]["PACKAGES_TO_SCAN"]
        )

        if not to_scan:
            return None

        command_prefix = self.select_operative_system(cli_version)
        self.scan_dependencies(command_prefix, to_scan, token_engine_dependencies)
        return self.search_result()
