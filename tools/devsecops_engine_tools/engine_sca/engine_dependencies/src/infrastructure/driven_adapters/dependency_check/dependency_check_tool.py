from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

import requests
import subprocess
import os
import platform
import json

from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import GithubApi
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class DependencyCheckTool(ToolGateway):

    def download_tool(self, cli_version):
        try:
            zip_name = f"dependency_check_{cli_version}.zip"
            url = f"https://github.com/jeremylong/DependencyCheck/releases/download/v{cli_version}/dependency-check-{cli_version}-release.zip"
            response = requests.get(url, allow_redirects=True)
            with open(zip_name, "wb") as f:
                f.write(response.content)

            github_api = GithubApi()
            github_api.unzip_file(zip_name, None)
        except Exception as ex:
            logger.error(f"An error ocurred downloading dependency-check {ex}")

    def install_tool(self, cli_version):
        command_prefix = "dependency-check.sh"
        installed = subprocess.run(
            ["which", command_prefix],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            current_route = os.getcwd()
            bin_route = "dependency-check\\bin\\dependency-check.sh"
            command_prefix = os.path.join(current_route, bin_route)

            installed = subprocess.run(
                ["which", command_prefix],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if installed.returncode == 1:
                try:
                    self.download_tool(cli_version)
                    current_route = os.getcwd()
                    bin_route = "dependency-check\\bin\\dependency-check.sh"
                    command_prefix = os.path.join(current_route, bin_route)

                    return command_prefix
                except Exception as e:
                    logger.error(f"Error installing OWASP dependency check: {e}")
            else:
                return command_prefix
        else:
            return command_prefix

    def install_tool_windows(self, cli_version):
        command_prefix = "dependency-check.bat"
        try:
            subprocess.run(
                [command_prefix, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return command_prefix
        except:
            try:
                current_route = os.getcwd()
                bin_route = "dependency-check\\bin\\dependency-check.bat"
                command_prefix = os.path.join(current_route, bin_route)
                subprocess.run(
                    [command_prefix, "--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except:
                try:
                    self.download_tool(cli_version)

                    current_route = os.getcwd()
                    bin_route = "dependency-check\\bin\\dependency-check.bat"
                    command_prefix = os.path.join(current_route, bin_route)

                    return command_prefix
                except Exception as e:
                    logger.error(f"Error installing OWASP dependency check: {e}")

    def scan_dependencies(self, command_prefix, file_to_scan, nvd_api_key, update_nvd):

        try:
            command = [command_prefix, "--scan", file_to_scan, "--noupdate", "--format", "JSON"]

            if update_nvd:
                command = [command_prefix, "--scan", file_to_scan, "--nvdApiKey", nvd_api_key, "--format", "JSON"]

            subprocess.run(command, capture_output=True)
        except subprocess.CalledProcessError as error:
            logger.error(f"Error executing OWASP dependency check scan: {error}")

        return None

    def select_operative_system(self, cli_version, file_to_scan, nvd_api_key, update_nvd):
        os_platform = platform.system()
        command_prefix = None

        if os_platform in ["Linux", "Darwin"]:
            command_prefix = self.install_tool(cli_version)
        elif os_platform == "Windows":
            command_prefix = self.install_tool_windows(cli_version)
        else:
            logger.warning(f"{os_platform} is not supported.")

        self.scan_dependencies(command_prefix, file_to_scan, nvd_api_key, update_nvd)

    def load_results(self):
        try:
            with open('dependency-check-report.json') as f:
                data = json.load(f)
            return data
        except Exception as ex:
            logger.error(f"An error ocurred loading dependency-check results {ex}")
            return None

    def run_tool_dependencies_sca(
            self,
            remote_config,
            file_to_scan,
            bypass_limits_flag,
            token,
    ):

        cli_version = remote_config["DEPENDENCY_CHECK"]["CLI_VERSION"]
        nvd_api_key = remote_config["DEPENDENCY_CHECK"]["NVD_API_KEY"]
        update_nvd = remote_config["DEPENDENCY_CHECK"]["UPDATE_NVD"]

        self.select_operative_system(cli_version, file_to_scan, nvd_api_key, update_nvd)
        data = self.load_results()

        return data
