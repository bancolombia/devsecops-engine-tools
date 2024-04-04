from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

import subprocess
import platform
import requests
import re
import os
import json

from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class XrayScan(ToolGateway):
    def install_tool_linux(self, version):
        installed = subprocess.run(
            ["which", "./jf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            command = ["chmod", "+x", "./jf"]
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-linux-amd64/jf"
                file = "./jf"
                response = requests.get(url, allow_redirects=True)
                with open(file, "wb") as archivo:
                    archivo.write(response.content)
                subprocess.run(
                    command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            except subprocess.CalledProcessError as error:
                logger.error(f"Error during Jfrog Cli installation on Linux: {error}")

    def install_tool_windows(self, version):
        try:
            subprocess.run(
                ["./jf.exe", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-windows-amd64/jf.exe"
                exe_file = "./jf.exe"
                response = requests.get(url, allow_redirects=True)
                with open(exe_file, "wb") as archivo:
                    archivo.write(response.content)
            except subprocess.CalledProcessError as error:
                logger.error(f"Error while Jfrog Cli installation on Windows: {error}")

    def install_tool_darwin(self, version):
        installed = subprocess.run(
            ["which", "./jf"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            command = ["chmod", "+x", "./jf"]
            try:
                url = f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-mac-386/jf"
                file = "./jf"
                response = requests.get(url, allow_redirects=True)
                with open(file, "wb") as archivo:
                    archivo.write(response.content)
                subprocess.run(
                    command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            except subprocess.CalledProcessError as error:
                logger.error(f"Error during Jfrog Cli installation on Darwin: {error}")

    def config_server(self, prefix, token):
        try:
            c_import = [prefix, "c", "im", token]
            result = subprocess.run(
                c_import,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            server_id = re.search(r"'(.*?)'", result.stderr).group(1)
            c_set_server = [prefix, "c", "use", server_id]
            subprocess.run(
                c_set_server,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except subprocess.CalledProcessError as error:
            logger.error(f"Error during Xray Server configuration: {error}")

    def scan_dependencies(self, prefix, target_dir_name, bypass_limits_flag):
        try:
            if bypass_limits_flag:
                command = [
                    prefix,
                    "scan",
                    "--format=json",
                    "--bypass-archive-limits",
                    f"{target_dir_name}/",
                ]
            else:
                command = [prefix, "scan", "--format=json", f"{target_dir_name}/"]
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            scan_result = json.loads(result.stdout)
            file_result = os.path.join(target_dir_name, "scan_result.json")
            with open(file_result, "w") as file:
                json.dump(scan_result, file, indent=4)
            return file_result
        except subprocess.CalledProcessError as error:
            logger.error(f"Error executing jf scan: {error}")

    def run_tool_dependencies_sca(
        self,
        remote_config,
        dir_to_scan_path,
        bypass_limits_flag,
        token,
    ):

        cli_version = remote_config["XRAY"]["CLI_VERSION"]
        os_platform = platform.system()

        if os_platform == "Linux":
            self.install_tool_linux(cli_version)
            command_prefix = "./jf"
        elif os_platform == "Windows":
            self.install_tool_windows(cli_version)
            command_prefix = "./jf.exe"
        elif os_platform == "Darwin":
            command_prefix = "./jf"
            self.install_tool_darwin(cli_version)
        else:
            logger.warning(f"{os_platform} is not supported.")

        self.config_server(command_prefix, token)

        results_file = None
        if len(os.listdir(dir_to_scan_path)) == 0:
            logger.warning("No artifacts found")
        else:
            results_file = self.scan_dependencies(
                command_prefix, dir_to_scan_path, bypass_limits_flag
            )

        return results_file
