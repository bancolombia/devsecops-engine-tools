from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

import subprocess
import platform
import requests
import re

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
            command1 = [
                "wget",
                f"https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-linux-amd64/jf"
            ]
            command2 = [
                "chmod",
                "+x",
                "./jf"
            ]
            try:
                subprocess.run(
                        command1, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
                subprocess.run(
                        command2, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                    )
            except subprocess.CalledProcessError as error:
                raise RuntimeError(f"Error al instalar Jfrog Cli en Linux: {error}")
        

    def install_tool_windows(self, version):
        try:
            subprocess.run(
                ["./jf.exe", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                url = f'https://releases.jfrog.io/artifactory/jfrog-cli/v2-jf/{version}/jfrog-cli-windows-amd64/jf.exe'
                exe_file = './jf.exe'
                response = requests.get(url, allow_redirects=True)
                with open(exe_file, 'wb') as archivo:
                    archivo.write(response.content)
            except subprocess.CalledProcessError as error:
                raise RuntimeError(f"Error al instalar Jfrog Cli en Windows: {error}")

    def scan_dependencies(self, prefix):
        return 0

    def run_tool_dependencies_sca(self, remote_config):
        cli_version = remote_config["JFROG"]["CLI_VERSION"]
        os_platform = platform.system()
        if os_platform == "Linux":
            self.install_tool_linux(cli_version)
            command_prefix = "./jf"
        elif os_platform == "Windows":
            self.install_tool_windows(cli_version)
            command_prefix = "./jf.exe"
        result_file = self.scan_dependencies(command_prefix)
        return result_file