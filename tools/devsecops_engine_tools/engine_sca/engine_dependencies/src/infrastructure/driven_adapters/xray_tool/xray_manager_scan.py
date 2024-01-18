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

    def config_server(self, prefix, token):
        command = [
            prefix,
            "c",
            "im",
            token
        ]
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if result.returncode == 0:
            server_id = re.search(r"'(.*?)'", result.stderr).group(1)

            print(result.stderr)
        else:
            raise RuntimeError(f"Error al importar artifactory server: {result.stderr}")
        return 0

    def scan_dependencies(self, prefix):
        try:
            command = [
                prefix,
                "scan",
            ]
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        except:
            return 0
        return 0

    def run_tool_dependencies_sca(self, remote_config, token):
        cli_version = remote_config["JFROG"]["CLI_VERSION"]
        os_platform = platform.system()
        if os_platform == "Linux":
            self.install_tool_linux(cli_version)
            command_prefix = "./jf"
        elif os_platform == "Windows":
            self.install_tool_windows(cli_version)
            command_prefix = "./jf.exe"
        self.config_server(command_prefix, token)
        return 0