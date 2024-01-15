from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)

import subprocess
import re

from devsecops_engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

class XrayScan(ToolGateway):
    def install_tool(self, version):
        try:
            command = ["command"]
            print(command)
        except subprocess.CalledProcessError as error:
            raise RuntimeError(f"Error al instalar Jfrog Cli: {error}")

    def scan_dependencies(self, remote_config):
        return 0

    def run_tool_dependencies_sca(self, remote_config):
        cli_version = remote_config["JFROG"]["CLI_VERSION"]
        self.install_tool(cli_version)
        return 0