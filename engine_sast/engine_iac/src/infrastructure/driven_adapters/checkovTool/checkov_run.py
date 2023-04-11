import yaml
import subprocess
from engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import ToolGateway
from engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import CheckovConfig


class CheckovTool(ToolGateway):
    CHECKOV_PACKAGE = "checkov"
    CHECKOV_CONFIG_FILE = "checkov_config.yaml"

    def create_config_file(self, checkov_config: CheckovConfig):
        with open(checkov_config.path_config_file + self.CHECKOV_CONFIG_FILE, "w") as file:
            yaml.dump(checkov_config.dict_confg_file, file)
            file.close()

    def run_tool(self, path_config_file):
        cmd = [
            "checkov",
            "--config-file",
            path_config_file + self.CHECKOV_CONFIG_FILE,
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            shell=True,
        )
        return result.stdout.decode()
