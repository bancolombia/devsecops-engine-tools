import yaml
import subprocess
import os
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import ToolGateway
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkovTool.CheckovConfig import (
    CheckovConfig,
)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageLoggingPipeline
)


class CheckovTool(ToolGateway):
    CHECKOV_PACKAGE = "checkov"
    CHECKOV_CONFIG_FILE = "checkov_config.yaml"

    def __init__(self, checkov_config: CheckovConfig):
        self.checkov_config = checkov_config

    def create_config_file(self):
        with open(
            self.checkov_config.path_config_file + self.checkov_config.config_file_name + self.CHECKOV_CONFIG_FILE, "w"
        ) as file:
            yaml.dump(self.checkov_config.dict_confg_file, file)
            file.close()

    def run_tool(self):
        command = (
            "checkov --config-file "
            + self.checkov_config.path_config_file
            + self.checkov_config.config_file_name
            + self.CHECKOV_CONFIG_FILE
        )
        env_modified = dict(os.environ)
        if self.checkov_config.env is not None:
            env_modified = {**dict(os.environ), **self.checkov_config.env}
        result = subprocess.run(command, capture_output=True, text=True, shell=True, env=env_modified)
        output = result.stdout.strip()
        error = result.stderr.strip()
        if error is not None and error != "":
            print(AzureMessageLoggingPipeline.WarningLogging.get_message(f"Error running checkov.. {error}"))
        return output
