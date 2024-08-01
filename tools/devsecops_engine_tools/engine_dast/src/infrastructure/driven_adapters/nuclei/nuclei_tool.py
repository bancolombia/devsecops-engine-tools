import os
import subprocess
import json
from devsecops_engine_tools.engine_dast.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_config import (
    NucleiConfig,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_deserealizer import (
    NucleiDesealizator,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.helpers.file_generator_tool import (
    generate_file_from_tool,
)
from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import (
    GithubApi
)


class NucleiTool(ToolGateway):

    """A class that wraps the nuclei scanner functionality"""

    def __init__(self, target_config=None, data_config_cli=None):
        """Initialize the class with the data from the config file and the cli"""
        self.target_config = target_config
        self.data_config_cli = data_config_cli
        self.TOOL: str = "NUCLEI"
        self.debug: str = os.environ.get("DEBUG", "false")

    def configurate_external_checks(
        self, config_tool: ConfigTool, github_token: str, output_dir: str = "tmp"
    ):
        # Create configuration dir external checks
        if config_tool.use_external_checks_dir == "True":
            github_api = GithubApi(github_token)
            github_api.download_latest_release_assets(
                config_tool.external_dir_owner,
                config_tool.external_dir_repository,
                output_dir,
            )
            return output_dir + config_tool.external_checks_save_path

    def execute(self, target_config: NucleiConfig) -> dict:
        """Interact with nuclei's core application"""

        command = (
            "nuclei "
            + "-duc "  # disable automatic update check
            + "-u "  # target URLs/hosts to scan
            + target_config.url
            + " -ud "  # custom directory to install / update nuclei-templates
            + target_config.custom_templates_dir
            + " -ni "  # disable interactsh server
            + "-dc "  # disable clustering of requests
            + "-tags " # Excute only templates with the especified tag
            + target_config.target_type
            + " -je "  # file to export results in JSON format
            + str(target_config.output_file)
        )

        if command is not None:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
            )
            error = result.stderr
            if (error is not None and error != "") and self.debug == "true":
                error = error.strip()
                print(f"Error executing nuclei: {error}")

        with open(target_config.output_file, "r") as f:
            json_response = json.load(f)
        return json_response

    def run_tool(self, target_data, config_tool, token):
        nuclei_config = NucleiConfig(target_data)
        checks_directory = self.configurate_external_checks(config_tool, token, ".") #DATA PDN
        nuclei_config.customize_templates(checks_directory)
        result_scans = self.execute(nuclei_config)
        nuclei_deserealizator = NucleiDesealizator()
        findings_list = nuclei_deserealizator.get_list_finding(result_scans)
        path_file_results = generate_file_from_tool(
            self.TOOL, result_scans, config_tool
        )
        return findings_list, path_file_results
