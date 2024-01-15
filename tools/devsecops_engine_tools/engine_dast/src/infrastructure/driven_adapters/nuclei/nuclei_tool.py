import os
import subprocess
import json
import platform

from regex import E
from devsecops_engine_tools.engine_core.src.domain.model.input_core import (
    InputCore,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import (
    Exclusions,
)
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
from devsecops_engine_utilities.github.infrastructure.github_api import GithubApi
from devsecops_engine_utilities.ssh.managment_private_key import (
    create_ssh_private_file,
    add_ssh_private_key,
    decode_base64,
    config_knowns_hosts,
)


class NucleiTool(ToolGateway):

    """A class that wraps the nuclei scanner functionality"""

    def __init__(self, target_config=None, data_config_cli=None):
        """Initialize the class with the data from the config file and the cli"""
        self.target_config = target_config
        self.data_config_cli = data_config_cli
        self.TOOL = "NUCLEI"

    def match_target_scan_type(self, target_data):
        if "operations" in target_data:
            return "API"
        else:
            return "AW"

    def search_target_file(self, folder_path):
        
        """Search the target file with the configuration for current scan"""

        scan_taget_type = None # API or AW
        found_files = []
        for path, dirs, files in os.walk(folder_path):
            for file in files:
                found_files.append(os.path.join(path, file))

        if len(found_files) == 0:
            raise(Exception("Error: No targets file found"))
        elif len(found_files) == 1:
            self.match_target_scan_type()

    def process_target_config(self, file_path):
        target_config_data = json.load(file_path)


        

    def configurate_external_checks(self, config_tool: ConfigTool, secret_tool):
        agent_env = None
        try:
            if secret_tool is None:
                print("Secrets manager is not enabled to configure external checks")
            else:
                if (
                    config_tool.use_external_checks_git == "True"
                    and platform.system()
                    in (
                        "Linux",
                        "Darwin",
                    )
                ):
                    config_knowns_hosts(
                        config_tool.repository_ssh_host,
                        config_tool.repository_public_key_fp,
                    )
                    ssh_key_content = decode_base64(
                        secret_tool, "repository_ssh_private_key"
                    )
                    ssh_key_file_path = "/tmp/ssh_key_file"
                    create_ssh_private_file(ssh_key_file_path, ssh_key_content)
                    ssh_key_password = decode_base64(
                        secret_tool, "repository_ssh_password"
                    )
                    agent_env = add_ssh_private_key(ssh_key_file_path, ssh_key_password)

                # Create configuration dir external checks
                if config_tool.use_external_checks_dir == "True":
                    github_api = GithubApi(secret_tool["github_token"])
                    github_api.download_latest_release_assets(
                        config_tool.external_dir_owner,
                        config_tool.external_dir_repository,
                        "/tmp",
                    )

        except Exception as ex:
            print(f"An error ocurred configuring external checks {ex}")
        return agent_env

    def complete_config_tool(
        self, data_file_tool, exclusions, pipeline, devops_platform_gateway, secret_tool
    ):
        config_tool = ConfigTool(json_data=data_file_tool, tool=self.TOOL)

        config_tool.exclusions = exclusions
        config_tool.scope_pipeline = pipeline

        if config_tool.exclusions.get("All") is not None:
            config_tool.exclusions_all = config_tool.exclusions.get("All").get(
                self.TOOL
            )
        if config_tool.exclusions.get(config_tool.scope_pipeline) is not None:
            config_tool.exclusions_scope = config_tool.exclusions.get(
                config_tool.scope_pipeline
            ).get(self.TOOL)

        target_config = self.search_target_file(devops_platform_gateway)

        # Create configuration external checks
        agent_env = self.configurate_external_checks(config_tool, secret_tool)

        return config_tool, agent_env, target_config

    def execute(self, nuclei_config):
        """Interact with nuclei's core application"""

        command = (
            "nuclei "
            + "-duc "  # disable automatic update check
            + "-u "  # target URLs/hosts to scan
            + nuclei_config.url
            + "-ud "  # custom directory to install / update nuclei-templates
            + nuclei_config.templates
            + "-ni "  # disable interactsh server
            + "-dc "  # disable clustering of requests
            + "-je "  # file to export results in JSON format
            + nuclei_config.output_file
            + nuclei_config.authentication
        )

        if command is not None:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
            )
            error = result.stderr.strip()
            if error is not None and error != "":
                print(f"Error executing nuclei: {error}")

        with open(nuclei_config.output_file, "r") as f:
            json_response = json.load(f)
        return json_response

    def run_tool(
        self,
        init_config_tool,
        exclusions,
        environment,
        pipeline,
        devops_platform_gateway,
        secret_tool,
    ):
        config_tool, agent_env = self.complete_config_tool(
            init_config_tool, exclusions, pipeline, devops_platform_gateway, secret_tool
        )

        result_scans = self.execute(config_tool)

        nuclei_deserealizator = NucleiDesealizator()
        findings_list = nuclei_deserealizator.get_list_finding(result_scans)

        totalized_exclusions = []
        totalized_exclusions.extend(
            map(lambda elem: Exclusions(**elem), config_tool.exclusions_all)
        ) if config_tool.exclusions_all is not None else None
        totalized_exclusions.extend(
            map(lambda elem: Exclusions(**elem), config_tool.exclusions_scope)
        ) if config_tool.exclusions_scope is not None else None

        input_core = InputCore(
            totalized_exclusions=totalized_exclusions,
            threshold_defined=config_tool.threshold,
            path_file_results=generate_file_from_tool(
                self.TOOL, result_scans, config_tool.rules_all
            ),
            custom_message_break_build=config_tool.message_info_dast,
            scope_pipeline=config_tool.scope_pipeline,
        )
        return findings_list, input_core
