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
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.target_config import (
    TargetConfig,
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
        self.debug = os.environ.get("DEBUG", "false")

    def match_target_scan_type(self, target_data):
        if "operations" in target_data:
            return "API"
        else:
            return "AW"

    def read_target_config(self, file_path):
        with open(file_path, "r") as f:
            data = json.load(f)
        return data

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
                    return "/tmp/nuclei-templates"

        except Exception as ex:
            print(f"An error ocurred configuring external checks {ex}")
        return "tmp/nuclei-templates" #BORRAR

    def complete_config_tool(
        self, 
        data_file_tool, 
        exclusions, 
        pipeline, 
        target_file_path, 
        secret_tool
    ) -> (ConfigTool, TargetConfig):
        
        config_tool = ConfigTool(
            json_data=data_file_tool, 
            tool=self.TOOL,
        )

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

        data_target_config = self.read_target_config(target_file_path) #configuration for the current target
        target_config = TargetConfig(data_target_config) #create a nuclei config object
        templates_directory = self.configurate_external_checks(config_tool, secret_tool)
        target_config.customize_templates(templates_directory) # update templates directory if needed
        # Create configuration external checks
        


        return config_tool, target_config

    def execute(self, target_config: TargetConfig) -> dict:
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
            + "-je "  # file to export results in JSON format
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

    def run_tool(
        self,
        init_config_tool,
        target_file_path,
        exclusions,
        environment,
        pipeline,
        secret_tool,
    ):
        config_tool, target_config = self.complete_config_tool(
            init_config_tool, exclusions, pipeline, target_file_path, secret_tool
        )

        result_scans = self.execute(target_config)

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
            stage_pipeline="Release",
        )
        return findings_list, input_core
