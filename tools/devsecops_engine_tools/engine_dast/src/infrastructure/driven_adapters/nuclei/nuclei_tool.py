import subprocess
import json
import re
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
from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import (
    GithubApi
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class NucleiTool(ToolGateway):

    """A class that wraps the nuclei scanner functionality"""

    def __init__(self, target_config=None, data_config_cli=None):
        """Initialize the class with the data from the config file and the cli"""
        self.target_config = target_config
        self.data_config_cli = data_config_cli
        self.TOOL: str = "NUCLEI"

    def check_install_tool(self) -> any:
        command = "nuclei --version"
        result = subprocess.run(command, capture_output=True, shell=True)
        output = result.stderr.strip()
        reg_exp = r"not found"
        check_tool = re.search(reg_exp, output.decode("utf-8"))
        if check_tool:
            install_result = self.run_install()
            if install_result != 0:
                logger.error(f"{self.TOOL} can't installed")
            return -1
        return 0

    def run_install(self):
        download = subprocess.run(
            "wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.4/nuclei_3.3.4_linux_amd64.zip -O nuclei.zip",
            capture_output=True,
            shell=True
        )
        if download.returncode != 0:
            logger.error(f"Error downloading {self.TOOL} binary")
            return -1

        unzip = subprocess.run(
            "unzip -o nuclei.zip -d /usr/local/bin/",
            capture_output=True,
            shell=True
        )
        if unzip.returncode != 0:
            logger.error(f"Error Unzipping {self.TOOL} binary")
            return -1

        make_exe = subprocess.run(
            "chmod +x /usr/local/bin/nuclei",
            capture_output=True,
            shell=True
        )
        if make_exe.returncode != 0:
            logger.error(f"Error giving execution permissions to {self.TOOL}")
            return -1
        return 0

    def configurate_external_checks(
        self, config_tool: ConfigTool, secret, output_dir: str = "/tmp"
    ):
        if secret is None:
            logger.warning("The secret is not configured for external controls")
        # Create configuration dir external checks
        elif config_tool.use_external_checks_dir == "True":
            github_api = GithubApi(secret["github_token"])
            github_api.download_latest_release_assets(
                config_tool.external_dir_owner,
                config_tool.external_dir_repository,
                output_dir,
            )
            return output_dir + config_tool.external_asset_name
        else:
            return None


    def execute(self, target_config: NucleiConfig) -> dict:
        """Interact with nuclei's core application"""

        command = (
            "nuclei "
            + "-duc "  # disable automatic update check
            + "-u "  # target URLs/hosts to scan
            + target_config.url
            + (f" -ud {target_config.custom_templates_dir}" if target_config.custom_templates_dir else "")
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
            error = result.stderr.decode().strip() if result.stderr else ""
            if result.returncode != 0:
                logger.warning(
                    f"Error executing nuclei: {error}")
        with open(target_config.output_file, "r") as f:
            json_response = json.load(f)
        return json_response

    def run_tool(self, 
        target_data, 
        config_tool,
        secret_tool, 
        secret_external_checks
    ):
        secret = None
        if secret_tool is not None:
            secret = secret_tool
        elif secret_external_checks is not None:
            secret = {
                "github_token": (
                    secret_external_checks.split("github")[1]
                    if "github" in secret_external_checks
                    else None
                )
            }
        if self.check_install_tool() != 0:
            return None
        nuclei_config = NucleiConfig(target_data)
        checks_directory = self.configurate_external_checks(config_tool, secret, "/tmp") #DATA PDN
        if checks_directory:
            nuclei_config.customize_templates(checks_directory)
        result_scans = self.execute(nuclei_config)
        nuclei_deserealizator = NucleiDesealizator()
        findings_list = nuclei_deserealizator.get_list_finding(result_scans)
        return findings_list, nuclei_config.output_file
