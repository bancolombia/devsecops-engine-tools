import os
import subprocess
import json
import platform
import requests
import shutil
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
from devsecops_engine_tools.engine_utilities.utils.utils import Utils

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class NucleiTool(ToolGateway):

    """A class that wraps the nuclei scanner functionality"""

    def __init__(self, target_config=None, data_config_cli=None):
        """Initialize the class with the data from the config file and the cli"""
        self.target_config = target_config
        self.data_config_cli = data_config_cli
        self.TOOL: str = "NUCLEI"

    def download_tool(self, version):
        try:
            base_url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{version}/"
            os_type = platform.system().lower()

            if os_type == "darwin":
                file_name = f"nuclei_{version}_macOS_amd64.zip"
            elif os_type == "linux":
                file_name = f"nuclei_{version}_linux_amd64.zip"
            elif os_type == "windows":
                file_name = f"nuclei_{version}_windows_amd64.zip"
            else:
                logger.error(f"Error [101]: {os_type} is an unsupported OS type!")
                return 101  # Unsupported OS type error

            url = f"{base_url}{file_name}"

            response = requests.get(url, allow_redirects=True)
            if response.status_code != 200:
                logger.error(f"Error [102]: Failed to download Nuclei version {version}. HTTP status code: {response.status_code}")
                return 102  # Download failed error

            home_directory = os.path.expanduser("~")
            zip_name = os.path.join(home_directory, file_name)
            with open(zip_name, "wb") as f:
                f.write(response.content)

            utils = Utils()
            utils.unzip_file(zip_name, home_directory)
            logger.info("Download and extraction completed successfully.")
            return 0  # Success
        except Exception as e:
            logger.error(f"Error [103]: An exception occurred during download: {e}")
            return 103  # General exception error

    def install_tool(self, version):
        try:
            nuclei_path = shutil.which("nuclei")
            if nuclei_path:
                logger.info(f"Success [200]: Nuclei is already installed at {nuclei_path}")
                return 200  # Already installed

            logger.info("Nuclei not found. Downloading and installing...")
            download_result = self.download_tool(version)
            if download_result != 0:
                logger.error(f"Error [104]: Download failed with error code {download_result}")
                return 104  # Download step failed

            os_type = platform.system().lower()
            home_directory = os.path.expanduser("~")

            if os_type == "darwin" or os_type == "linux":
                executable_path = os.path.join(home_directory, "nuclei")
                subprocess.run(["chmod", "+x", executable_path], check=True)
                target_path = os.path.expanduser("~/.local/bin/nuclei")
                shutil.move(executable_path, target_path)
                logger.info(f"Success [201]: Nuclei installed at {target_path}")
                return 201  # Installation successful
            elif os_type == "windows":
                executable_path = os.path.join(home_directory, "nuclei.exe")
                target_path = os.path.join(os.getenv("ProgramFiles"), "nuclei.exe")
                shutil.move(executable_path, target_path)
                logger.info(f"Success [202]: Nuclei installed at {target_path}")
                return 202  # Installation successful (Windows)
            else:
                logger.error(f"Error [105]: {os_type} is an unsupported OS type!")
                return 105  # Unsupported OS type error
        except subprocess.CalledProcessError as e:
            logger.error(f"Error [106]: Command execution failed: {e}")
            return 106  # Subprocess execution error
        except Exception as e:
            logger.error(f"Error [107]: An exception occurred during installation: {e}")
            return 107  # General exception error


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
        if self.install_tool(config_tool.version) < 200:
            return [], None
        nuclei_config = NucleiConfig(target_data)
        checks_directory = self.configurate_external_checks(config_tool, secret, "/tmp") #DATA PDN
        if checks_directory:
            nuclei_config.customize_templates(checks_directory)
        result_scans = self.execute(nuclei_config)
        nuclei_deserealizator = NucleiDesealizator()
        findings_list = nuclei_deserealizator.get_list_finding(result_scans)
        return findings_list, nuclei_config.output_file
