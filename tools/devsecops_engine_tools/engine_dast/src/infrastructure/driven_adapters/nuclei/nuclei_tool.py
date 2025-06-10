import os
import subprocess
import json
import platform
import requests
import shutil
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_config import (
    NucleiConfig,
)
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_deserealizer import (
    NucleiDesealizator,
)
from devsecops_engine_tools.engine_utilities.utils.utils import Utils
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

    def download_tool(self, version, binary_path):
        try:
            base_url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{version}/"
            os_type = platform.system().lower()

            os_types = {"darwin": "macOS", "linux": "linux", "windows": "windows"}
            if os_type in os_types:
                curr_os = os_types[os_type]
            else:
                raise Exception(f"Error [101]: {os_type} is an unsupported OS type!")

            file_name = f"nuclei_{version}_{curr_os}_amd64.zip"
            url = f"{base_url}{file_name}"

            response = requests.get(url, allow_redirects=True)
            if response.status_code != 200:
                raise Exception(f"Error [102]: Failed to download Nuclei version {version}. HTTP status code: {response.status_code}")

            zip_name = os.path.join(binary_path, file_name)
            with open(zip_name, "wb") as f:
                f.write(response.content)

            Utils().unzip_file(zip_name, binary_path)
            return 0
        except Exception as e:
            logger.error(f"Error [103]: An exception occurred during download: {e}")
            return e

    def install_tool(self, version, binary_path):
        try:
            nuclei_path = shutil.which("nuclei")

            if not nuclei_path:
                download_result = self.download_tool(version, binary_path)
                if download_result != 0:
                    raise Exception(f"Error [104]: Download failed with error: {download_result}")

            os_type = platform.system().lower()

            if nuclei_path:
                executable_path = nuclei_path
            elif os_type == "windows":
                executable_path = os.path.join(binary_path, "nuclei.exe")
            else:
                executable_path = os.path.join(binary_path, "nuclei")

            if os_type == "darwin" or os_type == "linux":
                subprocess.run(["chmod", "+x", executable_path], check=True)
                return {"status": 201, "path": executable_path}  # Installation successful
            elif os_type == "windows":
                return {"status": 202, "path":executable_path}
            else:
                raise Exception(f"Error [105]: {os_type} is an unsupported OS type!")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Error [106]: Command execution failed: {e}")
            return {"status": 106}
        except Exception as e:
            logger.error(f"Error [107]: An exception occurred during installation: {e}")
            return {"status": 107}

    def execute(self, command_prefix: str, target_config: NucleiConfig) -> dict:
        """Interact with nuclei's core application"""

        command = (
            command_prefix
            + " -u "  # target URLs/hosts to scan
            + target_config.url
            + (f" -ud {target_config.custom_templates_dir}" if target_config.custom_templates_dir else "")
            + " -ni "  # disable interactsh server
            + "-dc "  # disable clustering of requests
            + "-sr " # use system DNS resolving as error fallback
            + "-or " #  omit request/response pairs in the output
            + "-tags " # Excute only templates with the especified tag
            + target_config.target_type
            + (f" -c {target_config.concurrency}" if target_config.concurrency else "") # concurrency
            + (f" -rl {target_config.rate_limit}" if target_config.rate_limit else "") # rate limit
            + (f" -rss {target_config.response_size}" if target_config.response_size else "") # max response size to save in bytes
            + (f" -bs {target_config.bulk_size}" if target_config.bulk_size else "") #  max number of hosts to analyze
            + (f" -timeout {target_config.timeout}" if target_config.timeout else "") # timeout for each request
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
                raise Exception(f"Error executing nuclei: {error}")
        with open(target_config.output_file, "r") as f:
            json_response = json.load(f)
        return json_response

    def run_tool(self, 
        target_data, 
        config_tool,
        secret_tool, 
        secret_external_checks,
        agent_work_folder
    ):
        binary_path = agent_work_folder
        if config_tool[self.TOOL].get("BINARY_PATH"):
            binary_path = config_tool[self.TOOL]["BINARY_PATH"]

        result_install = self.install_tool(config_tool[self.TOOL]["VERSION"], binary_path)
        if result_install["status"] < 200:
            return [], None
        
        nuclei_config = NucleiConfig(target_data)
        if config_tool[self.TOOL]["ENABLE_CUSTOM_RULES"]:
            Utils().configurate_external_checks(self.TOOL, config_tool, secret_tool, secret_external_checks, agent_work_folder)
            nuclei_config.customize_templates(agent_work_folder)

        result_scans = self.execute(result_install["path"], nuclei_config)
        findings_list = NucleiDesealizator().get_list_finding(result_scans)
        return findings_list, nuclei_config.output_file
