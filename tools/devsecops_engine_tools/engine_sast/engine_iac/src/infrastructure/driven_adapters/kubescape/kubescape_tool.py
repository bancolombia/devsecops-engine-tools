import json
import subprocess
import platform
import requests
import distro
import os
import time
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_deserealizator import (
    KubescapeDeserealizator,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class KubescapeTool(ToolGateway):

    def download_tool(self, file, url):
        try:
            response = requests.get(url, allow_redirects=True)
            with open(file, "wb") as binary_file:
                binary_file.write(response.content)
        except Exception as e:
            logger.error(f"Error downloading Kubescape: {e}")

    def install_tool(self, file, url):
        installed = subprocess.run(
            ["which", f"./{file}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                self.download_tool(file, url)
                subprocess.run(["chmod", "+x", f"./{file}"])

            except Exception as e:
                logger.error(f"Error installing Kubescape: {e}")

    def install_tool_windows(self, file, url):
        try:
            subprocess.run(
                [f"./{file}", "version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                self.download_tool(file, url)

            except Exception as e:
                logger.error(f"Error installing Kubescape: {e}")

    def execute_kubescape(self, folders_to_scan, prefix, platform_to_scan):
        outputs_json = []
        for folder in folders_to_scan:
            if "k8s" in platform_to_scan:
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                output_filename = f"results_kubescape_{timestamp}.json"
                command = [prefix, "scan", "framework", "nsa", folder, "--format", "json", "--format-version", "v2",
                           "--output", output_filename, "-v"]
                try:
                    subprocess.run(command, capture_output=True)
                    outputs_json.append(output_filename)
                except subprocess.CalledProcessError as e:
                    logger.error(f"Error during Kubescape execution: {e}")
        return outputs_json

    def load_json(self, json_name):
        try:
            with open(json_name) as file:
                return json.load(file)
        except FileNotFoundError:
            logger.error(f"The file {json_name} does not exist.")
        except json.JSONDecodeError:
            logger.error("The JSON result is empty.")
        return None

    def run_tool(self, config_tool: ConfigTool, folders_to_scan, environment, platform_to_scan, secret_tool):

        if folders_to_scan:

            kubescape_version = config_tool.version
            os_platform = platform.system()
            base_url = f"https://github.com/kubescape/kubescape/releases/download/v{kubescape_version}/"

            if os_platform == "Linux":
                distro_name = distro.name()
                if distro_name == "Ubuntu":
                    file = "kubescape-ubuntu-latest"
                    self.install_tool(file, base_url + file)
                    command_prefix = f"./{file}"
                else:
                    logger.warning(f"{distro_name} is not supported.")
                    return None
            elif os_platform == "Windows":
                file = "kubescape-windows-latest.exe"
                self.install_tool_windows(file, base_url + file)
                command_prefix = f"./{file}"
            elif os_platform == "Darwin":
                file = "kubescape-macos-latest"
                self.install_tool(file, base_url + file)
                command_prefix = f"./{file}"
            else:
                logger.warning(f"{os_platform} is not supported.")
                return [], None

            outputs_json = self.execute_kubescape(folders_to_scan, command_prefix, platform_to_scan)

            total_findings = []
            path_json_result = []
            for json_name in outputs_json:

                path = os.path.abspath(json_name)
                path_json_result.append(path)

                data = self.load_json(json_name)

                if not data:
                    return [], None
                else:
                    kubescape_deserealizator = KubescapeDeserealizator()
                    result_extracted_data = kubescape_deserealizator.extract_failed_controls(data)
                    finding_list = kubescape_deserealizator.get_list_finding(result_extracted_data)
                    total_findings.extend(finding_list)

            return total_findings, path_json_result

        else:
            return [], None
