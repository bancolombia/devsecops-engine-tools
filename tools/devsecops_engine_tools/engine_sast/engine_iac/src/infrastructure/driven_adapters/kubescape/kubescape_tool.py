import json
import subprocess
import platform
import requests
import distro
import os
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_deserealizator import (
    KubescapeDeserealizator,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class KubescapeTool(ToolGateway):

    def run_tool(self, config_tool, folders_to_scan, platform_to_scan, **kwargs):

        if folders_to_scan and "k8s" in platform_to_scan:

            kubescape_version = config_tool["KUBESCAPE"]["VERSION"]
            os_platform = platform.system()
            base_url = f"https://github.com/kubescape/kubescape/releases/download/v{kubescape_version}/"
            command_prefix = self._select_operative_system(os_platform, base_url)
            self._execute_kubescape(folders_to_scan, command_prefix)

            json_name = "results_kubescape.json"
            data = self._load_json(json_name)

            if not data:
                return [], None
            else:
                kubescape_deserealizator = KubescapeDeserealizator()
                result_extracted_data = (
                    kubescape_deserealizator.extract_failed_controls(data)
                )
                finding_list = kubescape_deserealizator.get_list_finding(
                    result_extracted_data
                )
                path_results = os.path.abspath(json_name)
            return finding_list, path_results
        else:
            return [], None

    def get_iac_context_from_results(self, path_file_results):
        # TODO: Implement this method
        pass

    def _select_operative_system(self, os_platform, base_url):
        if os_platform == "Linux":
            distro_name = distro.name()
            if distro_name == "Ubuntu":
                file = "kubescape-ubuntu-latest"
                self._install_tool(file, base_url + file)
                return f"./{file}"
            else:
                logger.warning(f"{distro_name} is not supported.")
                return None
        elif os_platform == "Windows":
            file = "kubescape-windows-latest.exe"
            self._install_tool_windows(file, base_url + file)
            return f"./{file}"
        elif os_platform == "Darwin":
            file = "kubescape-macos-latest"
            self._install_tool(file, base_url + file)
            return f"./{file}"
        else:
            logger.warning(f"{os_platform} is not supported.")
            return [], None

    def _install_tool(self, file, url):
        installed = subprocess.run(
            ["which", f"./{file}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                self._download_tool(file, url)
                subprocess.run(["chmod", "+x", f"./{file}"])

            except Exception as e:
                logger.error(f"Error installing Kubescape: {e}")

    def _install_tool_windows(self, file, url):
        try:
            subprocess.run(
                [f"./{file}", "version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                self._download_tool(file, url)

            except Exception as e:
                logger.error(f"Error installing Kubescape: {e}")

    def _download_tool(self, file, url):
        try:
            response = requests.get(url, allow_redirects=True)
            with open(file, "wb") as binary_file:
                binary_file.write(response.content)
        except Exception as e:
            logger.error(f"Error downloading Kubescape: {e}")

    def _execute_kubescape(self, folders_to_scan, prefix):
        command = (
            [prefix, "scan"]
            + folders_to_scan
            + [
                "--format",
                "json",
                "--format-version",
                "v2",
                "--output",
                "results_kubescape.json",
                "-v",
            ]
        )
        try:
            subprocess.run(command, capture_output=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error during Kubescape execution: {e}")

    def _load_json(self, json_name):
        try:
            with open(json_name) as file:
                return json.load(file)
        except FileNotFoundError:
            logger.error(f"The file {json_name} does not exist.")
        except json.JSONDecodeError:
            logger.error("The JSON result is empty.")
        return None
