import json
import subprocess
import platform
import requests
import distro
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_deserealizator import (
    KubescapeDeserealizator,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.helpers.file_generator_tool import (
    generate_file_from_kubescape,
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

    def execute_kubescape(self, folders_to_scan, prefix):
        for folder in folders_to_scan:
            command = [prefix, "scan", "framework", "nsa", folder, "--format", "json", "--format-version", "v2", "--output", "results_kubescape.json", "-v"]
            try:
                subprocess.run(command, capture_output=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Error during Kubescape execution: {e}")

    def load_json(self):
        try:
            with open("results_kubescape.json") as file:
                return json.load(file)
        except FileNotFoundError:
            logger.error("The file results_kubescape.json does not exist.")
        except json.JSONDecodeError:
            logger.error("The JSON result is empty.")
        return None

    def extract_failed_controls(self, data):
        result_extracted_data = []
        results = data.get("results", [])
        resources = {resource.get("resourceID"): resource for resource in data.get("resources", [])}
        frameworks = data.get("summaryDetails", {}).get("frameworks", [])

        for result in results:
            resource_id = result.get("resourceID")
            controls = result.get("controls", [])

            for control in controls:
                if control.get("status", {}).get("status") == "failed":
                    control_id = control.get("controlID")
                    name = control.get("name")
                    resource = resources.get(resource_id)

                    if resource:
                        relative_path = resource.get("source", {}).get("relativePath", "").replace("\\", "/")
                        severity_score = self.get_severity_score(frameworks, control_id)

                        result_extracted_data.append({
                            "id": control_id,
                            "description": name,
                            "where": relative_path,
                            "severity": severity_score
                        })

        return result_extracted_data

    def get_severity_score(self, frameworks, control_id):
        classifications = {
            (0.0, 0.0): "none",
            (0.1, 3.9): "low",
            (4.0, 6.9): "medium",
            (7.0, 8.9): "high",
            (9.0, 10.0): "critical"
        }
        for framework in frameworks:
            control_object = framework.get("controls", {}).get(control_id, {})
            if control_object:
                for range_tuple, classification in classifications.items():
                    if range_tuple[0] <= control_object.get("scoreFactor", 0.0) <= range_tuple[1]:
                        return classification
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
                command_prefix = "./kubescape-windows-latest"
            else:
                logger.warning(f"{os_platform} is not supported.")
                return None

            self.execute_kubescape(folders_to_scan, command_prefix)
            data = self.load_json()

            if not data:
                return [], None
            else:
                result_extracted_data = self.extract_failed_controls(data)
                kubescape_deserealizator = KubescapeDeserealizator()
                finding_list = kubescape_deserealizator.get_list_finding(result_extracted_data)
                path_file_results = generate_file_from_kubescape(data)

                return finding_list, path_file_results

        else:
            return [], None
