import json
import subprocess
import platform
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
    generate_file_from_tool,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


class KubescapeTool(ToolGateway):
    TOOL = "KUBESCAPE"

    def install_tool_linux(self, version):
        command = f"curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash -s -- -v v{version}"
        result = subprocess.run(command, capture_output=True, shell=True, text=True)
        if result.returncode != 0:
            logger.error(f"Error during Kubescape installation on Linux: {result.stderr}")

    def install_tool_windows(self):
        command = "powershell -Command \"iwr -useb https://raw.githubusercontent.com/kubescape/kubescape/master/install.ps1 | iex\""
        result = subprocess.run(command, capture_output=True, shell=True, text=True)
        if result.returncode != 0:
            logger.error(f"Error during Kubescape installation on Windows: {result.stderr}")

    def execute_kubescape(self, folders_to_scan):
        for folder in folders_to_scan:
            command = f"kubescape scan framework nsa {folder} --format json --format-version v2 --output results_kubescape.json -v"
            try:
                subprocess.run(command, capture_output=True, shell=True)
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
        if not folders_to_scan:
            return [], None

        version = config_tool.version
        os_platform = platform.system()

        if os_platform == "Linux":
            self.install_tool_linux(version)
        elif os_platform == "Windows":
            self.install_tool_windows()
        else:
            logger.warning(f"{os_platform} is not supported.")
            return [], None

        self.execute_kubescape(folders_to_scan)
        data = self.load_json()

        if not data:
            return [], None

        result_extracted_data = self.extract_failed_controls(data)
        kubescape_deserealizator = KubescapeDeserealizator()
        finding_list = kubescape_deserealizator.get_list_finding(result_extracted_data)
        path_file_results = generate_file_from_tool(self.TOOL, data, config_tool.rules_all)

        return finding_list, path_file_results
