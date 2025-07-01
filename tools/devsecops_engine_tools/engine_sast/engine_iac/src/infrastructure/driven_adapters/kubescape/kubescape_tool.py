import json
import subprocess
import platform
import requests
import distro
import os
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.context_iac import ContextIac
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
        # Sanitize the file path to prevent path traversal attacks
        safe_path = os.path.basename(path_file_results)
        
        with open(safe_path, "r") as file:
            data = json.load(file)

            kubescape_deserealizator = KubescapeDeserealizator()
            extracted_controls = kubescape_deserealizator.extract_failed_controls(data)
            frameworks = data.get("summaryDetails", {}).get("frameworks", [])

            context_iac_list = []
            controls_by_id = {}

            for result in data.get("results", []):
                for ctrl in result.get("controls", []):
                    controls_by_id[ctrl.get("controlID")] = ctrl

            for control in extracted_controls:
                control_id = control.get("id")
                severity = kubescape_deserealizator.get_severity_score(frameworks, control_id)
                resource_ids = []
                fix_key =[]
                full_control = controls_by_id.get(control_id)

                if full_control:
                    for rule in full_control.get("rules", []):
                        for path in rule.get("paths", []):
                            resource_id = path.get("resourceID")
                            if resource_id:
                                resource_ids.append(resource_id)
                            fix_path = path.get("fixPath", {}).get("path")
                            if fix_path:
                                fix_key.append(fix_path)

                context_iac = ContextIac(
                    id=control_id or "unknown",
                    check_class=control_id or "unknown",
                    severity=severity if severity else "unknown",
                    where=control.get("where", "unknown"),
                    fix_key=fix_key if fix_key else ["unknown"],
                    resource=resource_ids if resource_ids else ["unknown"],
                    description=control.get("description", "unknown"),
                    module="engine_iac",
                    tool="Kubescape"
                )
                context_iac_list.append(context_iac)

            print("===== BEGIN CONTEXT OUTPUT =====")
            print(json.dumps({"iac_context": [obj.__dict__ for obj in context_iac_list]}, indent=4))
            print("===== END CONTEXT OUTPUT =====")

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
            # Sanitize filename to prevent path traversal
            safe_filename = os.path.basename(file)
            response = requests.get(url, allow_redirects=True)
            with open(safe_filename, "wb") as binary_file:
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
            # Sanitize filename to prevent path traversal
            safe_json_name = os.path.basename(json_name)
            with open(safe_json_name) as file:
                return json.load(file)
        except FileNotFoundError:
            logger.error(f"The file {safe_json_name} does not exist.")
        except json.JSONDecodeError:
            logger.error("The JSON result is empty.")
        return None
