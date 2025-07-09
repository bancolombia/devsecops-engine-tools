import json
import subprocess
import platform
import requests
import distro
import os
import shlex

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
           
            if not command_prefix:
                logger.error("Could not determine command prefix for Kubescape. Aborting scan.")
                return [], None
           
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
        safe_path = self._get_safe_path(path_file_results)
        if not safe_path:
            return
        
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

    def _get_safe_path(self, filename):
        """
        Resolves a filename to an absolute path and ensures it is within the current working directory.
        This prevents path traversal attacks.
        """
        if not filename or not isinstance(filename, str):
            logger.error("Invalid filename provided for sanitization.")
            return None

        # Prevent null byte injection
        if '\x00' in filename:
            logger.error("Filename contains null bytes.")
            return None

        # Get the absolute path of the intended file
        abs_path = os.path.abspath(os.path.join(os.getcwd(), os.path.basename(filename)))

        # Verify the path is within the current working directory
        if os.path.commonpath([abs_path, os.getcwd()]) != os.getcwd():
            logger.error(f"Path traversal attempt detected and blocked for: {filename}")
            return None

        return abs_path

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
        safe_path = self._get_safe_path(file)
        if not safe_path:
            return
        
        installed = subprocess.run(
            ["which", safe_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if installed.returncode == 1:
            try:
                self._download_tool(safe_path , url)
                subprocess.run(["chmod", "+x", safe_path], check=True)

            except Exception as e:
                logger.error(f"Error installing Kubescape: {e}")

    def _install_tool_windows(self, file, url):
        safe_path = self._get_safe_path(file)
        if not safe_path:
            return
        
        try:
            subprocess.run(
                [f"./{safe_path }", "version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except:
            try:
                self._download_tool(safe_path , url)

            except Exception as e:
                logger.error(f"Error installing Kubescape: {e}")

    def _download_tool(self, file_path, url):
        try:
            response = requests.get(url, allow_redirects=True)
            response.raise_for_status()

            with open(file_path, "wb") as binary_file:
                binary_file.write(response.content)
        except Exception as e:
            logger.error(f"Error downloading Kubescape: {e}")

    def _execute_kubescape(self, folders_to_scan, prefix):
        sanitized_folders = []
        for folder in folders_to_scan:
            # Sanitize each folder to prevent path traversal or command injection.
            # os.path.normpath will help resolve any redundant separators or `.` parts.
            # We also check if the path is absolute, and ensure it's within the current working directory.
            safe_folder = os.path.normpath(folder)
            if os.path.isabs(safe_folder):
                if not safe_folder.startswith(os.getcwd()):
                    logger.warning(f"Skipping folder outside of workspace: {folder}")
                    continue
            
            if safe_folder.startswith(('..', '/')):
                 logger.warning(f"Skipping potentially malicious folder path: {folder}")
                 continue

            sanitized_folders.append(safe_folder)

        if not sanitized_folders:
            logger.warning("No valid folders to scan after sanitization.")
            return

        command = (
            [prefix, "scan", *sanitized_folders,
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
            subprocess.run(command, capture_output=True,check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error during Kubescape execution: {e}")

    def _load_json(self, json_path):
        try:
            with open(json_path) as file:
                return json.load(file)
        except FileNotFoundError:
            logger.error(f"The file {json_path} does not exist.")
        except json.JSONDecodeError:
            logger.error("The JSON result is empty.")
        return None
