import json
import os
import re
import subprocess
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from devsecops_engine_tools.engine_utilities.utils.utils import Utils
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.utils.utils import Utils

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

class GitleaksTool(ToolGateway):
    COMMAND = None
    
    def install_tool(self, agent_os, agent_temp_dir, tool_version) -> any:
        reg_exp_os = r"Windows"
        is_windows_os = re.search(reg_exp_os, agent_os)
        reg_exp_tool = fr"{tool_version}"

        if is_windows_os:
            file_extension = "windows_x64.zip"
            command = f"{agent_temp_dir}/gitleaks.exe"
        else:
            file_extension = "linux_x64.tar.gz"
            command = f"gitleaks"

        self.COMMAND = command    
        result = subprocess.run(f"{command} --version", capture_output=True, shell=True, text=True)
        is_tool_installed = re.search(reg_exp_tool, result.stdout.strip())

        if is_tool_installed: return

        try:
            url = f"https://github.com/gitleaks/gitleaks/releases/download/v{tool_version}/gitleaks_{tool_version}_{file_extension}"
            response = requests.get(url, allow_redirects=True)
            compressed_name = os.path.join(
                agent_temp_dir, f"gitleaks_{tool_version}_{file_extension}"
            )
            with open(compressed_name, "wb") as f:
                f.write(response.content)

            utils = Utils()
            if is_windows_os:
                utils.unzip_file(compressed_name, agent_temp_dir)
            else:
                utils.extract_targz_file(compressed_name, "/usr/local/bin")

        except Exception as ex:
            logger.error(f"An error ocurred downloading Gitleaks: {ex}")
    
    def extract_json_data(self, file_path):
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            print(f"File {file_path} does not exist")
            return []

    def create_report(self, output_file, combined_data):        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, ensure_ascii=False, indent=4)

    def check_path(self, path, excluded_paths):
        parts = path.split(os.sep)
        for part in parts:
            if part in excluded_paths: return True
        return False
    
    def run_tool_secret_scan(
        self,
        files,
        agent_os,
        agent_work_folder,
        repository_name,
        config_tool,
        secret_tool,  # For external checks
        secret_external_checks,  # For external checks
        agent_temp_dir,
        tool
    ):
        command = [self.COMMAND, "dir"]
        finding_path = os.path.join(agent_work_folder, "gitleaks_report.json")
        excluded_paths = config_tool[tool]["EXCLUDE_PATH"]

        try:
            findings = []
            if len(files) > 1:
                with ThreadPoolExecutor(max_workers=config_tool[tool]["NUMBER_THREADS"]) as executor:
                    futures = []

                    for pull_file in files:
                        if self.check_path(pull_file, excluded_paths): continue
                        
                        aux_finding_path = os.path.join(
                            agent_work_folder, f"gitleaks_aux_report_{pull_file.replace(os.sep, '_')}.json"
                        )
                        
                        command_aux = command.copy()
                        command_aux.extend([
                            os.path.join(agent_work_folder, repository_name, pull_file),
                            "--report-path", aux_finding_path
                        ])

                        if not config_tool[tool]["ALLOW_IGNORE_LEAKS"]: command_aux.append("--ignore-gitleaks-allow")
                        
                        futures.append(executor.submit(self.run_subprocess_command, command_aux, aux_finding_path))

                    for future in as_completed(futures):
                        result = future.result()
                        findings.extend(result)

                self.create_report(finding_path, findings)
            else:
                command.extend([files[0], "--report-path", finding_path])

                if not config_tool[tool]["ALLOW_IGNORE_LEAKS"]:
                    command.append("--ignore-gitleaks-allow")

                subprocess.run(command, capture_output=True, text=True)
                findings = self.extract_json_data(finding_path)

            return findings, finding_path

        except Exception as e:
            print("El error es:", e)
            logger.error(f"Error executing gitleaks scan: {e}")

    def run_subprocess_command(self, command_aux, aux_finding_path):
        try:
            subprocess.run(command_aux, capture_output=True, text=True)
            return self.extract_json_data(aux_finding_path)
        except Exception as e:
            logger.error(f"Error executing gitleaks on {command_aux}: {e}")
            return []