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
    _COMMAND = None
    
    def install_tool(self, agent_os, agent_temp_dir, tool_version) -> any:
        is_windows_os = re.search(r"Windows", agent_os)
        is_linux_os = re.search(r"Linux", agent_os)

        if is_windows_os:
            file_extension = "windows_x64.zip"
        elif is_linux_os:
            file_extension = "linux_x64.tar.gz"
        else:
            file_extension = "darwin_x64.tar.gz"
        
        command = f"{agent_temp_dir}{os.sep}gitleaks"
        command = f"{command}.exe" if is_windows_os else command
        
        self._COMMAND = command
        result = subprocess.run(f"{command} --version", capture_output=True, shell=True, text=True)
        is_tool_installed = re.search(fr"{tool_version}", result.stdout.strip())

        if is_tool_installed: return

        try:
            url = f"https://github.com/gitleaks/gitleaks/releases/download/v{tool_version}/gitleaks_{tool_version}_{file_extension}"
            response = requests.get(url, allow_redirects=True)
            compressed_name = os.path.join(
                agent_temp_dir, f"gitleaks_{tool_version}_{file_extension}"
            )
            with open(compressed_name, "wb") as f:
                f.write(response.content)

            if is_windows_os:
                Utils().unzip_file(compressed_name, agent_temp_dir)
            else:
                Utils().extract_targz_file(compressed_name, agent_temp_dir)

        except Exception as ex:
            logger.error(f"An error ocurred downloading Gitleaks: {ex}")
    
    def _extract_json_data(self, file_path):
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            print(f"File {file_path} does not exist")
            return []

    def _create_report(self, output_file, combined_data):        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, ensure_ascii=False, indent=4)

    def _check_path(self, path, excluded_paths):
        parts = path.split(os.sep)
        for part in parts:
            if part in excluded_paths: return True
        return False
    
    def _add_flags(self, config_tool, tool, agent_work_folder):
        flags = []
        if not config_tool[tool]["ALLOW_IGNORE_LEAKS"]:
            flags.append("--ignore-gitleaks-allow")
        
        if config_tool[tool]["ENABLE_CUSTOM_RULES"]:
            flags.extend(["--config", f"{agent_work_folder}{os.sep}rules{os.sep}gitleaks{os.sep}gitleaks.toml"])
        
        return flags

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
        tool,
        folder_path = None
    ):
        command = [self._COMMAND, "dir"]
        finding_path = os.path.join(agent_work_folder, "gitleaks_report.json")
        excluded_paths = config_tool[tool]["EXCLUDE_PATH"]

        if config_tool[tool]["ENABLE_CUSTOM_RULES"]:
            Utils().configurate_external_checks(tool, config_tool, secret_tool, secret_external_checks, agent_work_folder)
            
        try:
            findings = []
            flags = self._add_flags(config_tool, tool, agent_work_folder)
            if len(files) > 1:
                with ThreadPoolExecutor(max_workers=config_tool[tool]["NUMBER_THREADS"]) as executor:
                    futures = []

                    for pull_file in files:
                        if self._check_path(pull_file, excluded_paths): continue
                        
                        aux_finding_path = os.path.join(
                            agent_work_folder, f"gitleaks_aux_report_{pull_file.replace(os.sep, '_')}.json"
                        )
                        
                        command_aux = command.copy()
                        command_aux.extend([
                            os.path.join(agent_work_folder, repository_name, pull_file),
                            "--report-path", aux_finding_path
                        ])
                        command_aux.extend(flags)
                        
                        futures.append(executor.submit(self._run_subprocess_command, command_aux, aux_finding_path))

                    for future in as_completed(futures):
                        result = future.result()
                        findings.extend(result)

                self._create_report(finding_path, findings)
            else:
                command.extend([files[0], "--report-path", finding_path])
                command.extend(flags)

                subprocess.run(command, capture_output=True, text=True)
                findings = self._extract_json_data(finding_path)

            return findings, finding_path

        except Exception as e:
            logger.error(f"Error executing gitleaks scan: {e}")

    def _run_subprocess_command(self, command_aux, aux_finding_path):
        try:
            subprocess.run(command_aux, capture_output=True, text=True)
            return self._extract_json_data(aux_finding_path)
        except Exception as e:
            logger.error(f"Error executing gitleaks on {command_aux}: {e}")
            return []