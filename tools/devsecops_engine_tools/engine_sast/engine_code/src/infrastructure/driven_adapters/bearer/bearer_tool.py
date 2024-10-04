import subprocess
import yaml
import shutil
import os
import json
import concurrent.futures
from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_deserealizator import (
    BearerDeserealizator,
)

class BearerTool(ToolGateway):

    BEARER_TOOL = "BEARER"
    MAX_RETRY = 5

    def install_tool(self):        
        command = f"bearer version"
        result = subprocess.run(
            command, 
            capture_output=True, 
            shell=True
        )

        if result.returncode != 0:
            command = f"curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b /usr/local/bin"

            for num_try in range(self.MAX_RETRY):
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True
                )

                if result.returncode == 0: break
                if num_try == self.MAX_RETRY - 1: 
                    raise Exception(f"Error installing Bearer tool.")

    def config_data(self, agent_work_folder):
        data = {
            "report": {
                "output": f"{agent_work_folder}/bearer-scan.json",
                "format": "json",
                "report": "security",
                "severity": "critical,high,medium,low"
            },
            "scan": {
                "disable-domain-resolution": True,
                "domain-resolution-timeout": "3s",
                "exit-code": 0,
                "scanner": ["sast"]
            },
        }
        return data

    def create_config_file(self, agent_work_folder):
        with open(
            f"{agent_work_folder}/bearer.yml",
            "w",
        ) as file:
            yaml.dump(self.config_data(agent_work_folder), file, default_flow_style=False)
            file.close()

    def copy_file(self, pull_file, agent_work_folder, repository, path_to_scan):
        path = f"{agent_work_folder}/{repository}/{pull_file}"
        destination_path = os.path.join(path_to_scan, f"{repository}/{pull_file}")
        os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        shutil.copy2(path, destination_path)

    def scan_path(self, path, agent_work_folder):
        command = f"bearer scan {path} --config-file {agent_work_folder}/bearer.yml"
        subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True
        )
        findings = BearerDeserealizator.get_list_finding(
            f"{agent_work_folder}/bearer-scan.json", agent_work_folder
        )

        return findings

    def format_scan_file(self, scan_result_path, agent_work_folder):
        with open(scan_result_path, encoding='utf-8') as arc:
            try:
                data = json.load(arc)
                severity = list(data.keys())
                for sev in severity:
                    for vul in data[sev]:
                        if "snippet" not in vul.keys(): vul["snippet"] = ""
            except:
                data = {}

        with open(f"{agent_work_folder}/bearer-scan-vul-man.json", "w") as file:
            json.dump(data, file)
            file.close()
        return f"{agent_work_folder}/bearer-scan-vul-man.json"

    def run_tool(self, folder_to_scan, pull_request_files, agent_work_folder, repository, config_tool):
        self.install_tool()

        number_threads = config_tool.data[self.BEARER_TOOL]["NUMBER_THREADS"]
        scan_result_path = f"{agent_work_folder}/bearer-scan.json"
        self.create_config_file(agent_work_folder)

        if folder_to_scan:
            path_to_scan = folder_to_scan
        else:
            path_to_scan = f"{agent_work_folder}/copy_files_bearer"
            os.makedirs(path_to_scan, exist_ok=True)
            with concurrent.futures.ThreadPoolExecutor(max_workers=number_threads) as executor:
                futures = [
                    executor.submit(self.copy_file, pull_file, agent_work_folder, repository, path_to_scan)
                    for pull_file in pull_request_files
                ]
                for future in futures: future.result() 

        findings = self.scan_path(path_to_scan, agent_work_folder)
        scan_result_path_formatted = self.format_scan_file(scan_result_path, agent_work_folder)

        return findings, scan_result_path_formatted