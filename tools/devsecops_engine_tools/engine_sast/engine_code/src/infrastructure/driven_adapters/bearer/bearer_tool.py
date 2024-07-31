import subprocess
import os
import re
import yaml
from devsecops_engine_tools.engine_sast.engine_code.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_deserealizator import (
    BearerDeserealizator,
)

class BearerTool(ToolGateway):

    def install_tool(self, agent_work_folder):
        command = f"{agent_work_folder}/bin/bearer version"
        result = subprocess.run(
            command, 
            capture_output=True, 
            shell=True
        )

        output = result.stderr.strip()
        reg_exp = r"not found"
        check_tool = re.search(reg_exp, output.decode("utf-8"))

        if check_tool:
            command = f"curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b {agent_work_folder}/bin"
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )

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
            }
        }
        return data

    def create_config_file(self, agent_work_folder):
        with open(
            f"{agent_work_folder}/bearer.yml",
            "w",
        ) as file:
            yaml.dump(self.config_data(agent_work_folder), file, default_flow_style=False)
            file.close()

    def apply_exclude_path(self, exclude_path, pull_request_file):
        pull_file_list = pull_request_file.split("/")
        for path in exclude_path:
            if path in pull_file_list:
                return True
        return False

    def run_tool(self, folder_to_scan, pull_request_files, agent_work_folder, repository, exclude_path):
        self.install_tool(agent_work_folder)
        self.create_config_file(agent_work_folder)
        findings = []
        if folder_to_scan:
            command = f"{agent_work_folder}/bin/bearer scan {folder_to_scan} --config-file {agent_work_folder}/bearer.yml"
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            findings = BearerDeserealizator.get_list_finding(f"{agent_work_folder}/bearer-scan.json")
        else:
            for pull_file in pull_request_files:
                if self.apply_exclude_path(exclude_path, pull_file): continue
                command = f"{agent_work_folder}/bin/bearer scan {agent_work_folder}/{repository}/{pull_file} --config-file {agent_work_folder}/bearer.yml"
                subprocess.run(
                    command,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True
                )
                findings.extend(BearerDeserealizator.get_list_finding(f"{agent_work_folder}/bearer-scan.json"))
        return findings