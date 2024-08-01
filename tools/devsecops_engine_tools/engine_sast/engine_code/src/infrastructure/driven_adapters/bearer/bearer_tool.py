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
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_scan_file_maker import (
    BearerScanFileMaker,
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

    def config_data(self, agent_work_folder, list_skip_rules):
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
            "rule": {
                "skip-rule": list_skip_rules
            }
        }
        return data

    def create_config_file(self, agent_work_folder, list_skip_rules):
        with open(
            f"{agent_work_folder}/bearer.yml",
            "w",
        ) as file:
            yaml.dump(self.config_data(agent_work_folder, list_skip_rules), file, default_flow_style=False)
            file.close()

    def skip_rules_list(self, list_exclusions, pull_file):
        list_skip_rules = []
        for exclusion in list_exclusions:
            if exclusion.where == pull_file or exclusion.where == "all":
                list_skip_rules.append(exclusion.id)
        return list_skip_rules

    def run_tool(self, folder_to_scan, pull_request_files, agent_work_folder, repository, list_exclusions):
        self.install_tool(agent_work_folder)
        findings, path_file_results = [], ""
        scan_result_path = f"{agent_work_folder}/bearer-scan.json"
        if folder_to_scan:
            self.create_config_file(agent_work_folder, [])
            command = f"{agent_work_folder}/bin/bearer scan {folder_to_scan} --config-file {agent_work_folder}/bearer.yml"
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            findings = BearerDeserealizator.get_list_finding(scan_result_path, agent_work_folder)
            path_file_results = scan_result_path
        else:
            scan_file_maker = BearerScanFileMaker()
            for pull_file in pull_request_files:
                self.create_config_file(agent_work_folder, self.skip_rules_list(list_exclusions, pull_file))
                command = f"{agent_work_folder}/bin/bearer scan {agent_work_folder}/{repository}/{pull_file} --config-file {agent_work_folder}/bearer.yml"
                subprocess.run(
                    command,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True
                )
                scan_file_maker.add_vulnerabilities(scan_result_path)
                findings.extend(BearerDeserealizator.get_list_finding(scan_result_path, agent_work_folder))
            path_file_results = scan_file_maker.make_scan_file(agent_work_folder)
        return findings, path_file_results