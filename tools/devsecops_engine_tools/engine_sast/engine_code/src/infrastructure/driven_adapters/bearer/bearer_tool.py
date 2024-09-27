import subprocess
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

    BEARER_TOOL = "BEARER"
    MAX_RETRY = 5

    def install_tool(self):        
        command = f"./bearer version"
        result = subprocess.run(
            command, 
            capture_output=True, 
            shell=True
        )

        if result.returncode != 0:
            command = f"curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh -s -- -b ."

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

    def config_data(self, agent_work_folder, excluded_rules):
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
                "skip-rule": excluded_rules
            }
        }
        return data

    def create_config_file(self, agent_work_folder, excluded_rules):
        with open(
            f"{agent_work_folder}/bearer.yml",
            "w",
        ) as file:
            yaml.dump(self.config_data(agent_work_folder, excluded_rules), file, default_flow_style=False)
            file.close()

    def run_tool(self, folder_to_scan, pull_request_files, agent_work_folder, repository, config_tool):
        self.install_tool()

        excluded_rules = config_tool.data[self.BEARER_TOOL]["EXCLUDED_RULES"]
        findings, path_file_results = [], ""
        scan_result_path = f"{agent_work_folder}/bearer-scan.json"

        if folder_to_scan:
            self.create_config_file(agent_work_folder, excluded_rules)
            command = f"./bearer scan {folder_to_scan} --config-file {agent_work_folder}/bearer.yml"
            subprocess.run(
                command,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            findings = BearerDeserealizator.get_list_finding(
                scan_result_path, agent_work_folder
            )
            path_file_results = scan_result_path
        else:
            scan_file_maker = BearerScanFileMaker()
            for pull_file in pull_request_files:
                self.create_config_file(agent_work_folder, excluded_rules)
                command = f"./bearer scan {agent_work_folder}/{repository}/{pull_file} --config-file {agent_work_folder}/bearer.yml"
                subprocess.run(
                    command,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True
                )
                scan_file_maker.add_vulnerabilities(scan_result_path)
                findings.extend(
                    BearerDeserealizator.get_list_finding(
                        scan_result_path, agent_work_folder
                    )
                )

            path_file_results = scan_file_maker.make_scan_file(agent_work_folder)
        return findings, path_file_results