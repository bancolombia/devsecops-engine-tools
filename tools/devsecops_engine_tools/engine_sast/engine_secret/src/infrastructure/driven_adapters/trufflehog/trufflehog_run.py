import json
import os
import re
import subprocess
import concurrent.futures

from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import (
    GithubApi,
)
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

result = []


class TrufflehogRun(ToolGateway):
    def install_tool(self, agent_os, agent_temp_dir) -> any:
        reg_exp_os = r"Windows"
        check_os = re.search(reg_exp_os, agent_os)
        if check_os:
            self.run_install_win(agent_temp_dir)
        else:
            command = f"trufflehog --version"
            result = subprocess.run(command, capture_output=True, shell=True)
            output = result.stderr.strip()
            reg_exp = r"not found"
            check_tool = re.search(reg_exp, output.decode("utf-8"))
            if check_tool:
                self.run_install()

    def run_install(self):
        command = f"curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
        subprocess.run(command, capture_output=True, shell=True)

    def run_install_win(self, agent_temp_dir):
        command_complete = f"powershell -Command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; [Net.ServicePointManager]::SecurityProtocol; New-Item -Path {agent_temp_dir} -ItemType Directory -Force; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh' -OutFile {agent_temp_dir}\install_trufflehog.sh; bash {agent_temp_dir}\install_trufflehog.sh -b C:/Trufflehog/bin; $env:Path += ';C:/Trufflehog/bin'; C:/Trufflehog/bin/trufflehog.exe --version"
        process = subprocess.Popen(
            command_complete, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        process.communicate()

    def run_tool_secret_scan(
        self,
        files_commits,
        agent_os,
        agent_work_folder,
        repository_name,
        config_tool,
        secret_tool,
        secret_external_checks
    ):
        trufflehog_command = "trufflehog"
        if "Windows" in agent_os:
            trufflehog_command = "C:/Trufflehog/bin/trufflehog.exe"
        with open(f"{agent_work_folder}/excludedPath.txt", "w") as file:
            file.write("\n".join(config_tool.exclude_path))
        exclude_path = f"{agent_work_folder}/excludedPath.txt"
        include_paths = self.config_include_path(files_commits, agent_work_folder)
        enable_custom_rules = config_tool.enable_custom_rules.lower()
        secret = None
        
        if secret_tool is not None:
            secret = secret_tool["github_token"] if "github" in secret_tool else None
        elif secret_external_checks is not None:
            secret = secret_external_checks.split("github:")[1] if "github" in secret_external_checks else None            

        if enable_custom_rules == "true" and secret is not None:
            self.configurate_external_checks(config_tool, secret)
        else: #In case that remote config from tool is enable but in the args dont send any type of secrets. So dont modified command
            enable_custom_rules == "false"

        with concurrent.futures.ThreadPoolExecutor(max_workers=config_tool.number_threads) as executor:
            results = executor.map(
                self.run_trufflehog,
                [trufflehog_command] * len(include_paths),
                [agent_work_folder] * len(include_paths),
                [exclude_path] * len(include_paths),
                include_paths,
                [repository_name] * len(include_paths),
                [enable_custom_rules],
            )
        findings, file_findings = self.create_file(self.decode_output(results), agent_work_folder)
        return  findings, file_findings

    def config_include_path(self, files, agent_work_folder):
        chunks = []
        if len(files) != 0:
            chunk_size = (len(files) + 3) // 4
            chunks = [
                files[i : i + chunk_size] for i in range(0, len(files), chunk_size)
            ]
        include_paths = []
        for i, chunk in enumerate(chunks):
            if not chunk:
                continue
            file_path = f"{agent_work_folder}/includePath{i}.txt"
            include_paths.append(file_path)
            with open(file_path, "w") as file:
                for file_pr_path in chunk:
                    file.write(f"{file_pr_path.strip()}\n")
        return include_paths

    def run_trufflehog(
        self,
        trufflehog_command,
        agent_work_folder,
        exclude_path,
        include_path,
        repository_name,
        enable_custom_rules
    ):
        command = f"{trufflehog_command} filesystem {agent_work_folder + '/' + repository_name} --include-paths {include_path} --exclude-paths {exclude_path} --no-verification --json"

        if enable_custom_rules == "true":
            command = command.replace("--no-verification --json", "--config /tmp/rules/trufflehog/custom-rules.yaml --no-verification --json")

        result = subprocess.run(command, capture_output=True, shell=True, text=True)
        return result.stdout.strip()

    def decode_output(self, results):
        for decode_output in results:
            if decode_output != "":
                object_json = decode_output.strip().split("\n")
                json_list = [json.loads(object) for object in object_json]
                for json_obj in json_list:
                    if json_obj not in result:
                        result.append(json_obj)
        return result
    
    def create_file(self, findings, agent_work_folder):
        file_findings = os.path.join(agent_work_folder, "secret_scan_result.json")
        with open(file_findings, "w") as file:
            for find in findings:
                original_where = str(find.get("SourceMetadata").get("Data").get("Filesystem").get("file"))
                original_where = original_where.replace("\\", "/")
                where_text = original_where.replace(agent_work_folder, "")
                find["SourceMetadata"]["Data"]["Filesystem"]["file"] = where_text
                json_str = json.dumps(find)
                file.write(json_str + '\n')
        return findings, file_findings
    
    def configurate_external_checks(self, config_tool, secret):
        try:
            github_api = GithubApi(secret)
            github_api.download_latest_release_assets(
                config_tool.external_dir_owner,
                config_tool.external_dir_repo,
                "/tmp",
            )
        except Exception as ex:
            logger.error(f"An error ocurred download external checks {ex}")