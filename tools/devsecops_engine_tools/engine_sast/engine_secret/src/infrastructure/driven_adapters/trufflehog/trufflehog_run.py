import json
import os
import re
import subprocess
import concurrent.futures

from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import (
    ToolGateway,
)

from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
from devsecops_engine_tools.engine_utilities.utils.utils import Utils

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()

result = []


class TrufflehogRun(ToolGateway):
    def install_tool(self, agent_os, agent_temp_dir, tool_version) -> any:
        reg_exp_os = r"Windows"
        check_os = re.search(reg_exp_os, agent_os)
        reg_exp_tool = fr"{tool_version}"
        if check_os:
            command = f"{agent_temp_dir}/trufflehog.exe --version"
            subprocess.run(command, shell=True)
            result = subprocess.run(command, capture_output=True, shell=True)
            output = result.stderr.strip()
            check_tool = re.search(reg_exp_tool, output.decode("utf-8"))
            if not check_tool:
                self.run_install_win(agent_temp_dir, tool_version)
                subprocess.run(command, shell=True)
        else:
            command = f"trufflehog --version"
            subprocess.run(command, shell=True)
            result = subprocess.run(command, capture_output=True, shell=True)
            output = result.stderr.strip()
            check_tool = re.search(reg_exp_tool, output.decode("utf-8"))
            if not check_tool:
                self.run_install(tool_version)
                subprocess.run(command, shell=True)

    def run_install(self, tool_version):
        command = f"curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin v{tool_version}"
        subprocess.run(command, capture_output=True, shell=True)

    def run_install_win(self, agent_temp_dir, tool_version):
        command_complete = f"powershell -Command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; [Net.ServicePointManager]::SecurityProtocol; New-Item -Path {agent_temp_dir} -ItemType Directory -Force; Invoke-WebRequest -Uri 'https://github.com/trufflesecurity/trufflehog/releases/download/v{tool_version}/trufflehog_{tool_version}_windows_amd64.tar.gz' -OutFile {agent_temp_dir}/trufflehog.tar.gz -UseBasicParsing; tar -xzf {agent_temp_dir}/trufflehog.tar.gz -C {agent_temp_dir}; Remove-Item {agent_temp_dir}/trufflehog.tar.gz; $env:Path += '; + {agent_temp_dir}'; & {agent_temp_dir}/trufflehog.exe --version"
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
        secret_external_checks,
        agent_temp_dir,
        tool,
        folder_path
    ):
        path = agent_work_folder if folder_path is None else folder_path
        trufflehog_command = "trufflehog"
        if "Windows" in agent_os:
            trufflehog_command = f"{agent_temp_dir}/trufflehog.exe"
        with open(f"{path}/excludedPath.txt", "w") as file:
            file.write("\n".join(config_tool[tool]["EXCLUDE_PATH"]))
        exclude_path = f"{path}/excludedPath.txt"
        include_paths = self.config_include_path(files_commits, path, agent_os, folder_path)
        enable_custom_rules = config_tool[tool]["ENABLE_CUSTOM_RULES"]
        if enable_custom_rules:
            Utils().configurate_external_checks(tool, config_tool, secret_tool, secret_external_checks, path)

        with concurrent.futures.ThreadPoolExecutor(max_workers=config_tool[tool]["NUMBER_THREADS"]) as executor:
            results = executor.map(
                self.run_trufflehog,
                [trufflehog_command] * len(include_paths),
                [path] * len(include_paths),
                [exclude_path] * len(include_paths),
                include_paths,
                [repository_name] * len(include_paths),
                [enable_custom_rules] * len(include_paths),
                [agent_os] * len(include_paths),
                [folder_path] * len(include_paths)
            )
        findings, file_findings = self.create_file(self.decode_output(results), path, config_tool, tool)
        return  findings, file_findings

    def config_include_path(self, files, path, agent_os, folder_path):
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
            file_path = f"{path}/includePath{i}.txt"
            include_paths.append(file_path)
            with open(file_path, "w") as file:
                if folder_path is None:
                    for file_pr_path in chunk:
                        if "Windows" in agent_os:
                            file_pr_path = str(file_pr_path).replace("/","\\\\")
                        file.write(f"{file_pr_path.strip()}\n")
                else:
                    file.write(".\n")
        return include_paths

    def run_trufflehog(
        self,
        trufflehog_command,
        path,
        exclude_path,
        include_path,
        repository_name,
        enable_custom_rules,
        agent_os,
        folder_path
    ):
        path_folder = folder_path if folder_path is not None else f"{path}/{repository_name}"
        command = f"{trufflehog_command} filesystem {path_folder} --include-paths {include_path} --exclude-paths {exclude_path} --no-verification --no-update --json"
        if enable_custom_rules:
            command = command.replace("--no-verification --no-update --json", f"--config {path}//rules//trufflehog//custom-rules.yaml --no-verification --no-update --json" if "Windows" in agent_os else
                                      f"--config {path}/rules/trufflehog/custom-rules.yaml --no-verification --no-update --json" if "Linux" in agent_os else
                                      "--no-verification --no-update --json")
            
        result = subprocess.run(command, capture_output=True, shell=True, text=True, encoding='utf-8')
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
    
    def create_file(self, findings, path, config_tool, tool):
        file_findings = os.path.join(path, "secret_scan_result.json")
        with open(file_findings, "w") as file:
            for find in findings:
                original_where = str(find.get("SourceMetadata").get("Data").get("Filesystem").get("file"))
                original_where = original_where.replace("\\", "/")
                where_text = original_where.replace(path, "")
                find["SourceMetadata"]["Data"]["Filesystem"]["file"] = where_text
                find["Id"] = "MISCONFIGURATION_SCANNING" if "exposure" in find["Raw"] else "SECRET_SCANNING"
                find["References"] = config_tool[tool]["RULES"][find["Id"]]["References"] if "SECRET_SCANNING" not in find["Id"] else "N.A"
                find["Mitigation"] = config_tool[tool]["RULES"][find["Id"]]["Mitigation"] if "SECRET_SCANNING" not in find["Id"] else "N.A"
                json_str = json.dumps(find)
                file.write(json_str + '\n')
        return findings, file_findings