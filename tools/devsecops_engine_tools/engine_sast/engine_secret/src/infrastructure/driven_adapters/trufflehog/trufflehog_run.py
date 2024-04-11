import json
import re
import subprocess
import concurrent.futures

from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import ToolGateway
result = []
class TrufflehogRun(ToolGateway):
    def install_tool(self, agent_os, agent_temp_dir) -> any:
        reg_exp_os = r'Windows'
        check_os = re.search(reg_exp_os, agent_os)
        if check_os:
            self.run_install_win(agent_temp_dir)
        else:
            command = (
                f"trufflehog --version"
            )
            result = subprocess.run(command, capture_output=True, shell=True)
            output = result.stderr.strip()
            reg_exp = r'not found'
            check_tool = re.search(reg_exp, output.decode('utf-8'))
            if check_tool:
                self.run_install()
    def run_install(self):
        command = (
            f"curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
        )
        subprocess.run(command, capture_output=True, shell=True)
    def run_install_win(self, agent_temp_dir):
        command_complete = f"powershell -Command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; [Net.ServicePointManager]::SecurityProtocol; New-Item -Path {agent_temp_dir} -ItemType Directory -Force; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh' -OutFile {agent_temp_dir}\install_trufflehog.sh; bash {agent_temp_dir}\install_trufflehog.sh -b C:/Trufflehog/bin; $env:Path += ';C:/Trufflehog/bin'; C:/Trufflehog/bin/trufflehog.exe --version"
        process = subprocess.Popen(command_complete, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        process.communicate()
    def run_tool_secret_scan(self, files_commits, exclude_paths, agent_os, agent_work_folder, sys_working_dir, num_threads):
        trufflehog_command = "trufflehog"
        if "Windows" in agent_os:
            trufflehog_command = "C:/Trufflehog/bin/trufflehog.exe"
        with open(f"{agent_work_folder}/excludedPath.txt", "w") as file:
            file.write('\n'.join(exclude_paths))
        exclude_path = f"{agent_work_folder}/excludedPath.txt"
        include_paths = self.config_include_path(files_commits, agent_work_folder)
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            results = executor.map(self.run_trufflehog, [trufflehog_command]*len(include_paths), [sys_working_dir]*len(include_paths), [exclude_path]* len(include_paths), include_paths)
        return self.decode_output(results)
    def config_include_path(self, files, agent_work_folder):
        chunks = []
        if len(files) != 0:
            chunk_size = (len(files) + 3) // 4
            chunks = [files[i:i + chunk_size] for i in range(0, len(files), chunk_size)]
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
    def run_trufflehog(self, trufflehog_command, sys_working_dir, exclude_path, include_path):
        command = f"{trufflehog_command} filesystem {sys_working_dir} --include-paths {include_path} --exclude-paths {exclude_path} --no-verification --json"
        result = subprocess.run(command, capture_output=True, shell=True, text=True)
        return result.stdout.strip()
    def decode_output(self, results):
        for decode_output in results:
            if decode_output != '':
                object_json = decode_output.strip().split('\n')
                json_list = [json.loads(object) for object in object_json]
                for json_obj in json_list:
                    result.append(json_obj)
        return result