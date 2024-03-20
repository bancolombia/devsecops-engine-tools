import json
import concurrent.futures
import re
import subprocess

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
    def run_tool_secret_scan(self, files_commits, exclude_path, agent_os, agent_work_folder):
        trufflehog_command = "trufflehog"
        reg_exp_os = r'Windows'
        check_os = re.search(reg_exp_os, agent_os)
        if check_os:
            trufflehog_command = "C:/Trufflehog/bin/trufflehog.exe"
        for i in exclude_path:
            command = (
                f'echo {i} >> {agent_work_folder}/excludedPath.txt'
            )
            subprocess.run(command, shell=True, check=True)
        exclude_path = agent_work_folder + "/excludedPath.txt"
        response = self.run_parallel_scans(files_commits, trufflehog_command, exclude_path)
        return response
    def scan_file(self, file_path, trufflehog_command, exclude_path):
        command = f"{trufflehog_command} filesystem {file_path} --json --exclude-paths {exclude_path} --no-verification"
        response_command = subprocess.run(command, capture_output=True, shell=True)
        output = response_command.stdout.decode("utf-8")
        return output
    def run_parallel_scans(self, files_commits, trufflehog_command, exclude_path):
        chunk_size = max(len(files_commits) // 4, 1)
        chunks = [files_commits[i:i+chunk_size] for i in range(0, len(files_commits), chunk_size)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            results = []
            for chunk in chunks:
                futures = [executor.submit(self.scan_file, file_path, trufflehog_command, exclude_path) for file_path in chunk]
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())
        return self.decode_output(results)
    def decode_output(self, results):
        for decode_output in results:
            if decode_output != '':
                object_json = decode_output.strip().split('\n')
                json_list = [json.loads(object) for object in object_json]
                for json_obj in json_list:
                    result.append(json_obj)
        return result