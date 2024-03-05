import json
import re
import subprocess
import requests
import base64

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
    def run_tool_secret_scan(self,
                            system_working_dir,
                            exclude_path, agent_os,
                            agent_work_folder,
                            access,
                            organization,
                            project_id,
                            repository_name,
                            pr_id):
        reg_exp_os = r'Windows'
        check_os = re.search(reg_exp_os, agent_os)
        if check_os:
            trufflehog_command = "C:/Trufflehog/bin/trufflehog.exe"
        else:
            trufflehog_command = "trufflehog"
        for i in exclude_path:
            command = (
                f'echo {i} >> {agent_work_folder}/excludedPath.txt'
            )
            subprocess.run(command, shell=True, check=True)
        exclude_path = agent_work_folder + "/excludedPath.txt"
        files_commits = []
        files_commits = self.process_pull_request(system_working_dir,
                            access,
                            organization,
                            project_id,
                            repository_name,
                            pr_id)
        response = []
        if len(files_commits) != 0:
            for resultado in files_commits:
                command = (
                    f"{trufflehog_command} filesystem {resultado} --json --exclude-paths {exclude_path} --no-verification"
                )
                res = subprocess.run(command, capture_output=True, shell=True)
                output = res.stdout.decode("utf-8")
                response = self.decode_output(output)
        return response
    def decode_output(self, decode_output):
        if decode_output != '':
            object_json = decode_output.strip().split('\n')
            json_list = [json.loads(objeto) for objeto in object_json]
            for json_obj in json_list:
                result.append(json_obj)
        return result
    def process_pull_request(self, system_working_dir, access, organization, project_id, repository_name, pr_id):
        authorization = f":{access}"
        pr_url = f"{organization}{project_id}/_apis/git/repositories/{repository_name}/pullRequests/{pr_id}/iterations?api-version=6.0"
        auth_coded = base64.b64encode(authorization.encode('utf-8')).decode('utf-8')
        headers = {
            'Authorization': f"Basic {auth_coded}"
        }
        pr_response = requests.get(pr_url, headers=headers)
        results = []
        if pr_response.status_code == 200:
            pr_data = pr_response.json()
            number_commits = pr_data["value"]
            for commit in number_commits:
                num_commit = commit["sourceRefCommit"]["commitId"]
                pr_url_commit = f"{organization}{project_id}/_apis/git/repositories/{repository_name}/commits/{num_commit}/changes?api-version=6.0"
                pr_response_commit = requests.get(pr_url_commit, headers=headers)
                commit_data = pr_response_commit.json()
                commit_data_list = commit_data["changes"]
                self.extract_blob_paths(results, commit_data_list, system_working_dir)
        return results
    def extract_blob_paths(self, blob_paths, commit_data_list, system_working_dir):
        for change in commit_data_list:
            if change["item"]["gitObjectType"] == "blob":
                path_changed = system_working_dir + change["item"]["path"]
                if not path_changed in blob_paths:
                    blob_paths.append(path_changed)
        return blob_paths