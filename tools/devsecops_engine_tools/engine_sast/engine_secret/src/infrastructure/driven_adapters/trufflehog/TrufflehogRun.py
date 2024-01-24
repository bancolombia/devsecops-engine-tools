import re
import subprocess
import os

from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_gateway import ToolGateway


class TrufflehogRun(ToolGateway):
    def __init__(self, trufflehog_path: str):
        self.trufflehog_path = trufflehog_path
        
    def run_tool(self):
        operative_system = os.environ.get('AGENT_OS')
        reg_exp_os = r'Windows'
        check_os = re.search(reg_exp_os, operative_system)
        if check_os:
            trufflehog_command = "C:/Trufflehog/bin/trufflehog.exe"
        else:
            trufflehog_command = "trufflehog"
        path = os.environ.get('AGENT_WORKFOLDER')
        command = (
            f'echo .git >> {path}/excludedPath.txt'
        )
        subprocess.run(command, shell=True, check=True) 
        
        repository = os.environ.get('SYSTEM_DEFAULTWORKINGDIRECTORY')
        exclude_path = os.environ.get('AGENT_WORKFOLDER') + "/excludedPath.txt"
        command = (
            f"{trufflehog_command} filesystem {repository} --json --exclude-paths {exclude_path} --no-verification"
        )
        result = subprocess.run(command, capture_output=True, shell=True)
        output = result.stdout.decode("utf-8")
        error = result.stderr.strip()
        # print(output)
        # print("ERROR")
        # print(error)
        # TODO revisar el stderr para manejo de excepciones.
        return output