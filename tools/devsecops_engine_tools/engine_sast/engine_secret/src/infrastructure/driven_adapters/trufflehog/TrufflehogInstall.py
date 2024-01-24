import re
import subprocess
import os

from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_install_gateway import ToolInstallGateway

class TrufflehogInstall(ToolInstallGateway):
    def __init__(self, trufflehog_path: str):
        self.trufflehog_path = trufflehog_path
    
    def check_tool(self) -> str:
        operative_system = os.environ.get('AGENT_OS')
        reg_exp_os = r'Windows'
        check_os = re.search(reg_exp_os, operative_system)
        if check_os:
            self.run_install_win()
        else:
            command = (
                f"trufflehog --version"
            )
            result = subprocess.run(command, capture_output=True, shell=True)
            output = result.stderr.strip()
            reg_exp = r'not found'
            check_tool = re.search(reg_exp, output.decode('utf-8'))
        
            if check_tool:
                output = self.run_install()
    
    def run_install(self):
        command = (
            f"curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
        )
        result = subprocess.run(command, capture_output=True, shell=True)
        output = result.stdout.strip()
        error = result.stderr.strip()
        # TODO revisar el stderr para manejo de excepciones.
        # self.check_tool()
        
    def run_install_win(self):
        temp = os.environ.get('AGENT_TEMPDIRECTORY')
        
        commandComplete = f"powershell -Command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; [Net.ServicePointManager]::SecurityProtocol; New-Item -Path {temp} -ItemType Directory -Force; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh' -OutFile {temp}\install_trufflehog.sh; bash {temp}\install_trufflehog.sh -b C:/Trufflehog/bin; $env:Path += ';C:/Trufflehog/bin'; C:/Trufflehog/bin/trufflehog.exe --version"

        process = subprocess.Popen(commandComplete, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        process.communicate()

   