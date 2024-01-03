import re
import subprocess
import os

from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.tool_install_gateway import ToolInstallGateway

class TrufflehogInstall(ToolInstallGateway):
    def __init__(self, trufflehog_path: str):
        self.trufflehog_path = trufflehog_path
    
    def check_tool(self) -> str:
        command = (
            f"trufflehog --version"
        )
        result = subprocess.run(command, capture_output=True, shell=True)
        output = result.stderr.strip()
        print(output)
        reg_exp = r'not found'
        check_tool = re.search(reg_exp, output.decode('utf-8'))
    
        if check_tool:
            output = self.run_install()
        return output
    
    def run_install(self):
        command = (
            f"curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
        )
        print(command)
        result = subprocess.run(command, capture_output=True, shell=True)
        output = result.stdout.strip()
        error = result.stderr.strip()
        print(output + error)
        # TODO revisar el stderr para manejo de excepciones.
        self.check_tool()