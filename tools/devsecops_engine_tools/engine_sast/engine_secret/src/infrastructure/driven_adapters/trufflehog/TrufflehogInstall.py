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
        # self.check_tool()
        
    def run_install_win(self):
        temp = os.environ.get('AGENT_TEMPDIRECTORY')
        command1 = f'Invoke-WebRequest -Uri "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh" -OutFile "{temp}\install_trufflehog.sh"'
        command2 = f'bash {temp}\\install_trufflehog.sh -b C:/Trufflehog/bin'
        command3 = '$env:Path += ";C:/Trufflehog/bin"'

        # Ejecutar los comandos de PowerShell desde Python
        commands = [f'powershell -Command "{cmd}"' for cmd in [command1, command2, command3]]
        for cmd in commands:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            output, error = process.communicate()
            print("Salida:", output.decode("utf-8"))
            print("Errores:", error.decode("utf-8"))