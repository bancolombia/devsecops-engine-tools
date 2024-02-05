import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run import TrufflehogRun

class TestTrufflehogRun(unittest.TestCase):

    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.run')
    def test_install_tool_unix(self, mock_subprocess_run):
        os_patch = patch.dict('os.environ', {'AGENT_OS': 'Linux'})
        os_patch.start()
        self.addCleanup(os_patch.stop)
        # Configuramos un valor de retorno para el subprocess.run
        mock_subprocess_run.return_value.stdout = b'Trufflehog version 1.0.0'
        mock_subprocess_run.return_value.stderr = b''

        trufflehog_run = TrufflehogRun()
        trufflehog_run.install_tool()
        # Aseguramos que subprocess.run fue llamado con el comando esperado
        mock_subprocess_run.assert_called_once_with("trufflehog --version", capture_output=True, shell=True)

    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.os.environ')
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.Popen')
    def test_run_install_win(self, mock_popen, mock_environ):
        # Configuramos el valor de retorno para os.environ
        mock_environ.get.return_value = 'C:/temp'
        
        trufflehog_run = TrufflehogRun()
        trufflehog_run.run_install_win()

        # Aseguramos que subprocess.Popen fue llamado con el comando esperado
        expected_command = (
            "powershell -Command "
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; [Net.ServicePointManager]::SecurityProtocol; " +
            "New-Item -Path C:/temp -ItemType Directory -Force; " +
            "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh' -OutFile C:/temp\\install_trufflehog.sh; " +
            "bash C:/temp\\install_trufflehog.sh -b C:/Trufflehog/bin; " +
            "$env:Path += ';C:/Trufflehog/bin'; C:/Trufflehog/bin/trufflehog.exe --version"
        )
        mock_popen.assert_called_once_with(expected_command, stdout=-1, stderr=-1, shell=True)
        
#     @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.run')
#     def test_run_tool_secret_scan_unix(self, mock_subprocess_run):
#         # Configuramos un valor de retorno para el subprocess.run
#         mock_subprocess_run.return_value.stdout = b'{"vulnerability_data": []}'
#         mock_subprocess_run.return_value.stderr = b''

#         trufflehog_run = TrufflehogRun()
#         trufflehog_run.run_tool_secret_scan('/path/to/repo')

#         # Aseguramos que subprocess.run fue llamado con el comando esperado
#         expected_command = "trufflehog filesystem /path/to/repo --json --exclude-paths /path/to/excludedPath.txt --no-verification"
#         mock_subprocess_run.assert_called_once_with(expected_command, capture_output=True, shell=True)

#     @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.run')
#     def test_run_tool_secret_scan_windows(self, mock_subprocess_run):
#         os_patch = patch.dict('os.environ', {'AGENT_OS': 'Windows'})
#         os_patch.start()
#         self.addCleanup(os_patch.stop)

#         # Configuramos un valor de retorno para el subprocess.run
#         mock_subprocess_run.return_value.stdout = b'{"vulnerability_data": []}'
#         mock_subprocess_run.return_value.stderr = b''

#         trufflehog_run = TrufflehogRun()
#         trufflehog_run.run_tool_secret_scan('C:\\path\\to\\repo')

#         # Aseguramos que subprocess.run fue llamado con el comando esperado
#         expected_command = "C:/Trufflehog/bin/trufflehog.exe filesystem C:\\path\\to\\repo --json --exclude-paths C:\\path\\to\\excludedPath.txt --no-verification"
#         mock_subprocess_run.assert_called_once_with(expected_command, capture_output=True, shell=True)

# if __name__ == '__main__':
#     unittest.main()
