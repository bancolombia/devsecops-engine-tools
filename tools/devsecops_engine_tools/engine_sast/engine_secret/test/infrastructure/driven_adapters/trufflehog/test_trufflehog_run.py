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
        trufflehog_run.install_tool("Linux", "/tmp")
        # Aseguramos que subprocess.run fue llamado con el comando esperado
        mock_subprocess_run.assert_called_once_with("trufflehog --version", capture_output=True, shell=True)
    
    @patch('subprocess.run')
    def test_run_install(self, mock_subprocess_run):
        trufflehog_run = TrufflehogRun()
        trufflehog_run.run_install()
        mock_subprocess_run.assert_called_once_with(
            "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin",
            capture_output=True,
            shell=True
        )

    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.Popen')
    def test_run_install_win(self, mock_popen):
        
        trufflehog_run = TrufflehogRun()
        trufflehog_run.run_install_win("C:/temp")

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

    @patch('subprocess.run')
    def test_run_tool_secret_scan_windows(self, mock_subprocess_run):
        mock_subprocess_run.return_value.stdout = b'{"some": "json"}\n{"another": "json"}'
        trufflehog_run = TrufflehogRun()
        result = trufflehog_run.run_tool_secret_scan("/path/to/system_working_dir", [".git"], "Windows", "C:/", "token", "org", "project", "repo", "pr_id")
        expected_result = [{"some": "json"}, {"another": "json"}]
        self.assertEqual(result, expected_result)
        
    @patch('subprocess.run')
    def test_run_tool_secret_scan_linux(self, mock_subprocess_run):
        mock_subprocess_run.return_value.stdout = b'{"some": "json"}\n{"another": "json"}'
        trufflehog_run = TrufflehogRun()
        result = trufflehog_run.run_tool_secret_scan("/path/to/system_working_dir", [".git"], "Linuz", "/azp/work", "token", "org", "project", "repo", "pr_id")
        expected_result = [{"some": "json"}, {"another": "json"}]
        self.assertEqual(result, expected_result)
    
    # @patch('subprocess.run')
    # def test_run_tool_secret_scan_empty_output(self, mock_subprocess_run):
    #     mock_subprocess_run.return_value.stdout = b''
    #     trufflehog_run = TrufflehogRun()
    #     result = trufflehog_run.run_tool_secret_scan("/path/to/system_working_dir", [".git"], "Linuz", "/azp/work", "token", "org", "project", "repo", "pr_id")
    #     self.assertEqual(result, [])
    
    def test_decode_output(self):
        trufflehog_run = TrufflehogRun()
        output = '{"some": "json"}\n{"another": "json"}'
        result = trufflehog_run.decode_output(output)
        expected_result = [{"some": "json"}, {"another": "json"}]
        self.assertEqual(result, expected_result)
    
    def test_decode_output_empty(self):
        trufflehog_run = TrufflehogRun()
        output = ''
        result = trufflehog_run.decode_output(output)
        self.assertEqual(result, [{'some': 'json'}, {'another': 'json'}])