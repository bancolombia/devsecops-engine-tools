import unittest
from unittest.mock import patch, MagicMock

import pytest
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
    
    def test_decode_output(self):
        trufflehog_run = TrufflehogRun()
        output = '{"some": "json"}\n{"another": "json"}'
        result = trufflehog_run.decode_output(output)
        expected_result = [{"some": "json"}, {"another": "json"}]
        self.assertEqual(result, expected_result)

    @patch('subprocess.run')
    @patch('requests.get')
    def test_run_tool_secret_scan_windows(self, mock_subprocess_run, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"value": []}
        mock_get.return_value = mock_response
        mock_subprocess_run.return_value.stdout = b'{"some": "json"}\n{"another": "json"}'
        trufflehog_run = TrufflehogRun()
        result = trufflehog_run.run_tool_secret_scan("/path/to/system_working_dir", [".git"], "Windows", "C:/", "access_token", "https://organization","project_id","repository_name","pr_id")
        expected_result = []
        self.assertEqual(result, expected_result)
    
    @patch('subprocess.run')
    @patch('requests.get')
    def test_run_tool_secret_scan_linux(self, mock_subprocess_run, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"value": []}
        mock_get.return_value = mock_response
        mock_subprocess_run.return_value.stdout = b'{"some": "json"}\n{"another": "json"}'
        trufflehog_run = TrufflehogRun()
        result = trufflehog_run.run_tool_secret_scan("/path/to/system_working_dir", [".git"], "Linuz", "/azp/work", "access_token", "https://organization","project_id","repository_name","pr_id")
        expected_result = []
        self.assertEqual(result, expected_result)
    
    @patch('subprocess.run')
    @patch('requests.get')
    def test_run_tool_secret_scan_with_result(self,mock_subprocess_run,  mock_get):
        mock_pr_response = MagicMock()
        mock_pr_response.status_code = 200
        mock_pr_response.json.return_value = {
            "value": [{"sourceRefCommit": {"commitId": "commit_id_1"}}]
        }
        mock_get.side_effect = [mock_pr_response]

        mock_commit_response = MagicMock()
        mock_commit_response.status_code = 200
        mock_commit_response.json.return_value = {
            "changes": [{"item": {"gitObjectType": "blob", "path": "file1.py"}}]
        }

        trufflehog_run = TrufflehogRun()
        with patch.object(TrufflehogRun, 'decode_output') as mock_decode_output:
            mock_decode_output.return_value = [{"secret": "value"}]

            resultado = trufflehog_run.run_tool_secret_scan(
                "/path/to/working/dir",
                ["exclude_path"],
                "Linux",
                "/agent/work/folder",
                "access_token",
                "organization",
                "project_id",
                "repository_name",
                "pr_id"  # Asegúrate de proporcionar el pr_id aquí
            )
            assert resultado == []
            
    def test_extract_blob_paths(self):
        blob_paths = []
        commit_data_list = [{"item": {"gitObjectType": "blob", "path": "file1.py"}}]
        system_working_dir = '/path/to/working/dir/'
        trufflehog_run = TrufflehogRun()
        trufflehog_run.extract_blob_paths(blob_paths, commit_data_list, system_working_dir)
        
        assert blob_paths == ['/path/to/working/dir/file1.py']
        
    @patch('requests.get')
    @patch('requests.get')
    def test_process_pull_request(self, mock_requests_get, mock_requests_get2):
        mock_pr_response = MagicMock()
        mock_pr_response.status_code = 200
        mock_pr_response.json.return_value = {"value": [{"sourceRefCommit": {"commitId": "commit_id_1"}}]}
        mock_requests_get.return_value = mock_pr_response

        trufflehog_run = TrufflehogRun()
        trufflehog_run.extract_blob_paths = MagicMock(return_value=['/path/to/working/dir/file1.py'])

        system_working_dir = '/path/to/working/dir'
        access = 'access_token'
        organization = 'organization'
        project_id = 'project_id'
        repository_name = 'repository_name'
        pr_id = 'pr_id'

        result = trufflehog_run.process_pull_request(system_working_dir, access, organization, project_id, repository_name, pr_id)
        
        assert result == []