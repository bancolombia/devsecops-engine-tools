import json
import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.DeserializeConfigTool import DeserializeConfigTool
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run import TrufflehogRun

import os

class TestTrufflehogRun(unittest.TestCase):
       
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.run')
    def test_install_tool_unix(self, mock_subprocess_run):
        os_patch = patch.dict('os.environ', {'AGENT_OS': 'Linux'})
        os_patch.start()
        self.addCleanup(os_patch.stop)

        mock_subprocess_run.return_value.stdout = b'Trufflehog version 1.0.0'
        mock_subprocess_run.return_value.stderr = b''

        trufflehog_run = TrufflehogRun()
        trufflehog_run.install_tool("Linux", "/tmp")

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

        expected_command = (
            "powershell -Command "
            "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; [Net.ServicePointManager]::SecurityProtocol; " +
            "New-Item -Path C:/temp -ItemType Directory -Force; " +
            "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh' -OutFile C:/temp\\install_trufflehog.sh; " +
            "bash C:/temp\\install_trufflehog.sh -b C:/Trufflehog/bin; " +
            "$env:Path += ';C:/Trufflehog/bin'; C:/Trufflehog/bin/trufflehog.exe --version"
        )
        mock_popen.assert_called_once_with(expected_command, stdout=-1, stderr=-1, shell=True)
    
    @patch('builtins.open', create=True)
    @patch('concurrent.futures.ThreadPoolExecutor')
    @patch.object(TrufflehogRun, 'config_include_path')
    def test_run_tool_secret_scan(self, mock_config_include_path, mock_thread_pool_executor, mock_open):
        mock_executor = MagicMock()
        mock_executor_map_result = ['{"SourceMetadata":{"Data":{"Filesystem":{"file":"/usr/bin/local/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null}\n']
        mock_executor.map.return_value = mock_executor_map_result
        mock_thread_pool_executor.return_value.__enter__.return_value = mock_executor

        mock_config_include_path.return_value = ['/usr/temp/includePath0.txt']

        files_commits = ['/usr/file1.py', '/usr/file2.py']
        agent_os = 'Windows'
        agent_work_folder = '/usr/temp'
        repository_name = 'NU00000_Repo_Test'
        secret_external_checks = "github:tokenFake"
        json_config_tool = {
                "IGNORE_SEARCH_PATTERN": [
                    "test",
                    "NU0429001_DevSecOps_Remote_Config"
                ],
                "MESSAGE_INFO_ENGINE_SECRET": "If you have doubts, visit https://discuss.apps.bancolombia.com/t/evolucion-tarea-escaneo-de-secretos-devsecops-engine-tools/11091",
                "THRESHOLD": {
                    "VULNERABILITY": {
                        "Critical": 1,
                        "High": 1,
                        "Medium": 1,
                        "Low": 1
                    },
                    "COMPLIANCE": {
                        "Critical": 0
                    }
                },
                "TARGET_BRANCHES": ["trunk", "develop", "main"],
                "trufflehog": {
                    "EXCLUDE_PATH": [".git", "node_modules", "target", "build", "build.gradle", "twistcli-scan", ".svg", ".drawio"],
                    "NUMBER_THREADS": 4,
                    "ENABLE_CUSTOM_RULES" : "True",
                    "EXTERNAL_DIR_OWNER": "BCSCode",
                    "EXTERNAL_DIR_REPOSITORY": "DevSecOps_Checks_IaC"
                }
            }
        config_tool = DeserializeConfigTool(json_data=json_config_tool, tool="trufflehog")
        secret_tool = "secret"

        trufflehog_run = TrufflehogRun()

        result, file_findings = trufflehog_run.run_tool_secret_scan(files_commits, agent_os, agent_work_folder, repository_name, config_tool, secret_tool, secret_external_checks)

        expected_result = [
            {"SourceMetadata": {"Data": {"Filesystem": {"file": "/usr/bin/local/file1.txt", "line": 1}}}, "SourceID": 1,
            "SourceType": 15, "SourceName": "trufflehog - filesystem", "DetectorType": 17, "DetectorName": "URI",
            "DecoderName": "BASE64", "Verified": False,
            "Raw": "https://admin:admin@the-internet.herokuapp.com",
            "RawV2": "https://admin:admin@the-internet.herokuapp.com/basic_auth",
            "Redacted": "https://admin:********@the-internet.herokuapp.com", "ExtraData": None,
            "StructuredData": None}]
        self.assertEqual(result, expected_result)
        self.assertEqual(os.path.normpath(file_findings), os.path.normpath(os.path.join('/usr/temp/', 'secret_scan_result.json')))

    @patch('builtins.open', create=True)
    def test_config_include_path(self, mock_open):
        trufflehog_run = TrufflehogRun()

        result = trufflehog_run.config_include_path(['/usr/file1.py', '/usr/file2.py'], '/usr/temp')

        expected_result = ['/usr/temp/includePath0.txt', '/usr/temp/includePath1.txt']
        self.assertEqual(result, expected_result)

    @patch('subprocess.run')
    def test_run_trufflehog_enable_rules_false(self, mock_subprocess_run):
        mock_subprocess_run.return_value.stdout.strip.return_value = '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/usr/bin/local/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null}'
        enable_custom_rules = "false"
        trufflehog_run = TrufflehogRun()

        result = trufflehog_run.run_trufflehog('trufflehog', '/usr/local', '/usr/temp/excludedPath.txt', '/usr/temp/includePath0.txt', 'NU00000_Repo_Test', enable_custom_rules)

        expected_result = '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/usr/bin/local/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null}'
        self.assertEqual(result, expected_result)

    @patch('subprocess.run')
    def test_run_trufflehog_enable_rules_true(self, mock_subprocess_run):
        mock_subprocess_run.return_value.stdout.strip.return_value = '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/usr/bin/local/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null}'
        enable_custom_rules = "true"
        trufflehog_run = TrufflehogRun()

        result = trufflehog_run.run_trufflehog('trufflehog', '/usr/local', '/usr/temp/excludedPath.txt', '/usr/temp/includePath0.txt', 'NU00000_Repo_Test', enable_custom_rules)

        expected_result = '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/usr/bin/local/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null}'
        self.assertEqual(result, expected_result)
        
if __name__ == '__main__':
    unittest.main()