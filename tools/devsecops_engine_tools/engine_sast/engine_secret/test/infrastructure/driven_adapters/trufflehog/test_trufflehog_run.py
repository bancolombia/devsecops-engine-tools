import json
import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.DeserializeConfigTool import DeserializeConfigTool
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run import TrufflehogRun

import os

class TestTrufflehogRun(unittest.TestCase):
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.run')
    def test_install_tool_win(self, mock_subprocess_run):
        tool_version = "3.0.1"
        agent_os = "Windows"
        agent_temp_dir = "/tmp"

        mock_subprocess_run.return_value = MagicMock(stderr=b"version 3.0.1")

        obj = TrufflehogRun()
        obj.run_install_win = MagicMock()
        obj.run_install = MagicMock()

        obj.install_tool(agent_os, agent_temp_dir, tool_version)
        
        obj.run_install.assert_not_called()
        obj.run_install_win.assert_not_called()
       
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.run')
    def test_install_tool_unix(self, mock_subprocess_run):
        tool_version = "3.0.1"
        agent_os = "Linux"
        agent_temp_dir = "/tmp"

        mock_subprocess_run.return_value = MagicMock(stderr=b"version 2.9.0")

        obj = TrufflehogRun()
        obj.run_install_win = MagicMock()
        obj.run_install = MagicMock()

        obj.install_tool(agent_os, agent_temp_dir, tool_version)

        obj.run_install.assert_called_once_with(tool_version)
        obj.run_install_win.assert_not_called()
    
    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.run')
    def test_install_tool_unix_no_install(self, mock_subprocess_run):
        tool_version = "3.0.1"
        agent_os = "Linux"
        agent_temp_dir = "/tmp"

        mock_subprocess_run.return_value = MagicMock(stderr=f"version {tool_version}".encode('utf-8'))

        obj = TrufflehogRun()
        obj.run_install_win = MagicMock()
        obj.run_install = MagicMock()

        obj.install_tool(agent_os, agent_temp_dir, tool_version)

        obj.run_install.assert_not_called()
        obj.run_install_win.assert_not_called()

    @patch('subprocess.run')
    def test_run_install(self, mock_subprocess_run):
        tool_version = "1.2.3"
        trufflehog_run = TrufflehogRun()
        trufflehog_run.run_install(tool_version)
        mock_subprocess_run.assert_called_once_with(
            f"curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin v{tool_version}",
            capture_output=True,
            shell=True
        )

    @patch('devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_run.subprocess.Popen')
    def test_run_install_win(self, mock_popen):
        agent_temp_dir = "C:/temp"
        tool_version = "1.2.3"     
        trufflehog_run = TrufflehogRun()
        trufflehog_run.run_install_win(agent_temp_dir, tool_version)

        expected_command = (
            f"powershell -Command [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; [Net.ServicePointManager]::SecurityProtocol; New-Item -Path {agent_temp_dir} -ItemType Directory -Force; Invoke-WebRequest -Uri 'https://github.com/trufflesecurity/trufflehog/releases/download/v{tool_version}/trufflehog_{tool_version}_windows_amd64.tar.gz' -OutFile {agent_temp_dir}/trufflehog.tar.gz -UseBasicParsing; tar -xzf {agent_temp_dir}/trufflehog.tar.gz -C {agent_temp_dir}; Remove-Item {agent_temp_dir}/trufflehog.tar.gz; $env:Path += '; + {agent_temp_dir}'; & {agent_temp_dir}/trufflehog.exe --version"
        )
        mock_popen.assert_called_once_with(expected_command, stdout=-1, stderr=-1, shell=True)
    
    @patch('builtins.open', create=True)
    @patch('concurrent.futures.ThreadPoolExecutor')
    @patch.object(TrufflehogRun, 'config_include_path')
    def test_run_tool_secret_scan(self, mock_config_include_path, mock_thread_pool_executor, mock_open):
        mock_executor = MagicMock()
        mock_executor_map_result = ['{"SourceMetadata":{"Data":{"Filesystem":{"file":"/usr/bin/local/file1.txt","line":1}}},"SourceID":1,"SourceType":15,"SourceName":"trufflehog - filesystem","DetectorType":17,"DetectorName":"URI","DecoderName":"BASE64","Verified":false,"Raw":"https://admin:admin@the-internet.herokuapp.com","RawV2":"https://admin:admin@the-internet.herokuapp.com/basic_auth","Redacted":"https://admin:********@the-internet.herokuapp.com","ExtraData":null,"StructuredData":null,"Id": "SECRET_SCANNING"}\n']
        mock_executor.map.return_value = mock_executor_map_result
        mock_thread_pool_executor.return_value.__enter__.return_value = mock_executor

        mock_config_include_path.return_value = ['/usr/temp/includePath0.txt']

        agent_temp_dir = '/tmp'
        files_commits = ['/usr/file1.py', '/usr/file2.py']
        agent_os = 'Windows'
        agent_work_folder = '/usr/temp'
        repository_name = 'NU00000_Repo_Test'
        secret_external_checks = "github:tokenFake"
        json_config_tool = {
                "IGNORE_SEARCH_PATTERN": [
                    "test"
                ],
                "MESSAGE_INFO_ENGINE_SECRET": "dummy message",
                "THRESHOLD": {
                    "VULNERABILITY": {
                        "Critical": 1,
                        "High": 1,
                        "Medium": 1,
                        "Low": 1
                    },
                    "COMPLIANCE": {
                        "Critical": 1
                    }
                },
                "TARGET_BRANCHES": ["trunk", "develop", "main"],
                "trufflehog": {
                    "VERSION": "1.2.3",
                    "EXCLUDE_PATH": [".git", "node_modules", "target", "build", "build.gradle", "twistcli-scan", ".svg", ".drawio"],
                    "NUMBER_THREADS": 4,
                    "ENABLE_CUSTOM_RULES" : "True",
                    "EXTERNAL_DIR_OWNER": "External_Github",
                    "EXTERNAL_DIR_REPOSITORY": "DevSecOps_Checks",
                    "RULES": {
                        "MISSCONFIGURATION_SCANNING" : {
                            "References" : "https://link.reference.com"
                        }
                    }
                }
            }
        config_tool = DeserializeConfigTool(json_data=json_config_tool, tool="trufflehog")
        secret_tool = "secret"

        trufflehog_run = TrufflehogRun()

        result, file_findings = trufflehog_run.run_tool_secret_scan(files_commits, agent_os, agent_work_folder, repository_name, config_tool, secret_tool, secret_external_checks, agent_temp_dir)

        expected_result = [
            {"SourceMetadata": {"Data": {"Filesystem": {"file": "/usr/bin/local/file1.txt", "line": 1}}}, "SourceID": 1,
            "SourceType": 15, "SourceName": "trufflehog - filesystem", "DetectorType": 17, "DetectorName": "URI",
            "DecoderName": "BASE64", "Verified": False,
            "Raw": "https://admin:admin@the-internet.herokuapp.com",
            "RawV2": "https://admin:admin@the-internet.herokuapp.com/basic_auth",
            "Redacted": "https://admin:********@the-internet.herokuapp.com", "ExtraData": None,
            "StructuredData": None,
            "Id": "SECRET_SCANNING",
            'References': 'N.A', 
            'Mitigation': ''}]
        self.assertEqual(result, expected_result)
        self.assertEqual(os.path.normpath(file_findings), os.path.normpath(os.path.join('/usr/temp/', 'secret_scan_result.json')))

    @patch('builtins.open', create=True)
    def test_config_include_path(self, mock_open):
        trufflehog_run = TrufflehogRun()

        result = trufflehog_run.config_include_path(['/usr/file1.py', '/usr/file2.py'], '/usr/temp', 'Windows')

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