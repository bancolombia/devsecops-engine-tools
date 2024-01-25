import unittest
from unittest.mock import MagicMock
from unittest import mock
from queue import Queue
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool import (
    CheckovTool,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.domain.model.config_tool import (
    ConfigTool,
)
from devsecops_engine_utilities.github.infrastructure.github_api import GithubApi
import os


class TestCheckovTool(unittest.TestCase):
    def setUp(self):
        self.checkov_tool = CheckovTool()

    def test_create_config_file(self):
        checkov_config = MagicMock()
        checkov_config.path_config_file = "/path/to/config/"
        checkov_config.config_file_name = "docker"
        checkov_config.dict_confg_file = {"key": "value"}

        with mock.patch("builtins.open", create=True) as mock_open:
            self.checkov_tool.create_config_file(checkov_config)

            mock_open.assert_called_once_with(
                "/path/to/config/dockercheckov_config.yaml", "w"
            )

    def test_configurate_external_checks_git(self):
        # Configurar valores simulados
        json_data = {
            "CHECKOV": {
                "VERSION": "2.3.296",
                "SEARCH_PATTERN": ["AW", "NU"],
                "IGNORE_SEARCH_PATTERN": [
                    "test",
                ],
                "USE_EXTERNAL_CHECKS_GIT": "True",
                "EXTERNAL_CHECKS_GIT": "rules",
                "EXTERNAL_GIT_SSH_HOST": "github",
                "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "fingerprint",
                "USE_EXTERNAL_CHECKS_DIR": "False",
                "EXTERNAL_DIR_OWNER": "test",
                "EXTERNAL_DIR_REPOSITORY": "repository",
                "EXTERNAL_DIR_ASSET_NAME": "rules",
                "EXCLUSIONS_PATH": "Exclusions.json",
                "MESSAGE_INFO_SAST_RM": "message test",
                "THRESHOLD": {
                    "VULNERABILITY": {
                        "Critical": 10,
                        "High": 3,
                        "Medium": 20,
                        "Low": 30,
                    },
                    "COMPLIANCE": {"Critical": 4},
                },
                "RULES": "",
            }
        }
        mock_config_tool = ConfigTool(json_data, "CHECKOV")
        mock_secret_tool = {
            "repository_ssh_private_key": "cmVwb3NpdG9yeV9zc2hfcHJpdmF0ZV9rZXkK",
            "repository_ssh_password": "cmVwb3NpdG9yeV9zc2hfcGFzc3dvcmQK",
        }

        # Llamar al método que se está probando
        result = self.checkov_tool.configurate_external_checks(
            mock_config_tool, mock_secret_tool
        )

        # Verificar que el resultado es el esperado
        self.assertIsNone(result)

    @mock.patch(
        "devsecops_engine_utilities.github.infrastructure.github_api.GithubApi.download_latest_release_assets",
        autospec=True,
    )
    def test_configurate_external_checks_dir(self, mock_github_api):
        # Configurar valores simulados
        json_data = {
            "CHECKOV": {
                "VERSION": "2.3.296",
                "SEARCH_PATTERN": ["AW", "NU"],
                "IGNORE_SEARCH_PATTERN": [
                    "test",
                ],
                "USE_EXTERNAL_CHECKS_GIT": "False",
                "EXTERNAL_CHECKS_GIT": "rules",
                "EXTERNAL_GIT_SSH_HOST": "github",
                "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "fingerprint",
                "USE_EXTERNAL_CHECKS_DIR": "True",
                "EXTERNAL_DIR_OWNER": "test",
                "EXTERNAL_DIR_REPOSITORY": "repository",
                "EXTERNAL_DIR_ASSET_NAME": "rules",
                "EXCLUSIONS_PATH": "Exclusions.json",
                "MESSAGE_INFO_SAST_RM": "message test",
                "THRESHOLD": {
                    "VULNERABILITY": {
                        "Critical": 10,
                        "High": 3,
                        "Medium": 20,
                        "Low": 30,
                    },
                    "COMPLIANCE": {"Critical": 4},
                },
                "RULES": "",
            }
        }
        mock_config_tool = ConfigTool(json_data, "CHECKOV")
        mock_secret_tool = {
            "github_token": "mock_github_token",
            "repository_ssh_host": "repository_ssh_host",
        }

        # Configurar el valor simulado de retorno para ciertos métodos
        mock_github_api_instance = MagicMock()
        mock_github_api.return_value = mock_github_api_instance

        # Llamar al método que se está probando
        result = self.checkov_tool.configurate_external_checks(
            mock_config_tool, mock_secret_tool
        )

        # Verificar que el resultado es el esperado
        self.assertIsNone(result)

    def test_configurate_external_checks_secret_tool_None(self):
        # Llamar al método que se está probando
        result = self.checkov_tool.configurate_external_checks(
            None, None
        )

        # Verificar que el resultado es el esperado
        self.assertIsNone(result)

    @mock.patch(
        "devsecops_engine_utilities.github.infrastructure.github_api.GithubApi.download_latest_release_assets",
        autospec=True,
    )
    def test_configurate_external_checks_error(self, mock_github_api):
        # Configurar valores simulados
        json_data = {
            "CHECKOV": {
                "VERSION": "2.3.296",
                "SEARCH_PATTERN": ["AW", "NU"],
                "IGNORE_SEARCH_PATTERN": [
                    "test",
                ],
                "USE_EXTERNAL_CHECKS_GIT": "False",
                "EXTERNAL_CHECKS_GIT": "rules",
                "EXTERNAL_GIT_SSH_HOST": "github",
                "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "fingerprint",
                "USE_EXTERNAL_CHECKS_DIR": "True",
                "EXTERNAL_DIR_OWNER": "test",
                "EXTERNAL_DIR_REPOSITORY": "repository",
                "EXTERNAL_DIR_ASSET_NAME": "rules",
                "EXCLUSIONS_PATH": "Exclusions.json",
                "MESSAGE_INFO_SAST_RM": "message test",
                "THRESHOLD": {
                    "VULNERABILITY": {
                        "Critical": 10,
                        "High": 3,
                        "Medium": 20,
                        "Low": 30,
                    },
                    "COMPLIANCE": {"Critical": 4},
                },
                "RULES": "",
            }
        }
        mock_config_tool = ConfigTool(json_data, "CHECKOV")
        mock_secret_tool = {
            "github_token": "mock_github_token",
            "repository_ssh_host": "repository_ssh_host",
        }

        # Configurar el valor simulado de retorno para ciertos métodos
        mock_github_api.side_effect = Exception("Simulated error")

        # Llamar al método que se está probando
        result = self.checkov_tool.configurate_external_checks(
            mock_config_tool, mock_secret_tool
        )

        # Verificar que el resultado es el esperado
        self.assertIsNone(result)

    def test_execute(self):
        checkov_config = MagicMock()
        checkov_config.path_config_file = "/path/to/config/"
        checkov_config.config_file_name = "checkov_config"

        subprocess_mock = MagicMock()
        subprocess_mock.run.return_value.stdout = "Output"
        subprocess_mock.run.return_value.stderr = "Error"

        with mock.patch("subprocess.run", return_value=subprocess_mock) as mock_run:
            self.checkov_tool.execute(checkov_config)

            mock_run.assert_called_once_with(
                "checkov --config-file /path/to/config/checkov_configcheckov_config.yaml",
                capture_output=True,
                text=True,
                shell=True,
                env=dict(os.environ),
            )

    @mock.patch(
        "devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.checkov.checkov_tool.CheckovTool.execute",
        autospec=True,
    )
    def test_async_scan(self, mock_checkov_tool):
        checkov_config = MagicMock()
        checkov_config.path_config_file = "/path/to/config/"
        checkov_config.config_file_name = "checkov_config"

        output_queue = Queue()

        mock_checkov_tool.return_value = '{"key": "value"}'

        self.checkov_tool.async_scan(output_queue, checkov_config)

        self.assertEqual(output_queue.get(), [{"key": "value"}])

    def test_scan_folders(self):
        folders_to_scan = ["/path/to/folder"]
        config_tool = MagicMock()
        config_tool.rules_data_type = {
            "RULES_DOCKER": {"rule1": {"environment": {"dev": True}}},
            "RULES_K8S": {"rule2": {"environment": {"prod": True}}},
        }
        agent_env = MagicMock()
        environment = "dev"

        output_queue = Queue()
        output_queue.put([{"key": "value"}])

        with mock.patch.object(
            self.checkov_tool, "async_scan", side_effect=output_queue.put
        ):
            result_scans = self.checkov_tool.scan_folders(
                folders_to_scan, config_tool, agent_env, environment, "eks"
            )

        self.assertEqual(result_scans, [])

    def test_run_tool(self):
        config_tool = MagicMock()
        folders_to_scan = ["/path/to/folder"]
        environment = "dev"
        platform = "eks"
        secret_tool = MagicMock()

        self.checkov_tool.configurate_external_checks = MagicMock(
            return_value="agent_env"
        )
        self.checkov_tool.scan_folders = MagicMock(return_value=[{"key": "value"}])
        self.checkov_tool.TOOL = "CHECKOV"

        findings_list, file_from_tool = self.checkov_tool.run_tool(
            config_tool, folders_to_scan, environment, platform ,secret_tool
        )

        self.assertEqual(findings_list, [])
        assert "results.json" in file_from_tool
