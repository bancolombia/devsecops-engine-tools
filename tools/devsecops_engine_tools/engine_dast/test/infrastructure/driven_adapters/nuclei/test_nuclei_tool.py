import unittest
from unittest.mock import Mock, patch, mock_open
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool import (
    NucleiTool,
    NucleiConfig
    )

class TestNucleiTool(unittest.TestCase):

    def setUp(self):
        self.target_config = Mock()
        self.target_config.endpoint = "https://dummy.endpoint"
        self.target_config.target_type = "api"
        self.target_config.custom_templates_dir = "dummy_templates_dir"
        self.target_config.output_file = "result_dast_scan.json"

        self.config_tool = {
            "NUCLEI": {
                "VERSION": "2.3.296",
                "USE_EXTERNAL_CHECKS_GIT": False,
                "EXTERNAL_CHECKS_GIT": "git@github.com:example/Checks.git//rules",
                "USE_EXTERNAL_CHECKS_DIR": True,
                "EXTERNAL_DIR_OWNER": "username",
                "EXTERNAL_DIR_REPOSITORY": "engine-dast-nuclei-templates",
                "EXTERNAL_DIR_ASSET_NAME": "rules/engine_dast/nuclei",
                "MESSAGE_INFO_DAST": "If you have doubts, visit https://example.com/t/",
                "ENABLE_CUSTOM_RULES": True,
            }
        }
        self.token = "dummy_token"
        self.secret_tool = {
            "github_token": self.token
        }
        self.agent_work_folder = "/tmp"
        self.secret_external_checks = {}
        self.version = "3.0.0"
        self.nuclei_tool = NucleiTool(target_config=self.target_config)

    @patch("requests.get")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.path.expanduser")
    @patch("devsecops_engine_tools.engine_utilities.utils.utils.Utils.unzip_file")
    def test_download_tool(self, mock_unzip, mock_expanduser, mock_open_file, mock_requests_get):
        mock_expanduser.return_value = "/home/user"
        mock_requests_get.return_value.status_code = 200
        mock_requests_get.return_value.content = b"fake zip content"

        result = self.nuclei_tool.download_tool(self.version)

        self.assertEqual(result, 0)
        mock_requests_get.assert_called_once()
        mock_open_file.assert_called_once()
        mock_unzip.assert_called_once()

    @patch("shutil.which", return_value=None)
    @patch("subprocess.run")
    @patch("shutil.move")
    @patch("os.path.expanduser")
    @patch("devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool.NucleiTool.download_tool")
    def test_install_tool_linux(self, mock_download_tool, mock_expanduser, mock_shutil_move, mock_subprocess_run, mock_shutil_which):
        mock_expanduser.return_value = "/home/user"
        mock_download_tool.return_value = 0

        result = self.nuclei_tool.install_tool(self.version)

        self.assertEqual(result["status"], 201)
        mock_download_tool.assert_called_once()
        mock_subprocess_run.assert_called_once_with(["chmod", "+x", "/home/user/nuclei"], check=True)
        mock_shutil_move.assert_called_once()

    @patch('builtins.open', new_callable=mock_open, read_data='{"key": "value"}')
    @patch('json.load', return_value={"key": "value"})
    @patch("subprocess.run")
    def test_execute(self, mock_subprocess, mock_json_load, mock_open):
        mock_subprocess.side_effect = [
            Mock(returncode=0),
         ]
        target_config = NucleiConfig(self.target_config)
        result = self.nuclei_tool.execute("", target_config)
        mock_open.assert_called_once_with(target_config.output_file, 'r')
        mock_json_load.assert_called_once()
        self.assertEqual(result, {"key": "value"})

    @patch("devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool.NucleiTool.install_tool")
    @patch("devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool.NucleiTool.execute")
    @patch("devsecops_engine_tools.engine_utilities.utils.utils.Utils.configurate_external_checks")
    @patch("devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_config.NucleiConfig.customize_templates")
    def test_run_tool(self, mock_customize_templates, mock_configurate_external_checks, mock_execute, mock_install_tool):
        mock_install_tool.return_value = {"status": 201, "path": "/home/user/nuclei"}
        mock_execute.return_value = [{"id": "123", "info": {"name": "Test", "severity": "info"}}]

        findings, output_file = self.nuclei_tool.run_tool(
            target_data=self.target_config,
            config_tool=self.config_tool,
            secret_tool=self.secret_tool,
            secret_external_checks=self.secret_external_checks,
            agent_work_folder=self.agent_work_folder
        )

        self.assertEqual(output_file, self.target_config.output_file)
        mock_install_tool.assert_called_once()
        mock_execute.assert_called_once()