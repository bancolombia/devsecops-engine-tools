import unittest
from unittest.mock import Mock, patch, mock_open
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool import (
    NucleiTool,
    NucleiConfig,
    ConfigTool
    )

class TestNucleiTool(unittest.TestCase):

    def setUp(self):
        self.target_config = Mock()
        self.target_config.endpoint = "https://dummy.endpoint"
        self.target_config.target_type = "api"
        self.target_config.custom_templates_dir = "dummy_templates_dir"
        self.target_config.output_file = "dummy_output_file.json"

        self.config_tool = {
            "NUCLEI": {
                "VERSION": "2.3.296",
                "USE_EXTERNAL_CHECKS_GIT": "False",
                "EXTERNAL_CHECKS_GIT": "git@github.com:example/Checks.git//rules",
                "USE_EXTERNAL_CHECKS_DIR": "True",
                "EXTERNAL_DIR_OWNER": "username",
                "EXTERNAL_DIR_REPOSITORY": "engine-dast-nuclei-templates",
                "EXTERNAL_DIR_ASSET_NAME": "rules/engine_dast/nuclei",
                "EXCLUSIONS_PATH": "/engine_dast/Exclusions.json",
                "EXTERNAL_CHECKS_PATH": "/nuclei-templates",
                "MESSAGE_INFO_DAST": "If you have doubts, visit https://example.com/t/"
            }
        }
        self.token = "dummy_token"

        self.nuclei_tool = NucleiTool(target_config=self.target_config)

    @patch('os.environ.get', return_value="true")
    @patch('subprocess.run')
    @patch('builtins.open', new_callable=mock_open, read_data='{"key": "value"}')
    @patch('json.load', return_value={"key": "value"})
    def test_execute(self, mock_json_load, mock_open, mock_subprocess_run, mock_os_environ):
        target_config = NucleiConfig(self.target_config)
        result = self.nuclei_tool.execute(target_config)

        mock_subprocess_run.assert_called_once()
        mock_open.assert_called_once_with(target_config.output_file, 'r')
        mock_json_load.assert_called_once()
        self.assertEqual(result, {"key": "value"})

    @patch(
    'devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool.NucleiConfig.customize_templates'
    )
    @patch(
    'devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool.NucleiTool.configurate_external_checks',
    return_value="dummy_directory")
    @patch(
    'devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool.NucleiTool.execute',
    return_value={"key": "value"})
    @patch(
    'devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool.NucleiDesealizator.get_list_finding',
    return_value=[Mock()])
    @patch(
    'devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_tool.generate_file_from_tool',
    return_value="dummy_path_file_results")
    def test_run_tool(self, mock_generate_file, mock_get_list_finding,
                      mock_execute, mock_configurate_external_checks,
                      mock_customize_templates):
        findings_list, path_file_results = self.nuclei_tool.run_tool(self.target_config, self.config_tool, self.token)

        mock_configurate_external_checks.assert_called_once_with(self.config_tool, self.token, "/tmp")
        mock_customize_templates.assert_called_once_with("dummy_directory")
        mock_execute.assert_called_once()
        mock_get_list_finding.assert_called_once_with({"key": "value"})
        mock_generate_file.assert_called_once_with("NUCLEI", {"key": "value"}, self.config_tool)

        self.assertEqual(path_file_results, "dummy_path_file_results")