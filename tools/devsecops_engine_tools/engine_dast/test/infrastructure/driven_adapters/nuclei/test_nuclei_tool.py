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
    @patch('builtins.open', new_callable=mock_open, read_data='{"key": "value"}')
    @patch('json.load', return_value={"key": "value"})
    def test_execute(self, mock_json_load, mock_open, mock_os_environ):
        target_config = NucleiConfig(self.target_config)
        result = self.nuclei_tool.execute(target_config)
        mock_open.assert_called_once_with(target_config.output_file, 'r')
        mock_json_load.assert_called_once()
        self.assertEqual(result, {"key": "value"})
