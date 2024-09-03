import unittest
from unittest.mock import Mock, patch, mock_open
from devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_config import NucleiConfig

class TestNucleiConfig(unittest.TestCase):

    def setUp(self):
        self.target_config_api = Mock()
        self.target_config_api.endpoint = "https://dummy.endpoint"
        self.target_config_api.target_type = "api"
        self.target_config_api.operations = [Mock(), Mock()]

        self.target_config_wa = Mock()
        self.target_config_wa.endpoint = "https://dummy.endpoint"
        self.target_config_wa.target_type = "wa"
        self.target_config_wa.data = {"key": "value"}

        self.nuclei_api = NucleiConfig(self.target_config_api)
        self.nuclei_wa = NucleiConfig(self.target_config_wa)

    def test_init_api(self):
        self.assertEqual(self.nuclei_api.url, "https://dummy.endpoint")
        self.assertEqual(self.nuclei_api.target_type, "api")
        self.assertEqual(self.nuclei_api.data, self.target_config_api.operations)

    def test_init_wa(self):
        self.assertEqual(self.nuclei_wa.url, "https://dummy.endpoint")
        self.assertEqual(self.nuclei_wa.target_type, "wa")
        self.assertEqual(self.nuclei_wa.data, self.target_config_wa.data)

    def test_init_invalid_target_type(self):
        target_config_invalid = Mock()
        target_config_invalid.target_type = "invalid"
        with self.assertRaises(ValueError):
            NucleiConfig(target_config_invalid)

    @patch('os.makedirs')
    @patch('os.path.exists', return_value=False)
    def test_process_templates_folder(self, mock_exists, mock_makedirs):
        base_folder = "dummy_base_folder"
        self.nuclei_api.custom_templates_dir = "dummy_custom_templates_dir"
        
        with patch('os.walk', return_value=[('root', [], ['file.yaml'])]), \
             patch('builtins.open', mock_open(read_data="https: {}")), \
             patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_config.NucleiConfig.process_template_file') as mock_process_template_file:
            
            self.nuclei_api.process_templates_folder(base_folder)
            mock_exists.assert_called_once_with(self.nuclei_api.custom_templates_dir)
            mock_makedirs.assert_called_once_with(self.nuclei_api.custom_templates_dir)

    @patch('builtins.open', new_callable=mock_open, read_data="https: {}")
    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_config.YAML.load',
           return_value={"https": [{}]})
    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_config.YAML.dump')
    def test_process_template_file(self, mock_dump, mock_load, mock_open):
        base_folder = "dummy_base_folder"
        dest_folder = "dummy_dest_folder"
        template_name = "dummy_template.yaml"
        new_template_data = {
            "operation": {
                "method": "GET",
                "path": "/dummy_path",
                "headers": {"Content-Type": "application/json"},
                "payload": {"key": "value"}
            }
        }
        template_counter = 0

        self.nuclei_api.process_template_file(base_folder,
                                              dest_folder,
                                              template_name,
                                              new_template_data,
                                              template_counter)

        mock_load.assert_called_once()
        mock_dump.assert_called_once()

    @patch('devsecops_engine_tools.engine_dast.src.infrastructure.driven_adapters.nuclei.nuclei_config.NucleiConfig.process_templates_folder')
    def test_customize_templates(self, mock_process_templates_folder):
        directory = "dummy_directory"
        self.nuclei_api.customize_templates(directory)
        self.assertEqual(self.nuclei_api.custom_templates_dir, "customized-nuclei-templates")
        mock_process_templates_folder.assert_any_call(base_folder=directory)