import unittest
from unittest.mock import patch, mock_open
from devsecops_engine_tools.engine_utilities.sonarqube.infrastructure.sonar.report_sonar import SonarAdapter

class TestSonarAdapter(unittest.TestCase):

    @patch(
        "os.getenv"
    )
    def test_get_project_keys_from_env(self, mock_getenv):
        # Arrange
        adapter = SonarAdapter()
        mock_getenv.return_value = '{"sonar.scanner.metadataFilePath":"path/to/metadata.json"}'
        
        with patch.object(adapter, 'parse_project_key', return_value="project_key_123") as mock_parse:
            # Act
            project_keys = adapter.get_project_keys("pipeline_name")

            # Assert
            mock_parse.assert_called_once_with("path/to/metadata.json")
            self.assertEqual(project_keys, ["project_key_123"])

    @patch('os.getenv')
    def test_get_project_keys_no_match_in_env(self, mock_getenv):
        # Arrange
        adapter = SonarAdapter()
        mock_getenv.return_value = ''
        
        # Act
        project_keys = adapter.get_project_keys("pipeline_name")

        # Assert
        self.assertEqual(project_keys, ["pipeline_name"])

    @patch('os.getenv')
    def test_get_project_keys_no_project_key_found(self, mock_getenv):
        # Arrange
        adapter = SonarAdapter()
        mock_getenv.return_value = '{"sonar.scanner.metadataFilePath":"path/to/metadata.json"}'
        
        with patch.object(adapter, 'parse_project_key', return_value=None) as mock_parse:
            # Act
            project_keys = adapter.get_project_keys("pipeline_name")

            # Assert
            mock_parse.assert_called_once_with("path/to/metadata.json")
            self.assertEqual(project_keys, ["pipeline_name"])

    @patch(
        "builtins.open", 
        new_callable=mock_open,
        read_data="projectKey=my_project_key"
    )
    def test_parse_project_key_success(self, mock_file):
        # Arrange
        adapter = SonarAdapter()
        
        # Act
        result = adapter.parse_project_key("path/to/metadata.json")

        # Assert
        mock_file.assert_called_once_with("path/to/metadata.json", 'r', encoding='utf-8')
        self.assertEqual(result, "my_project_key")

    def test_parse_project_key_invalid_content(self):
        # Arrange
        adapter = SonarAdapter()

        # Act
        result = adapter.parse_project_key("path/to/metadata.json")

        # Assert
        self.assertIsNone(result)

    @patch(
        "builtins.open", 
        side_effect=Exception("File not found")
    )
    def test_parse_project_key_file_not_found(self, mock_file):
        # Arrange
        adapter = SonarAdapter()

        # Act
        result = adapter.parse_project_key("path/to/nonexistent_file.json")

        # Assert
        mock_file.assert_called_once_with("path/to/nonexistent_file.json", 'r', encoding='utf-8')
        self.assertIsNone(result)

    def test_create_task_report_from_string(self):
        # Arrange
        adapter = SonarAdapter()
        file_content = "projectKey=my_project_key\nanotherSetting=some_value"
        
        # Act
        result = adapter.create_task_report_from_string(file_content)

        # Assert
        self.assertEqual(result["projectKey"], "my_project_key")
        self.assertEqual(result["anotherSetting"], "some_value")
