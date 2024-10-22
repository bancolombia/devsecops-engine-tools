import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import GithubApi, ApiError
import json


class TestGithubApi(unittest.TestCase):
    def setUp(self):
        self.personal_access_token = "your_token"
        self.github_api = GithubApi()

    @patch('devsecops_engine_tools.engine_utilities.github.infrastructure.github_api.zipfile.ZipFile')
    def test_unzip_file(self, mock_zipfile):
        # Configurar el mock de zipfile
        mock_zip_ref = mock_zipfile.return_value

        # Llamar a la función que deseas probar
        self.github_api.unzip_file('/path/to/your/file.zip', '/path/to/extract')

        # Verificar que se haya llamado a los métodos/métodos simulados según lo esperado
        mock_zipfile.assert_called_once_with('/path/to/your/file.zip', 'r')

    @patch('devsecops_engine_tools.engine_utilities.github.infrastructure.github_api.requests.get')
    @patch('devsecops_engine_tools.engine_utilities.github.infrastructure.github_api.GithubApi.unzip_file')
    @patch('builtins.open', new_callable=unittest.mock.mock_open())
    def test_download_latest_release_assets(self, mock_open, mock_unzip_file, mock_get):
        # Configurar el objeto de respuesta simulado
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "assets": [
                {
                    "url": "https://example.com/asset.zip",
                    "name": "asset.zip"
                }
            ]
        }
        mock_get.return_value = mock_response

        owner = "owner"
        repository = "repository"
        download_path = "."

        # Llamar a la función que deseas probar
        self.github_api.download_latest_release_assets(
            owner, repository, download_path
        )

        # Verificar que se haya llamado a los métodos/métodos simulados según lo esperado
        mock_get.assert_called()
        mock_unzip_file.assert_called_once_with(
            f"{download_path}/asset.zip", download_path
        )

        mock_open.assert_called_once_with(f"{download_path}/asset.zip", "wb")

    @patch('devsecops_engine_tools.engine_utilities.github.infrastructure.github_api.Github')
    def test_get_github_connection(self, mock_github):
        mock_github_instance = MagicMock()
        mock_github.return_value = mock_github_instance

        test_token = "test_token"

        github_api = GithubApi()

        result = github_api.get_github_connection(test_token)

        mock_github.assert_called_once_with(test_token)

        self.assertEqual(result, mock_github_instance)

    @patch('devsecops_engine_tools.engine_utilities.github.infrastructure.github_api.Github')
    def test_get_remote_json_config(self, MockGithub):
        owner = "test_owner"
        repository = "test_repo"
        path = "path/to/config.json"
        expected_json = {"key": "value"}
        encoded_content = json.dumps(expected_json).encode()

        mock_github_instance = MagicMock()
        mock_repo = MagicMock()
        mock_file_content = MagicMock()
        mock_file_content.decoded_content = encoded_content

        mock_github_instance.get_repo.return_value = mock_repo
        mock_repo.get_contents.return_value = mock_file_content
        MockGithub.return_value = mock_github_instance

        github_api = GithubApi()

        result = github_api.get_remote_json_config(mock_github_instance, owner, repository, path)

        mock_github_instance.get_repo.assert_called_once_with(f"{owner}/{repository}")
        mock_repo.get_contents.assert_called_once_with(path)

        self.assertEqual(result, expected_json)

    @patch('devsecops_engine_tools.engine_utilities.github.infrastructure.github_api.Github')
    def test_get_remote_json_config_raises_error(self, MockGithub):
        owner = "test_owner"
        repository = "test_repo"
        path = "path/to/config.json"

        mock_github_instance = MagicMock()
        mock_github_instance.get_repo.side_effect = Exception("Test exception")

        MockGithub.return_value = mock_github_instance

        github_api = GithubApi()

        with self.assertRaises(ApiError) as context:
            github_api.get_remote_json_config(mock_github_instance, owner, repository, path)

        self.assertIn("Error getting remote github configuration file: Test exception", str(context.exception))
