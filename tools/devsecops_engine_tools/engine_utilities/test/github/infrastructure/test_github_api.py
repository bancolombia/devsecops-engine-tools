import unittest
from unittest.mock import patch, MagicMock
from devsecops_engine_tools.engine_utilities.github.infrastructure.github_api import GithubApi

class TestGithubApi(unittest.TestCase):
    def setUp(self):
        self.token = "your_token"
        self.github_api = GithubApi(token=self.token)

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