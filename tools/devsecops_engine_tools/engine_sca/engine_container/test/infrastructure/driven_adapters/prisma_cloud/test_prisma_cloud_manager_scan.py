from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan import (
    PrismaCloudManagerScan,
)

from unittest.mock import patch, Mock, mock_open, call
import pytest
import stat
import base64

@pytest.fixture
def mock_requests_get():
    with patch('requests.get') as mock_get:
        yield mock_get

@pytest.fixture
def twistcli_instance():
    return PrismaCloudManagerScan()

def test_download_twistcli_failure(twistcli_instance, mock_requests_get):
    file_path = '/path/to/twistcli'
    prisma_access_key = 'your_access_key'
    prisma_secret_key = 'your_secret_key'
    prisma_console_url = 'https://prisma-console-url.com'

    expected_url = f"{prisma_console_url}/api/v1/util/twistcli"
    expected_credentials = 'your_access_key:your_secret_key'
    expected_headers = {"Authorization": f"Basic {expected_credentials}"}

    mock_response = Mock()
    mock_response.raise_for_status.side_effect = Exception('Test Exception')
    mock_requests_get.return_value = mock_response

    with pytest.raises(ValueError, match='Error downloading twistcli: Test Exception'), \
         patch('builtins.open', create=True) as mock_open, \
         patch('os.chmod') as mock_chmod, \
         patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.info') as mock_logger_info:
        
        twistcli_instance.download_twistcli(file_path, prisma_access_key, prisma_secret_key, prisma_console_url)

        mock_requests_get.assert_called_once_with(expected_url, headers=expected_headers)
        mock_response.raise_for_status.assert_called_once()
        mock_open.assert_not_called()
        mock_chmod.assert_not_called()
        mock_logger_info.assert_not_called()