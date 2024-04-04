from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan import (
    PrismaCloudManagerScan,
)

from unittest.mock import patch, Mock, mock_open, MagicMock
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

@pytest.fixture
def mock_remoteconfig():
    return {
    "PRISMA_CLOUD": {
        "TWISTCLI_PATH": "twistcli",
        "PRISMA_CONSOLE_URL": "",
        "PRISMA_ACCESS_KEY": "" ,
         "PRISMA_API_VERSION":"v32.03"        
    },
    "TRIVY": {
        "TRIVY_VERSION": "0.48.1"
    },
    "MESSAGE_INFO_SCA_RM": "If you have doubts, visit ",
    "REGEX_EXPRESSION_PROJECTS": "((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS[A-Z]{3})\\d+)",
    "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 999,
            "High": 999,
            "Medium": 999,
            "Low": 999
        },
        "COMPLIANCE": {
            "Critical": 1
        }
    }
}

@pytest.fixture
def mock_scan_image():
    return [{"Repository": "466.com/nu04cr", "Tag": "ms_broker_db-trunk-trunk.20240126.1"}]

@pytest.fixture
def mock_images_scanned():
    return []

@pytest.fixture
def mock_logger():
    return MagicMock()

def test_download_twistcli_success(mock_remoteconfig):
    with patch("requests.get") as mock_get, \
            patch("builtins.open", create=True) as mock_open, \
            patch("os.chmod") as mock_chmod, \
            patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.info') as mock_logger_info:
             
        mock_response = MagicMock()
        mock_response.content = b"twistcli_content"
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        scan_manager = PrismaCloudManagerScan()
        scan_manager.download_twistcli(
            "file_path",
            "prisma_access_key",
            "prisma_secret_key",
            mock_remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
            mock_remoteconfig["PRISMA_CLOUD"]["PRISMA_API_VERSION"]
        )
     
def test_download_twistcli_failure(twistcli_instance, mock_requests_get):
    file_path = '/path/to/twistcli'
    prisma_access_key = 'your_access_key'
    prisma_secret_key = 'your_secret_key'
    prisma_console_url = 'https://prisma-console-url.com'
    prisma_api_version = 'v1'

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
        
        twistcli_instance.download_twistcli(file_path, prisma_access_key, prisma_secret_key, prisma_console_url,prisma_api_version)

        mock_requests_get.assert_called_once_with(expected_url, headers=expected_headers)
        mock_response.raise_for_status.assert_called_once()
        mock_open.assert_not_called()
        mock_chmod.assert_not_called()
        mock_logger_info.assert_not_called()
        

def test_scan_image_success(mock_remoteconfig, mock_scan_image, mock_images_scanned):
    with patch("builtins.print") as mock_print, \
            patch("devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.subprocess.run") as mock_run, \
            patch("builtins.open", create=True) as mock_open:
        mock_run.return_value = MagicMock()
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""
        mock_open().readlines.return_value = mock_images_scanned

        scan_manager = PrismaCloudManagerScan()
        result = scan_manager.scan_image(
            "file_path",
            "repository",
            "tag",
            mock_remoteconfig,
            "prisma_secret_key",
            "release",
        )

        assert result == mock_images_scanned


def test_run_tool_container_sca_success(mock_remoteconfig, mock_scan_image, mock_images_scanned):
    with patch("devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.os.path.exists") as mock_exists, \
            patch("builtins.open", create=True) as mock_open, \
            patch.object(PrismaCloudManagerScan, "download_twistcli") as mock_download_twistcli, \
            patch.object(PrismaCloudManagerScan, "scan_image") as mock_scan_image:
        mock_exists.return_value = False
        mock_scan_image.return_value = mock_images_scanned

        scan_manager = PrismaCloudManagerScan()
        result = scan_manager.run_tool_container_sca(
            mock_remoteconfig, "prisma_secret_key", mock_scan_image, "release",False
        )

        assert result == mock_images_scanned
        mock_download_twistcli.assert_called_once()