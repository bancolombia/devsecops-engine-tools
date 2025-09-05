import json
import subprocess
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan import (
    PrismaCloudManagerScan,
)
from devsecops_engine_tools.engine_core.src.domain.model.component import Component
from unittest.mock import patch, Mock, MagicMock, mock_open, mock_open
import pytest
import json


@pytest.fixture
def mock_requests_get():
    with patch("requests.get") as mock_get:
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
            "PRISMA_ACCESS_KEY": "",
            "PRISMA_API_VERSION": "v32.03",
        },
        "TRIVY": {"TRIVY_VERSION": "0.48.1"},
        "MESSAGE_INFO_SCA_RM": "If you have doubts, visit ",
        "THRESHOLD": {
            "VULNERABILITY": {"Critical": 999, "High": 999, "Medium": 999, "Low": 999},
            "COMPLIANCE": {"Critical": 1},
        },
    }


@pytest.fixture
def mock_scan_image():
    return [
        {"Repository": "466.com/nu04cr", "Tag": "ms_broker_db-trunk-trunk.20240126.1"}
    ]


@pytest.fixture
def mock_logger():
    return MagicMock()


def test_download_twistcli_success(mock_remoteconfig):
    with patch("requests.get") as mock_get, patch(
        "builtins.open", create=True
    ) as mock_open, patch("os.chmod") as mock_chmod, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.info"
    ) as mock_logger_info:
        mock_response = MagicMock()
        mock_response.content = b"twistcli_content"
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        scan_manager = PrismaCloudManagerScan()
        scan_manager.download_twistcli(
            "file_path",
            "prisma_key",
            mock_remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
            mock_remoteconfig["PRISMA_CLOUD"]["PRISMA_API_VERSION"],
        )


def test_download_twistcli_failure(twistcli_instance, mock_requests_get):
    file_path = "/path/to/twistcli"
    prisma_key = "your_access_key:your_secret_key"
    prisma_console_url = "https://prisma-console-url.com"
    prisma_api_version = "v1"

    expected_url = f"{prisma_console_url}/api/v1/util/twistcli"
    expected_credentials = "your_access_key:your_secret_key"
    expected_headers = {"Authorization": f"Basic {expected_credentials}"}

    mock_response = Mock()
    mock_response.raise_for_status.side_effect = Exception("Test Exception")
    mock_requests_get.return_value = mock_response

    with pytest.raises(
        ValueError, match="Error downloading twistcli: Test Exception"
    ), patch("builtins.open", create=True) as mock_open, patch(
        "os.chmod"
    ) as mock_chmod, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.info"
    ) as mock_logger_info:
        twistcli_instance.download_twistcli(
            file_path,
            prisma_key,
            prisma_console_url,
            prisma_api_version,
        )

        mock_requests_get.assert_called_once_with(
            expected_url, headers=expected_headers
        )
        mock_response.raise_for_status.assert_called_once()
        mock_open.assert_not_called()
        mock_chmod.assert_not_called()
        mock_logger_info.assert_not_called()


def test_scan_image_success(mock_remoteconfig):
    mock_file_data = '{"scanned_data": {"vulnerabilities": []}}'

    with patch("builtins.print") as mock_print, \
         patch("devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.subprocess.run") as mock_run, \
         patch("builtins.open", mock_open(read_data=mock_file_data)) as mock_file, \
         patch("json.dump") as mock_json_dump:

        mock_run.return_value = MagicMock()
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""

    
        scan_manager = PrismaCloudManagerScan()

       
        result = scan_manager.scan_image(
            "file_path",
            "image_name",
            "result.json",
            mock_remoteconfig,
            "prisma_access_key:some_secret_key",
            "unix:///var/run/docker.sock"
        )

       
        assert result == "result.json"
        mock_run.assert_called_once_with(
            [
                "file_path",
                "images",
                "scan",
                "--address",
                mock_remoteconfig["PRISMA_CLOUD"]["PRISMA_CONSOLE_URL"],
                "--user",
                "prisma_access_key",
                "--password",
                "some_secret_key",
                "--docker-address",
                "unix:///var/run/docker.sock",
                "--output-file",
                "result.json",
                "--details",
                "image_name"
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )
       
        mock_print.assert_any_call("The image image_name was scanned")


def test_run_tool_container_sca_success(mock_remoteconfig, mock_scan_image):
    with patch("builtins.open") as mock_open, patch("os.path.join") as mock_join, patch(
        "os.path.exists"
    ) as mock_exists:
        PrismaCloudManagerScan.download_twistcli = MagicMock()
        PrismaCloudManagerScan.scan_image = MagicMock()
        mock_exists.return_value = False
        PrismaCloudManagerScan.scan_image.return_value = "result.json"

        scan_manager = PrismaCloudManagerScan()
        result = scan_manager.run_tool_container_sca(
            mock_remoteconfig,
            {"access_prisma": "asdasd","token_prisma": "asdasd"},
            "token_container",
            "image_name",
            "result.json" , None , {"exclusions": "all"},
            "unix:///var/run/docker.sock",
            True,
        )
        
        assert result == ("result.json", None)


def test_generate_sbom_success():
    with patch(
        "builtins.open",
        mock_open(read_data=json.dumps({"results": [{"scanID": "12345"}]})),
    ), patch("requests.get") as mock_request:

        # Configurar los mocks
        mock_response = MagicMock()
        mock_response.content = b"fake sbom content"
        mock_request.return_value = mock_response

        # Crear instancia de PrismaCloudManagerScan
        prisma_scan = PrismaCloudManagerScan()

        # Datos de prueba
        image_scanned = "image_scanned.json"
        remoteconfig = {
            "PRISMA_CLOUD": {
                "PRISMA_CONSOLE_URL": "http://example.com",
                "PRISMA_API_VERSION": "v1",
                "SBOM_FORMAT": "json",
            }
        }
        prisma_key = "secret_key"
        image_name = "test_image"

        # Llamar a la función
        result = prisma_scan._generate_sbom(
            image_scanned, remoteconfig, prisma_key, image_name
        )

        # Verificar que se llamaron las funciones esperadas
        mock_request.assert_called_once_with(
            "http://example.com/api/v1/sbom/download/cli-images",
            headers={"Authorization": "Basic c2VjcmV0X2tleQ=="},
            params={"id": "12345", "sbomFormat": "json"},
        )
        assert result is not None

def test_write_image_base_success():
    mock_file_data = json.dumps({
        "results": [
            {
                "vulnerabilities": [
                    {"id": "CVE-1234-5678", "other_field": "value"}
                ]
            }
        ]
    })
    exclusions_data = {
        "All": {
            "PRISMA": [
                {
                    "id": "CVE-1234-5678",
                    "x86.image.name": ["python:3.9"]
                }
            ]
        }
    }
    remote_config = {
        "GET_IMAGE_BASE": {
            "LABEL_KEYS": {
                "key_image_exception": "x86.image.name"
            }
        }
    }
    base_image_tuple = ([["python:3.9"]], False)
    with patch("builtins.open", mock_open(read_data=mock_file_data)) as mock_file, \
         patch("json.dump") as mock_json_dump:
        scan_manager = PrismaCloudManagerScan()
        scan_manager._write_image_base("result.json", base_image_tuple, exclusions_data, remote_config)

        mock_file.assert_any_call("result.json", "r")
        mock_file.assert_any_call("result.json", "w")
        mock_json_dump.assert_called_once()
        written_data = mock_json_dump.call_args[0][0]
        assert written_data["results"][0]["vulnerabilities"][0]["baseImage"] == "['python:3.9']"

def test_write_image_base_no_match():
    mock_file_data = json.dumps({
        "results": [
            {
                "vulnerabilities": [
                    {"id": "CVE-9999-8888", "other_field": "value"}
                ]
            }
        ]
    })
    exclusions_data = {
        "All": {
            "PRISMA": [
                {
                    "id": "CVE-1234-5678",
                    "source_images": ["python:3.9"]
                }
            ]
        }
    }
    remote_config = {
        "VALIDATE_BASE_IMAGE_DATE": {
            "LABEL_KEYS": {
                "key_image_exception": "x86.image.name"
            }
        }
    }
    with patch("builtins.open", mock_open(read_data=mock_file_data)), \
         patch("json.dump") as mock_json_dump:
        scan_manager = PrismaCloudManagerScan()
        scan_manager._write_image_base("result.json", ([["python:3.9"]], False), exclusions_data, remote_config)

        # Validar que el archivo no fue modificado
        mock_json_dump.assert_not_called()

def test_write_image_base_file_not_found():
    exclusions_data = {
        "All": {
            "PRISMA": [
                {
                    "id": "CVE-1234-5678",
                    "source_images": ["python:3.9"]
                }
            ]
        }
    }
    remote_config = {
        "VALIDATE_BASE_IMAGE_DATE": {
            "LABEL_KEYS": {
                "key_image_exception": "x86.image.name"
            }
        }
    }
    with patch("builtins.open", side_effect=FileNotFoundError):
        scan_manager = PrismaCloudManagerScan()
        with pytest.raises(FileNotFoundError):
            scan_manager._write_image_base("result.json", ([["python:3.9"]], False), exclusions_data, remote_config)

def test_valid_prisma_key():
    scan_manager = PrismaCloudManagerScan()
    prisma_key = "your_access_key:your_secret_key"
    result = scan_manager._split_prisma_token(prisma_key)
    assert result == ("your_access_key", "your_secret_key")
    assert type(result) == tuple

def test_invalid_prisma_key():
    scan_manager = PrismaCloudManagerScan()
    prisma_key = "your_access_key"
    with pytest.raises(ValueError, match="The string is not properly formatted. Make sure it contains a ':'."):
        scan_manager._split_prisma_token(prisma_key)

def test_empty_prisma_key():
    scan_manager = PrismaCloudManagerScan()
    prisma_key = ""
    with pytest.raises(ValueError, match="The string is not properly formatted. Make sure it contains a ':'."):
        scan_manager._split_prisma_token(prisma_key)

def test_extra_colon_prisma_key():
    scan_manager = PrismaCloudManagerScan()
    prisma_key = "your_access_key:your_secret_key:extra"
    with pytest.raises(ValueError, match="The string is not properly formatted. Make sure it contains a ':'."):
        scan_manager._split_prisma_token(prisma_key)


def test_run_tool_container_sca_compressed_file():
    """Test that Prisma Cloud returns None for compressed files with proper warning"""
    scan_manager = PrismaCloudManagerScan()
    
    result = scan_manager.run_tool_container_sca(
        remoteconfig={},
        secret_tool=None,
        token_engine_container=None,
        image_name="/path/to/image.tar.gz",
        result_file="result.json",
        base_image=None,
        exclusions={},
        generate_sbom=False,
        docker_address="unix:///var/run/docker.sock",
        is_compressed_file=True
    )
    
    assert result == ("", None)
