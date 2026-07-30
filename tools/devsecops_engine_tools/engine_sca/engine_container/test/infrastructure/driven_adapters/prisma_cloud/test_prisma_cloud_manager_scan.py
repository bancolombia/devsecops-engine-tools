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
            "unix:///var/run/docker.sock",
            False,
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


def test_scan_image_error_logs_details(mock_remoteconfig):
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.subprocess.run"
    ) as mock_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error"
    ) as mock_logger_error, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.os.path.exists",
        return_value=False,
    ):
        error = subprocess.CalledProcessError(
            137,
            ["twistcli", "images", "scan"],
        )
        error.stdout = "stdout content"
        error.stderr = "stderr content"
        mock_run.side_effect = error

        scan_manager = PrismaCloudManagerScan()

        result = scan_manager.scan_image(
            "file_path",
            "image_name",
            "result.json",
            mock_remoteconfig,
            "prisma_access_key:some_secret_key",
            None,
            False,
        )

        assert result is None
        # Check that scan error was logged with correct format and arguments
        assert mock_logger_error.called
        call_args = mock_logger_error.call_args_list[0]
        assert "Error during image scan of %s" in call_args[0][0]
        assert call_args[0][1] == "image_name"
        assert call_args[0][2] == 137
        assert call_args[0][3] == "stderr content"
        assert call_args[0][4] == "stdout content"


def test_scan_image_retries_with_delay(mock_remoteconfig):
    remoteconfig = {
        **mock_remoteconfig,
        "PRISMA_CLOUD": {
            **mock_remoteconfig["PRISMA_CLOUD"],
            "SCAN_RETRIES_TAR": 2,
            "SCAN_RETRY_DELAY_TAR_SECONDS": 0.5,
        },
    }

    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.subprocess.run"
    ) as mock_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.time.sleep"
    ) as mock_sleep, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.error"
    ) as mock_logger_error, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.warning"
    ) as mock_logger_warning, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.logger.info"
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.os.path.exists",
        return_value=True,
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.os.remove"
    ), patch("builtins.print"):
        mock_success = MagicMock()
        mock_success.stderr = ""
        mock_docker_save = MagicMock()

        error = subprocess.CalledProcessError(1, ["twistcli", "images", "scan"])
        error.stdout = ""
        error.stderr = ""
        # 1: normal scan fails, 2: docker save ok, 3: tarball attempt 1 fails, 4: tarball attempt 2 ok
        mock_run.side_effect = [
            error,
            mock_docker_save,
            error,
            mock_success,
        ]

        scan_manager = PrismaCloudManagerScan()

        result = scan_manager.scan_image(
            "file_path",
            "image_name",
            "result.json",
            remoteconfig,
            "prisma_access_key:some_secret_key",
            None,
            False,
        )

        assert result == "result.json"
        assert mock_run.call_count == 4
        mock_sleep.assert_called_once_with(0.5)


def test_run_tool_container_sca_success(mock_remoteconfig, mock_scan_image):
    with patch("builtins.open") as mock_open, patch("os.path.join") as mock_join, patch(
        "os.path.exists"
    ) as mock_exists, patch.object(
        PrismaCloudManagerScan, "download_twistcli"
    ), patch.object(
        PrismaCloudManagerScan, "scan_image", return_value="result.json"
    ):
        mock_exists.return_value = False

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


def test_scan_image_tarball_fallback_success(mock_remoteconfig):
    """Test that scan falls back to tarball when normal scan fails."""
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.subprocess.run"
    ) as mock_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.os.path.exists",
        return_value=True,
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.os.remove"
    ) as mock_remove, patch("builtins.print"):
        error = subprocess.CalledProcessError(1, ["twistcli", "images", "scan"])
        error.stdout = ""
        error.stderr = "scan failed"

        mock_docker_save_success = MagicMock()
        mock_tarball_scan_success = MagicMock()
        mock_tarball_scan_success.stderr = ""

        mock_run.side_effect = [error, mock_docker_save_success, mock_tarball_scan_success]

        scan_manager = PrismaCloudManagerScan()

        result = scan_manager.scan_image(
            "file_path",
            "my/image:latest",
            "result.json",
            mock_remoteconfig,
            "prisma_access_key:some_secret_key",
            None,
            False,
        )

        assert result == "result.json"
        assert mock_run.call_count == 3
        # Verify docker save was called
        docker_save_call = mock_run.call_args_list[1]
        assert docker_save_call[0][0] == ["docker", "save", "-o", "/tmp/my_image_latest.tar", "my/image:latest"]
        # Verify tarball scan used --tarball flag and tarball path as last arg
        tarball_scan_call = mock_run.call_args_list[2]
        assert "--tarball" in tarball_scan_call[0][0]
        assert tarball_scan_call[0][0][-1] == "/tmp/my_image_latest.tar"
        # Verify cleanup
        mock_remove.assert_called_once_with("/tmp/my_image_latest.tar")


def test_scan_image_tarball_fallback_cleanup_on_failure(mock_remoteconfig):
    """Test that tarball is cleaned up even when tarball scan also fails."""
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.subprocess.run"
    ) as mock_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.os.path.exists",
        return_value=True,
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.os.remove"
    ) as mock_remove:
        error = subprocess.CalledProcessError(1, ["twistcli"])
        error.stdout = ""
        error.stderr = "scan failed"

        mock_docker_save_success = MagicMock()

        # Normal scan fails, docker save succeeds, tarball scan fails
        mock_run.side_effect = [error, mock_docker_save_success, error]

        scan_manager = PrismaCloudManagerScan()

        result = scan_manager.scan_image(
            "file_path",
            "ubuntu:latest",
            "result.json",
            mock_remoteconfig,
            "prisma_access_key:some_secret_key",
            None,
            False,
        )

        assert result is None
        # Tarball must be cleaned up even on failure
        mock_remove.assert_called_once_with("/tmp/ubuntu_latest.tar")


def test_run_tool_container_sca_compressed_file(mock_remoteconfig):
    """Test that compressed files are scanned with --tarball flag via scan_image"""
    with patch("os.path.join", return_value="/fake/twistcli"), \
         patch("os.path.exists", return_value=True), \
         patch.object(
             PrismaCloudManagerScan, "scan_image", return_value="result.json"
         ) as mock_scan:
        scan_manager = PrismaCloudManagerScan()

        result = scan_manager.run_tool_container_sca(
            remoteconfig=mock_remoteconfig,
            secret_tool={"access_prisma": "key", "token_prisma": "secret"},
            token_engine_container=None,
            image_name="/path/to/image.tar.gz",
            result_file="result.json",
            base_image=None,
            exclusions={},
            generate_sbom=False,
            docker_address="unix:///var/run/docker.sock",
            is_compressed_file=True,
        )

        assert result == ("result.json", None)
        # Verify scan_image was called with is_compressed_file=True
        mock_scan.assert_called_once()
        call_kwargs_or_args = mock_scan.call_args
        assert call_kwargs_or_args[0][-1] is True  # last positional arg = is_compressed_file


def test_scan_image_compressed_file_uses_tarball_flag(mock_remoteconfig):
    """Test that scan_image uses --tarball flag when is_compressed_file=True"""
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan.subprocess.run"
    ) as mock_run, patch("builtins.print"):
        mock_run.return_value = MagicMock(stderr="")

        scan_manager = PrismaCloudManagerScan()
        result = scan_manager.scan_image(
            "file_path",
            "/path/to/image.tar.gz",
            "result.json",
            mock_remoteconfig,
            "prisma_access_key:some_secret_key",
            None,
            True,
        )

        assert result == "result.json"
        # Verify the command used --tarball flag with image as last arg
        actual_command = mock_run.call_args[0][0]
        assert "--tarball" in actual_command
        assert actual_command[-1] == "/path/to/image.tar.gz"


def test_scan_image_normal_retries_success_no_tarball(mock_remoteconfig):
    """Test that normal scan retries (SCAN_RETRIES > 1) can succeed without tarball fallback."""
    remoteconfig = {
        **mock_remoteconfig,
        "PRISMA_CLOUD": {
            **mock_remoteconfig["PRISMA_CLOUD"],
            "SCAN_RETRIES": 3,
            "SCAN_RETRY_DELAY_SECONDS": 0.1,
        },
    }

    _mod = "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan"
    with patch(f"{_mod}.subprocess.run") as mock_run, \
         patch(f"{_mod}.time.sleep") as mock_sleep, \
         patch(f"{_mod}.logger.error"), \
         patch(f"{_mod}.logger.warning"), \
         patch("builtins.print"):

        error = subprocess.CalledProcessError(1, ["twistcli"])
        error.stdout = ""
        error.stderr = ""
        mock_success = MagicMock(stderr="")

        # Normal: attempt 1 fails, attempt 2 fails, attempt 3 succeeds
        mock_run.side_effect = [error, error, mock_success]

        scan_manager = PrismaCloudManagerScan()
        result = scan_manager.scan_image(
            "file_path", "image_name", "result.json",
            remoteconfig, "key:secret", None, False,
        )

        assert result == "result.json"
        # Only 3 calls (all normal scan), no docker save, no tarball scan
        assert mock_run.call_count == 3
        assert mock_sleep.call_count == 2
        # Verify no --tarball in any call
        for call in mock_run.call_args_list:
            assert "--tarball" not in call[0][0]


def test_scan_image_normal_retries_exhaust_then_tarball_succeeds(mock_remoteconfig):
    """Test that after all normal retries fail, tarball fallback succeeds on first try."""
    remoteconfig = {
        **mock_remoteconfig,
        "PRISMA_CLOUD": {
            **mock_remoteconfig["PRISMA_CLOUD"],
            "SCAN_RETRIES": 2,
            "SCAN_RETRY_DELAY_SECONDS": 0.1,
        },
    }

    _mod = "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan"
    with patch(f"{_mod}.subprocess.run") as mock_run, \
         patch(f"{_mod}.time.sleep"), \
         patch(f"{_mod}.logger.error"), \
         patch(f"{_mod}.logger.warning"), \
         patch(f"{_mod}.logger.info"), \
         patch(f"{_mod}.os.path.exists", return_value=True), \
         patch(f"{_mod}.os.remove") as mock_remove, \
         patch("builtins.print"):

        error = subprocess.CalledProcessError(1, ["twistcli"])
        error.stdout = ""
        error.stderr = ""
        mock_docker_save = MagicMock()
        mock_success = MagicMock(stderr="")

        # Normal: 2 fails, docker save ok, tarball: 1 success
        mock_run.side_effect = [error, error, mock_docker_save, mock_success]

        scan_manager = PrismaCloudManagerScan()
        result = scan_manager.scan_image(
            "file_path", "image_name", "result.json",
            remoteconfig, "key:secret", None, False,
        )

        assert result == "result.json"
        assert mock_run.call_count == 4
        # Verify tarball scan used --tarball flag
        tarball_scan_call = mock_run.call_args_list[3]
        assert "--tarball" in tarball_scan_call[0][0]
        mock_remove.assert_called_once()


def test_scan_image_docker_save_failure(mock_remoteconfig):
    """Test that when docker save fails, error is logged and None is returned."""
    _mod = "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan"
    with patch(f"{_mod}.subprocess.run") as mock_run, \
         patch(f"{_mod}.logger.error") as mock_logger_error, \
         patch(f"{_mod}.logger.warning"), \
         patch(f"{_mod}.os.path.exists", return_value=False):

        scan_error = subprocess.CalledProcessError(1, ["twistcli"])
        scan_error.stdout = ""
        scan_error.stderr = ""

        docker_save_error = subprocess.CalledProcessError(1, ["docker", "save"])
        docker_save_error.stdout = ""
        docker_save_error.stderr = "no space left on device"

        # Normal scan fails, docker save fails
        mock_run.side_effect = [scan_error, docker_save_error]

        scan_manager = PrismaCloudManagerScan()
        result = scan_manager.scan_image(
            "file_path", "ubuntu:latest", "result.json",
            mock_remoteconfig, "key:secret", None, False,
        )

        assert result is None
        assert mock_run.call_count == 2
        # Verify docker save error was logged
        save_error_calls = [
            c for c in mock_logger_error.call_args_list
            if "Error saving image" in str(c)
        ]
        assert len(save_error_calls) == 1


def test_scan_image_tar_retries_clamped_to_one_when_zero(mock_remoteconfig):
    """Test that SCAN_RETRIES_TAR < 1 is clamped to 1 (at least one tarball attempt)."""
    remoteconfig = {
        **mock_remoteconfig,
        "PRISMA_CLOUD": {
            **mock_remoteconfig["PRISMA_CLOUD"],
            "SCAN_RETRIES_TAR": 0,
        },
    }

    _mod = "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan"
    with patch(f"{_mod}.subprocess.run") as mock_run, \
         patch(f"{_mod}.logger.error"), \
         patch(f"{_mod}.logger.warning"), \
         patch(f"{_mod}.logger.info"), \
         patch(f"{_mod}.os.path.exists", return_value=True), \
         patch(f"{_mod}.os.remove"), \
         patch("builtins.print"):

        error = subprocess.CalledProcessError(1, ["twistcli"])
        error.stdout = ""
        error.stderr = ""
        mock_docker_save = MagicMock()
        mock_success = MagicMock(stderr="")

        # Normal fails, docker save ok, tarball succeeds
        mock_run.side_effect = [error, mock_docker_save, mock_success]

        scan_manager = PrismaCloudManagerScan()
        result = scan_manager.scan_image(
            "file_path", "image:tag", "result.json",
            remoteconfig, "key:secret", None, False,
        )

        assert result == "result.json"
        assert mock_run.call_count == 3


def test_scan_image_compressed_file_failure_triggers_tarball_fallback(mock_remoteconfig):
    """Test that when is_compressed_file=True and first scan fails, tarball fallback is attempted."""
    _mod = "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.prisma_cloud.prisma_cloud_manager_scan"
    with patch(f"{_mod}.subprocess.run") as mock_run, \
         patch(f"{_mod}.logger.error"), \
         patch(f"{_mod}.logger.warning"), \
         patch(f"{_mod}.logger.info"), \
         patch(f"{_mod}.os.path.exists", return_value=True), \
         patch(f"{_mod}.os.remove") as mock_remove, \
         patch("builtins.print"):

        error = subprocess.CalledProcessError(1, ["twistcli"])
        error.stdout = ""
        error.stderr = ""
        mock_docker_save = MagicMock()
        mock_success = MagicMock(stderr="")

        # First scan (with --tarball) fails, docker save ok, tarball fallback succeeds
        mock_run.side_effect = [error, mock_docker_save, mock_success]

        scan_manager = PrismaCloudManagerScan()
        result = scan_manager.scan_image(
            "file_path", "/path/to/image.tar.gz", "result.json",
            mock_remoteconfig, "key:secret", None, True,
        )

        assert result == "result.json"
        assert mock_run.call_count == 3
        # First call should have --tarball (compressed file)
        first_call_cmd = mock_run.call_args_list[0][0][0]
        assert "--tarball" in first_call_cmd
        # Cleanup should happen
        mock_remove.assert_called_once()


def test_get_container_context_from_results_maps_fields(twistcli_instance):
    mock_file_data = json.dumps({
        "results": [
            {
                "id": "sha256:abcd1234",
                "name": "test_image:latest",
                "distro": "Debian GNU/Linux 9 (stretch)",
                "vulnerabilities": [
                    {
                        "id": "CVE-2013-7459",
                        "status": "fixed in 2.6.2",
                        "cvss": 9.8,
                        "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "description": "Heap-based buffer overflow\nin pycrypto.",
                        "severity": "important",
                        "packageName": "pycrypto",
                        "packageVersion": "2.6.1",
                        "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-7459",
                        "publishedDate": "2014-01-01T00:00:00Z",
                        "discoveredDate": "2023-01-01T00:00:00Z",
                    }
                ],
            }
        ]
    })

    with patch("builtins.open", mock_open(read_data=mock_file_data)):
        context_list = twistcli_instance.get_container_context_from_results("result.json")

    assert len(context_list) == 1
    context = context_list[0]
    assert context.cve_id == "CVE-2013-7459"
    assert context.severity == "high"
    assert context.vulnerability_status == "fixed in 2.6.2"
    assert context.target_image == "test_image:latest"
    assert context.package_name == "pycrypto"
    assert context.installed_version == "2.6.1"
    assert context.fixed_version == "2.6.2"
    assert context.cvss_score == 9.8
    assert context.cvss_vector == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert "\n" not in context.description
    assert context.os_type == "Debian GNU/Linux 9 (stretch)"
    assert context.layer_digest == "sha256:abcd1234"
    assert context.published_date == "2014-01-01T00:00:00Z"
    assert context.last_modified_date == "2023-01-01T00:00:00Z"
    assert context.references == ["https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-7459"]
    assert context.source_tool == "PrismaCloud"


def test_get_container_context_from_results_defaults_missing_fields(twistcli_instance):
    mock_file_data = json.dumps({
        "results": [
            {
                "id": "sha256:abcd1234",
                "vulnerabilities": [
                    {"id": "CVE-9999-0000", "packageName": "openssl"}
                ],
            }
        ]
    })

    with patch("builtins.open", mock_open(read_data=mock_file_data)):
        context_list = twistcli_instance.get_container_context_from_results("result.json")

    assert len(context_list) == 1
    context = context_list[0]
    assert context.cve_id == "CVE-9999-0000"
    assert context.severity == "unknown"
    assert context.fixed_version == "unknown"
    assert context.target_image == "sha256:abcd1234"
    assert context.references == "unknown"
    assert context.cvss_score is None


def test_get_container_context_from_results_no_results(twistcli_instance):
    mock_file_data = json.dumps({"results": []})

    with patch("builtins.open", mock_open(read_data=mock_file_data)):
        context_list = twistcli_instance.get_container_context_from_results("result.json")

    assert context_list == []
