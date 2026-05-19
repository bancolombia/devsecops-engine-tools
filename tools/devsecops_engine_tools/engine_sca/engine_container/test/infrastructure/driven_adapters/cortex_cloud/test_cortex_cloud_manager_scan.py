import subprocess
from unittest.mock import MagicMock, patch

import pytest

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan import (
    CortexCloudManagerScan,
)


@pytest.fixture
def mock_remoteconfig():
    return {
        "CORTEX_CLOUD": {
            "TWISTCLI_PATH": "twistcli",
            "PRISMA_CONSOLE_URL": "https://console.example.com",
            "PRISMA_API_VERSION": "v1",
            "SBOM_FORMAT": "json",
        }
    }


def test_scan_image_success(mock_remoteconfig):
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.subprocess.run"
    ) as mock_run, patch("builtins.print"):
        mock_run.return_value = MagicMock(stderr="")

        scan_manager = CortexCloudManagerScan()
        result = scan_manager.scan_image(
            "file_path",
            "image_name",
            "result.json",
            mock_remoteconfig,
            "access_key:secret_key",
            None,
            False,
        )

        assert result == "result.json"
        mock_run.assert_called_once_with(
            [
                "file_path",
                "images",
                "scan",
                "--address",
                "https://console.example.com",
                "--user",
                "access_key",
                "--password",
                "secret_key",
                "--output-file",
                "result.json",
                "--details",
                "image_name",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )


def test_scan_image_compressed_file_uses_tarball(mock_remoteconfig):
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.subprocess.run"
    ) as mock_run, patch("builtins.print"):
        mock_run.return_value = MagicMock(stderr="")

        scan_manager = CortexCloudManagerScan()
        result = scan_manager.scan_image(
            "file_path",
            "/tmp/image.tar.gz",
            "result.json",
            mock_remoteconfig,
            "access_key:secret_key",
            "unix:///var/run/docker.sock",
            True,
        )

        assert result == "result.json"
        command = mock_run.call_args[0][0]
        assert "--tarball" in command
        assert command[-1] == "/tmp/image.tar.gz"


def test_scan_image_tarball_fallback_success(mock_remoteconfig):
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.subprocess.run"
    ) as mock_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.os.path.exists",
        return_value=True,
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.os.remove"
    ) as mock_remove, patch("builtins.print"):
        error = subprocess.CalledProcessError(1, ["twistcli"])
        error.stdout = ""
        error.stderr = "scan failed"

        mock_docker_save = MagicMock()
        mock_success = MagicMock(stderr="")
        mock_run.side_effect = [error, mock_docker_save, mock_success]

        scan_manager = CortexCloudManagerScan()
        result = scan_manager.scan_image(
            "file_path",
            "ubuntu:latest",
            "result.json",
            mock_remoteconfig,
            "access_key:secret_key",
            None,
            False,
        )

        assert result == "result.json"
        assert mock_run.call_count == 3
        mock_remove.assert_called_once_with("/tmp/ubuntu_latest.tar")


def test_split_cortex_token_invalid_format():
    scan_manager = CortexCloudManagerScan()
    with pytest.raises(
        ValueError,
        match="The string is not properly formatted. Make sure it contains a ':'.",
    ):
        scan_manager._split_cortex_token("invalid_token")


def test_run_tool_container_sca_success(mock_remoteconfig):
    with patch(
        "os.path.exists", return_value=True
    ), patch.object(
        CortexCloudManagerScan, "scan_image", return_value="result.json"
    ) as mock_scan:
        scan_manager = CortexCloudManagerScan()
        result = scan_manager.run_tool_container_sca(
            remoteconfig=mock_remoteconfig,
            secret_tool={"access_cortex": "access", "token_cortex": "secret"},
            token_engine_container=None,
            image_name="image_name",
            result_file="result.json",
            base_image=None,
            exclusions={},
            generate_sbom=False,
            docker_address="unix:///var/run/docker.sock",
            is_compressed_file=False,
        )

        assert result == ("result.json", None)
        mock_scan.assert_called_once()
