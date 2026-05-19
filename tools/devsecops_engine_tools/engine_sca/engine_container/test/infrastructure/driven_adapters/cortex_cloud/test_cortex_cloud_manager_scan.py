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
            "CORTEXCLI_PATH": "twistcli",
            "CORTEX_CONSOLE_URL": "https://console.example.com",
            "CORTEX_API_VERSION": "v1",
            "SBOM_FORMAT": "json",
        }
    }


def test_split_cortex_token_invalid_format():
    with pytest.raises(ValueError):
        CortexCloudManagerScan()._split_cortex_token("invalid_token")


def test_split_cortex_token_valid_format():
    access, secret = CortexCloudManagerScan()._split_cortex_token("access:secret")
    assert access == "access"
    assert secret == "secret"


def test_scan_image_delegates_to_helper(mock_remoteconfig):
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.scan_image_with_tarball_fallback",
        return_value="result.json",
    ) as mock_fallback, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.build_scan_base_command",
        return_value=["base", "command"],
    ) as mock_build:
        manager = CortexCloudManagerScan()
        result = manager.scan_image(
            "file_path",
            "image_name",
            "result.json",
            mock_remoteconfig,
            "access:secret",
            "unix:///var/run/docker.sock",
            False,
        )

        assert result == "result.json"
        mock_build.assert_called_once()
        mock_fallback.assert_called_once()
        assert mock_fallback.call_args.kwargs["tool_label"] == "Cortex"
        assert mock_fallback.call_args.kwargs["is_compressed_file"] is False


def test_generate_sbom_delegates_to_helper(mock_remoteconfig):
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.generate_sbom",
        return_value=["component"],
    ) as mock_generate:
        manager = CortexCloudManagerScan()
        result = manager._generate_sbom(
            "scan.json", mock_remoteconfig, "access:secret", "image:1.0"
        )

        assert result == ["component"]
        kwargs = mock_generate.call_args.kwargs
        assert kwargs["console_url"] == "https://console.example.com"
        assert kwargs["api_version"] == "v1"
        assert kwargs["sbom_format"] == "json"


def test_write_image_base_uses_cortex_exclusions(mock_remoteconfig):
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.apply_base_image_exclusions"
    ) as mock_apply:
        manager = CortexCloudManagerScan()
        manager._write_image_base(
            "result.json", [["base"]], {"All": {"CORTEX": []}}, mock_remoteconfig
        )

        assert mock_apply.call_args.kwargs["exclusions_tool_key"] == "CORTEX"


def test_run_tool_container_sca_secret_tool_builds_key(mock_remoteconfig):
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.os.path.exists",
        return_value=True,
    ), patch.object(
        CortexCloudManagerScan, "scan_image", return_value="result.json"
    ) as mock_scan:
        manager = CortexCloudManagerScan()
        image_scanned, sbom = manager.run_tool_container_sca(
            remoteconfig=mock_remoteconfig,
            secret_tool={"access_cortex": "access", "token_cortex": "secret"},
            token_engine_container=None,
            image_name="image:1.0",
            result_file="result.json",
            base_image=None,
            exclusions={},
            generate_sbom=False,
            docker_address=None,
            is_compressed_file=False,
        )

        assert image_scanned == "result.json"
        assert sbom is None
        assert mock_scan.call_args.args[4] == "access:secret"


def test_run_tool_container_sca_downloads_and_calls_sbom_and_base_image(mock_remoteconfig):
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.os.path.exists",
        return_value=False,
    ), patch.object(
        CortexCloudManagerScan, "download_twistcli"
    ) as mock_download, patch.object(
        CortexCloudManagerScan, "scan_image", return_value="result.json"
    ), patch.object(
        CortexCloudManagerScan, "_write_image_base"
    ) as mock_base, patch.object(
        CortexCloudManagerScan, "_generate_sbom", return_value=["c1"]
    ) as mock_sbom:
        manager = CortexCloudManagerScan()
        image_scanned, sbom = manager.run_tool_container_sca(
            remoteconfig=mock_remoteconfig,
            secret_tool=None,
            token_engine_container="raw_token:secret",
            image_name="image:1.0",
            result_file="result.json",
            base_image=[["base_image"]],
            exclusions={"All": {"CORTEX": []}},
            generate_sbom=True,
            docker_address=None,
            is_compressed_file=False,
        )

        assert image_scanned == "result.json"
        assert sbom == ["c1"]
        mock_download.assert_called_once()
        mock_base.assert_called_once()
        mock_sbom.assert_called_once()


def test_download_twistcli_delegates_to_utility():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.download_twistcli",
        return_value=0,
    ) as mock_download:
        manager = CortexCloudManagerScan()
        result = manager.download_twistcli(
            "file_path", "access:secret", "https://console", "v1"
        )

        assert result == 0
        mock_download.assert_called_once_with(
            "file_path", "access:secret", "https://console", "v1"
        )


def test_get_container_context_from_results_returns_empty_list():
    assert CortexCloudManagerScan().get_container_context_from_results("any") == []
