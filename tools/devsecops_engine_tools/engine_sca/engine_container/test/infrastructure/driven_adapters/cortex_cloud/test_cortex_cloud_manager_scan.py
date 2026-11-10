import json
import subprocess
from unittest.mock import Mock, patch

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan import (
    CortexCloudManagerScan,
)


def test_run_tool_container_sca_uses_secret_manager_credentials_and_remote_version(tmp_path):
    result_file = tmp_path / "scan.json"
    scan_output = {"scannersResults": []}
    secret_tool = {"token_cortex": "api-token", "access_cortex": "api-key-id"}
    remote_config = {
        "CORTEX_CLOUD": {
            "CORTEX_API_URL": "https://cortex.example.test",
            "CORTEX_CLI_VERSION": "0.37.0",
        }
    }

    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.download_cortexcli",
        return_value="/tmp/cortexcli",
    ) as download, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.subprocess.run",
        return_value=Mock(stdout=json.dumps(scan_output), stderr=""),
    ) as run:
        manager = CortexCloudManagerScan()
        result, sbom = manager.run_tool_container_sca(
            remote_config,
            secret_tool,
            None,
            "biometriafacial:latest",
            str(result_file),
            None,
            {},
            False,
            "unix:///var/run/docker.sock",
        )

    download.assert_called_once_with("0.37.0")
    assert run.call_args.args[0] == [
        "/tmp/cortexcli",
        "--api-base-url",
        "https://cortex.example.test",
        "--api-key",
        "api-token",
        "--api-key-id",
        "api-key-id",
        "--soft-fail",
        "image",
        "scan",
        "--output-format",
        "json",
        "--docker-host",
        "unix:///var/run/docker.sock",
        "biometriafacial:latest",
    ]
    run.assert_called_once_with(
        run.call_args.args[0],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert json.loads(result_file.read_text()) == scan_output
    assert result == str(result_file)
    assert sbom is None


def test_scan_image_uses_archive_option_for_compressed_images(tmp_path):
    result_file = tmp_path / "scan.json"
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.subprocess.run",
        return_value=Mock(stdout='{"scannersResults": []}', stderr=""),
    ) as run:
        result = CortexCloudManagerScan().scan_image(
            "/tmp/cortexcli",
            "image.tar.gz",
            str(result_file),
            {"CORTEX_CLOUD": {}},
            {"token_cortex": "token", "access_cortex": "id"},
            None,
            True,
        )

    assert run.call_args.args[0][-2:] == ["--archive", "image.tar.gz"]
    assert "--api-base-url" not in run.call_args.args[0]
    assert result == str(result_file)


def test_generate_sbom_uses_cyclonedx_output(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    manager = CortexCloudManagerScan()
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.subprocess.run"
    ) as run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.get_list_component",
        return_value=["component"],
    ) as parse_sbom:
        result = manager._generate_sbom(
            "/tmp/cortexcli",
            "biometriafacial:latest",
            {"CORTEX_CLOUD": {"CORTEX_CLI_VERSION": "0.37.0"}},
            {"token_cortex": "token", "access_cortex": "id"},
            None,
            False,
        )

    command = run.call_args.args[0]
    assert "--api-base-url" not in command
    assert command[command.index("image") : command.index("image") + 2] == ["image", "sbom"]
    assert command[command.index("--sbom-type") + 1] == "cyclonedx1.4"
    assert command[-1] == "biometriafacial:latest"
    parse_sbom.assert_called_once_with("biometriafacial_latest_SBOM.json", "cyclonedx_json")
    assert result == ["component"]


def test_run_tool_container_sca_requires_cortex_secrets():
    manager = CortexCloudManagerScan()
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.cortex_cloud.cortex_cloud_manager_scan.download_cortexcli"
    ) as download:
        try:
            manager.run_tool_container_sca({}, None, None, "image", "result.json", None, {}, False, None)
        except ValueError as error:
            assert "credentials" in str(error)
        else:
            raise AssertionError("Missing Cortex credentials should be rejected")
    download.assert_not_called()