import subprocess
from unittest.mock import MagicMock, patch

import pytest

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper import (
    build_scan_base_command,
    execute_scan,
    get_scan_retry_settings,
    scan_image_with_tarball_fallback,
    split_basic_auth_token,
)


def test_split_basic_auth_token_valid():
    assert split_basic_auth_token("a:b") == ("a", "b")


def test_split_basic_auth_token_invalid():
    with pytest.raises(ValueError):
        split_basic_auth_token("invalid")


def test_split_basic_auth_token_custom_error():
    with pytest.raises(ValueError, match="custom error"):
        split_basic_auth_token("invalid", error_message="custom error")


def test_build_scan_base_command_with_docker_address():
    cmd = build_scan_base_command(
        "twistcli", "https://console", "u:p", "unix:///docker.sock", "out.json"
    )
    assert cmd == [
        "twistcli",
        "images",
        "scan",
        "--address",
        "https://console",
        "--user",
        "u",
        "--password",
        "p",
        "--docker-address",
        "unix:///docker.sock",
        "--output-file",
        "out.json",
        "--details",
    ]


def test_build_scan_base_command_without_docker_address():
    cmd = build_scan_base_command(
        "twistcli", "https://console", "u:p", None, "out.json"
    )
    assert "--docker-address" not in cmd


def test_get_scan_retry_settings_uses_defaults():
    assert get_scan_retry_settings({}) == (1, 0.0, 1, 0.0)


def test_get_scan_retry_settings_clamps_tar_to_one():
    settings = get_scan_retry_settings({"SCAN_RETRIES_TAR": 0})
    assert settings[2] == 1


def test_execute_scan_returns_true_on_success():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.subprocess.run"
    ) as mock_run, patch("builtins.print"):
        mock_run.return_value = MagicMock(stderr="warning")
        assert execute_scan(["cmd"], "image", 1, 0, "Tool") is True


def test_execute_scan_retries_then_succeeds():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.subprocess.run"
    ) as mock_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.time.sleep"
    ) as mock_sleep, patch("builtins.print"):
        error = subprocess.CalledProcessError(1, ["cmd"])
        error.stdout = ""
        error.stderr = ""
        mock_run.side_effect = [error, MagicMock(stderr="")]

        assert execute_scan(["cmd"], "image", 2, 0.5, "Tool") is True
        mock_sleep.assert_called_once_with(0.5)


def test_execute_scan_returns_false_on_all_failures():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.subprocess.run"
    ) as mock_run:
        error = subprocess.CalledProcessError(1, ["cmd"])
        error.stdout = ""
        error.stderr = ""
        mock_run.side_effect = [error]
        assert execute_scan(["cmd"], "image", 1, 0, "Tool") is False


def test_scan_image_with_tarball_fallback_normal_success():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.execute_scan",
        return_value=True,
    ):
        result = scan_image_with_tarball_fallback(
            base_command=["base"],
            image_name="image",
            result_file="result.json",
            is_compressed_file=False,
            retry_settings=(1, 0, 1, 0),
            tool_label="Tool",
        )
        assert result == "result.json"


def test_scan_image_with_tarball_fallback_compressed_uses_tarball_flag():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.execute_scan",
        return_value=True,
    ) as mock_execute:
        result = scan_image_with_tarball_fallback(
            base_command=["base"],
            image_name="/tmp/image.tar",
            result_file="result.json",
            is_compressed_file=True,
            retry_settings=(1, 0, 1, 0),
            tool_label="Tool",
        )
        assert result == "result.json"
        executed_cmd = mock_execute.call_args.args[0]
        assert "--tarball" in executed_cmd


def test_scan_image_with_tarball_fallback_uses_docker_save_when_normal_fails():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.execute_scan",
        side_effect=[False, True],
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.subprocess.run"
    ) as mock_run, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.os.path.exists",
        return_value=True,
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.os.remove"
    ) as mock_remove:
        result = scan_image_with_tarball_fallback(
            base_command=["base"],
            image_name="ubuntu:latest",
            result_file="result.json",
            is_compressed_file=False,
            retry_settings=(1, 0, 1, 0),
            tool_label="Tool",
        )
        assert result == "result.json"
        mock_run.assert_called_once()
        mock_remove.assert_called_once_with("/tmp/ubuntu_latest.tar")


def test_scan_image_with_tarball_fallback_returns_none_when_docker_save_fails():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.execute_scan",
        return_value=False,
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, ["docker"], stderr="boom"),
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.helpers.twistcli_scan_helper.os.path.exists",
        return_value=False,
    ):
        result = scan_image_with_tarball_fallback(
            base_command=["base"],
            image_name="image",
            result_file="result.json",
            is_compressed_file=False,
            retry_settings=(1, 0, 1, 0),
            tool_label="Tool",
        )
        assert result is None
