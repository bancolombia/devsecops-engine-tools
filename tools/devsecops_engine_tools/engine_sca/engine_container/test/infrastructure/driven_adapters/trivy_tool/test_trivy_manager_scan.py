from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan import (
    TrivyScan,
)

from unittest.mock import patch, Mock, mock_open, call
import pytest
import subprocess


@pytest.fixture
def trivy_scan_instance():
    return TrivyScan()


def test_install_tool_already_installed(trivy_scan_instance):
    version = "0.48.1"
    with patch("subprocess.run") as mock_subprocess_run:
        mock_subprocess_run.side_effect = [Mock(returncode=0)]
        trivy_scan_instance.install_tool(version)

        assert (
            mock_subprocess_run.call_count == 1
        ), "subprocess se ejecuta una vez (Trivy instalado)"


def test_install_tool_installation_successful(trivy_scan_instance):
    version = "0.48.1"
    with patch("subprocess.run") as mock_subprocess_run:
        mock_subprocess_run.reset_mock()
        mock_subprocess_run.side_effect = [
            Mock(returncode=1),  # Mock 'which' can not find 'trivy'
            Mock(returncode=0),  # Mock success running 'wget'
            Mock(returncode=0),  # Mock success running 'dpkg'
        ]
        trivy_scan_instance.install_tool(version)
        mock_subprocess_run.assert_has_calls(
            [
                call(["which", "trivy"], stdout=-1, stderr=-1),
                call(
                    [
                        "wget",
                        f"https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_Linux-64bit.deb",
                    ],
                    check=True,
                    stdout=-1,
                    stderr=-1,
                ),
                call(
                    ["sudo", "dpkg", "-i", f"trivy_{version}_Linux-64bit.deb"],
                    check=True,
                    stdout=-1,
                    stderr=-1,
                ),
            ]
        )


def test_install_tool_installation_failure(trivy_scan_instance):
    version = "0.48.1"
    with patch("subprocess.run") as mock_subprocess_run:
        mock_subprocess_run.side_effect = [
            Mock(returncode=1),  # Mock 'which' can not find 'trivy'
            subprocess.CalledProcessError(
                returncode=1, cmd="wget"
            ),  # Mock failure running 'wget'
            Mock(side_effect=0),  # Mock success running 'dpkg'
        ]

        with pytest.raises(RuntimeError):
            trivy_scan_instance.install_tool(version)

        mock_subprocess_run.reset_mock()
        mock_subprocess_run.side_effect = [
            Mock(returncode=1),  # Mock 'which' can not find 'trivy'
            Mock(side_effect=0),  # Mock success running 'wget'
            subprocess.CalledProcessError(
                returncode=1, cmd="dpkg"
            ),  # Mock failure running 'dpkg'
        ]

        with pytest.raises(RuntimeError):
            trivy_scan_instance.install_tool(version)


def test_run_tool_container_sca(trivy_scan_instance):
    mock_remoteconfig = {
        "TRIVY": {"TRIVY_VERSION": "0.48.1"},
        "REGEX_EXPRESSION_PROJECTS": "((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS[A-Z]{3})\\d+)",
    }
    mock_scan_image = [
        {"Repository": "registry/nu0429002_devsecops_test_debian", "Tag": "latest"},
        {"Repository": "registry/nu0429002_devsecops_test", "Tag": "latest"},
        {"Repository": "Ubuntu", "Tag": "latest"},
        {"Repository": "Debian", "Tag": "latest"},
        {"Repository": "registry/nu0429002_test", "Tag": "1.2"},
    ]

    with patch("subprocess.run", return_value=Mock()) as mock_subprocess_run:
        with patch("builtins.open", mock_open()) as mock_file_open:
            result = trivy_scan_instance.run_tool_container_sca(
                mock_remoteconfig, "token", mock_scan_image, "nu0429002_devsecops_test"
            )

            # Subprocess
            mock_subprocess_run.assert_called()  # Make sure subprocess.run has been called correctly

            # Open file
            mock_file_open.assert_called()  # Make sure that an attempt has been made to open the file

            # Return
            assert isinstance(result, list)  # Make sure that a list has been returned
            expected_result = [
                "nu0429002_devsecops_test_debian:latest_scan_result.json",
                "nu0429002_devsecops_test:latest_scan_result.json",
                "nu0429002_test:1.2_scan_result.json",
            ]
            assert result == expected_result, "La lista resotrnada no es la esperada"

            # Could not scan image
            mock_subprocess_run.reset_mock()
            mock_subprocess_run.side_effect = [
                Mock(side_effect=0),  # Mock 'which' can find 'trivy'
                subprocess.CalledProcessError(
                    returncode=1, cmd="dpkg"
                ),  # Mock failure running 'trivy'
                Mock(side_effect=0),  # Mock success running 'trivy'
            ]

            result = trivy_scan_instance.run_tool_container_sca(
                mock_remoteconfig, "token", mock_scan_image, "test"
            )
            assert len(result) == 0
