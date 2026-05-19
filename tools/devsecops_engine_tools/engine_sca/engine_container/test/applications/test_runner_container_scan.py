from devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan import (
    runner_engine_container,
)

from unittest.mock import patch


def test_init_engine_container():
    """Test that runner_engine_container properly initializes and returns expected values"""
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan.init_engine_sca_rm"
    ) as mock_init_engine_sca_rm, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan.PrismaCloudManagerScan"
    ) as mock_prisma, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan.PrismaDeserealizator"
    ) as mock_prisma_deser, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan.DockerImages"
    ) as mock_docker:
        # Mock the return value to match what init_engine_sca_rm returns (3 values)
        mock_findings = ["finding1", "finding2"]
        mock_input_core = {"key": "value"}
        mock_sbom = ["component1"]
        mock_init_engine_sca_rm.return_value = (mock_findings, mock_input_core, mock_sbom)
        
        dict_args = {"remote_config_repo": "remote_repo", "remote_config_branch": ""}
        token = "token"
        tool = "PRISMA"

        findings_list, input_core, sbom_components, tool_run = runner_engine_container(dict_args, tool, token, None, None)

        # Verify init_engine_sca_rm was called
        mock_init_engine_sca_rm.assert_called_once()
        
        # Verify return values
        assert findings_list == mock_findings
        assert input_core == mock_input_core
        assert sbom_components == mock_sbom
        assert tool_run is not None  # tool_run should be the PrismaCloudManagerScan instance


def test_init_engine_container_cortex():
    """Test that runner_engine_container supports Cortex tool selection."""
    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan.init_engine_sca_rm"
    ) as mock_init_engine_sca_rm, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan.CortexCloudManagerScan"
    ) as mock_cortex, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan.CortexDeserealizator"
    ) as mock_cortex_deser, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.applications.runner_container_scan.DockerImages"
    ) as mock_docker:
        mock_findings = ["finding1"]
        mock_input_core = {"key": "value"}
        mock_sbom = ["component1"]
        mock_init_engine_sca_rm.return_value = (mock_findings, mock_input_core, mock_sbom)

        dict_args = {"remote_config_repo": "remote_repo", "remote_config_branch": ""}

        findings_list, input_core, sbom_components, tool_run = runner_engine_container(
            dict_args, "CORTEX", "token", None, None
        )

        mock_init_engine_sca_rm.assert_called_once()
        assert findings_list == mock_findings
        assert input_core == mock_input_core
        assert sbom_components == mock_sbom
        assert tool_run is not None
