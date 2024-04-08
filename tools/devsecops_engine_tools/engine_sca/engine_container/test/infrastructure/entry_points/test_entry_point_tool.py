from unittest import mock
from unittest.mock import MagicMock
from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool import init_engine_sca_rm
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold


@mock.patch('devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.ContainerScaScan')

@mock.patch('devsecops_engine_tools.engine_sca.engine_container.src.domain.usecases.handle_remote_config_patterns.HandleRemoteConfigPatterns.ignore_analysis_pattern')

def test_init_engine_sca_rm(mock_container_scan,mock_remote_config):
    # Mock the output

    input_core = InputCore(
        totalized_exclusions=[],
        threshold_defined=Threshold,
        path_file_results=None,
        custom_message_break_build="If you have doubts",
        scope_pipeline="pipeline",
        stage_pipeline="Release",
    )

    mock_container_scan.return_value.process.return_value = [] , input_core
    mock_remote_config.return_value.process.return_value = False
    # Define the input arguments
    tool_run = MagicMock()
    tool_remote = MagicMock()
    tool_images = MagicMock()
    tool_deseralizator = MagicMock()
    dict_args = {"remote_config_repo": "repo_value"} 
    token = ""
    tool = "prisma"
    tool_remote.ignore_analysis_pattern.return_value = False
    tool_remote.get_remote_config.return_value = {
            "IGNORE_SEARCH_PATTERN": "(.*_demo0|.*_ACE11_CER)",
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 999,
                    "High": 999,
                    "Medium": 999,
                    "Low": 999
                },
                "COMPLIANCE": {
                    "Critical": 1
                },
                "CVE": [
                    "CVE-2023-29405",
                    "CVE-2023-24538"
                ]
            },
            "MESSAGE_INFO_SCA_RM": "If you have doubts"
        }
    #Call the function
    [] , input_output = init_engine_sca_rm(tool_run, tool_remote, tool_images, tool_deseralizator, dict_args, token,tool)

    mock_container_scan.assert_called()
