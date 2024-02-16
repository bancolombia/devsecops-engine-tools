from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_dependencies,
)

import pytest
from unittest.mock import mock_open, patch, Mock


def test_init_engine_dependencies():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan.DependenciesScan"
    ) as mock_dependencies_scan, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.set_input_core.SetInputCore"
    ) as mock_set_input_core, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.handle_remote_config_patterns.HandleRemoteConfigPatterns"
    ) as mock_handle_remote_config_patterns, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_manager_scan.XrayScan"
    ) as mock_tool_run, patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.azure.azure_devops.AzureDevops"
    ) as mock_tool_remote, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.xray_tool.xray_deserialize_output.XrayDeserializator"
    ) as mock_tool_deserializator:
        dict_args = {"remote_config_repo": "remote_repo"}
        token = "token"
        tool = "tool"
        mock_tool_remote.get_remote_config.return_value = {
            "XRAY": {"CLI_VERSION": "2.52.8"},
            "IGNORE_ANALYSIS_PATTERN": "(.*_test|Template_.*)",
            "BYPASS_ARCHIVE_LIMITS": "(pipeline_test1|pipeline_test2)",
            "WORK_DIR_DIFFERENT_FLAG": "SCRIPTS_WEB_MR",
            "REGEX_EXPRESSION_EXTENSIONS": "\\.(jar|ear|war)$",
            "MESSAGE_INFO_SCA": "If you have doubts, visit 'Análisis de composición del software (SCA)' in Azure DevOps Wiki.",
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 999,
                    "High": 999,
                    "Medium": 999,
                    "Low": 999,
                },
                "COMPLIANCE": {"Critical": 1},
            },
            "ENGINE_DEPENDENCIES": {"ENABLED": "true"},
            "NU0000002_DevSecOps_Test": {
                "XRAY": [
                    {
                        "id": "XRAY-129823",
                        "cve_id": "",
                        "expired_date": "21092022",
                        "create_date": "24012023",
                        "hu": "",
                    },
                    {
                        "id": "XRAY-75464",
                        "cve_id": "",
                        "expired_date": "21092022",
                        "create_date": "24012023",
                        "hu": "",
                    },
                ],
                "SKIP_FILES": {
                    "files": ["war"],
                    "create_date": "24012023",
                    "expired_date": "21092022",
                    "hu": "",
                },
                "SKIP_TOOL": {
                    "create_date": "24012023",
                    "expired_date": "21092024",
                    "hu": "",
                },
            },
        }
        mock_tool_remote.get_variable.return_value = "variable"
        mock_handle_remote_config_patterns.process_handle_working_directory.return_value = (
            "working_dir"
        )
        mock_handle_remote_config_patterns.process_handle_skip_tool.return_value = True
        mock_handle_remote_config_patterns.process_handle_analysis_pattern.return_value = (
            True
        )
        mock_handle_remote_config_patterns.process_handle_bypass_expression.return_value = (
            True
        )
        mock_handle_remote_config_patterns.process_handle_excluded_files.return_value = (
            "pattern"
        )
        mock_dependencies_scan.process.return_value = "scan_result.json"
        mock_dependencies_scan.deserializator.return_value = "deserialized"
        mock_set_input_core.set_input_core.return_value = "input_core"
        init_engine_dependencies_instance = init_engine_dependencies(
            mock_tool_run,
            mock_tool_remote,
            mock_tool_deserializator,
            dict_args,
            token,
            tool,
        )

        mock_set_input_core.set_input_core.assert_any_call
