from unittest.mock import Mock, patch

from devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool import (
    init_engine_sca_rm,
)


def test_successful_scan_loads_cross_approval_exclusions():
    remote_config = {
        "IGNORE_SEARCH_PATTERN": "^skip$",
        "CROSS_APPROVAL_EXCLUSIONS": {
            "ENABLED": True,
        },
    }
    exclusions = {}
    core_config_tool = {
        "VULNERABILITY_MANAGER": {
            "DEFECT_DOJO": {"HOST_DEFECT_DOJO": "https://dojo.example"}
        }
    }
    remote_config_source = Mock()
    remote_config_source.get_remote_config.side_effect = [
        remote_config,
        exclusions,
        core_config_tool,
    ]
    tool_remote = Mock()
    tool_remote.get_variable.side_effect = {
        "pipeline_name": "example_pipeline",
        "branch_tag": "main",
        "stage": "dev",
    }.get
    dict_args = {
        "remote_config_repo": "remote_repo",
        "remote_config_branch": "main",
        "image_to_scan": "image:latest",
        "token_engine_container": "engine-token",
        "context": "false",
        "docker_address": "",
    }
    cross_approval_exclusions = [Mock()]

    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.ContainerScaScan"
    ) as container_scan, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.SetInputCore"
    ) as set_input_core, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.DefectDojoCrossApprovalAdapter"
    ) as adapter, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.GetCrossApprovalExclusions"
    ) as get_cross_approval_exclusions:
        container_scan.return_value.process.return_value = (
            "scan-result.json",
            None,
            None,
        )
        get_cross_approval_exclusions.return_value.execute.return_value = (
            cross_approval_exclusions
        )

        init_engine_sca_rm(
            Mock(),
            tool_remote,
            remote_config_source,
            Mock(),
            Mock(),
            dict_args,
            {"token_defect_dojo": "dojo-token"},
            "PRISMA",
        )

    adapter.assert_called_once_with()
    remote_config_source.get_remote_config.assert_any_call(
        "remote_repo", "engine_core/ConfigTool.json", "main"
    )
    get_cross_approval_exclusions.return_value.execute.assert_called_once_with(
        remote_config,
        dict_args,
        {"token_defect_dojo": "dojo-token"},
        "https://dojo.example",
    )
    assert container_scan.call_args.kwargs["cross_approval_exclusions"] == (
        cross_approval_exclusions
    )
    set_input_core.assert_called_once_with(
        remote_config,
        exclusions,
        "example_pipeline",
        "PRISMA",
        "dev",
        cross_approval_exclusions,
    )


def test_disabled_cross_approval_does_not_fetch_core_config():
    remote_config = {
        "IGNORE_SEARCH_PATTERN": "^skip$",
        "CROSS_APPROVAL_EXCLUSIONS": {"ENABLED": False},
    }
    exclusions = {}
    remote_config_source = Mock()
    remote_config_source.get_remote_config.side_effect = [remote_config, exclusions]
    tool_remote = Mock()
    tool_remote.get_variable.side_effect = {
        "pipeline_name": "example_pipeline",
        "branch_tag": "main",
        "stage": "dev",
    }.get
    dict_args = {
        "remote_config_repo": "remote_repo",
        "remote_config_branch": "main",
        "image_to_scan": "image:latest",
        "token_engine_container": "engine-token",
        "context": "false",
        "docker_address": "",
    }

    with patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.ContainerScaScan"
    ) as container_scan, patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.SetInputCore"
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.DefectDojoCrossApprovalAdapter"
    ), patch(
        "devsecops_engine_tools.engine_sca.engine_container.src.infrastructure.entry_points.entry_point_tool.GetCrossApprovalExclusions"
    ) as get_cross_approval_exclusions:
        container_scan.return_value.process.return_value = (
            "scan-result.json",
            None,
            None,
        )

        init_engine_sca_rm(
            Mock(),
            tool_remote,
            remote_config_source,
            Mock(),
            Mock(),
            dict_args,
            {"token_defect_dojo": "dojo-token"},
            "PRISMA",
        )

    assert remote_config_source.get_remote_config.call_count == 2
    get_cross_approval_exclusions.return_value.execute.assert_called_once_with(
        remote_config, dict_args, {"token_defect_dojo": "dojo-token"}, None
    )