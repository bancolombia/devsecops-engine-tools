from devsecops_engine_tools.engine_sca.engine_dependencies.src.applications.runner_dependencies_scan import (
    runner_engine_dependencies,
)

from unittest.mock import patch


def test_init_engine_dependencies_xray():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.applications.runner_dependencies_scan.init_engine_dependencies"
    ) as mock_init_engine_dependencies:
        dict_args = {"remote_config_repo": "remote_repo"}
        token = "token"
        config_tool = {
            "ENGINE_DEPENDENCIES": {"ENABLED": "true", "TOOL": "XRAY"},
        }

        result = runner_engine_dependencies(dict_args, config_tool, token, None)

        mock_init_engine_dependencies.assert_any_call


def test_init_engine_dependencies_dependency_check():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.applications.runner_dependencies_scan.init_engine_dependencies"
    ) as mock_init_engine_dependencies:
        dict_args = {"remote_config_repo": "remote_repo"}
        token = "token"
        config_tool = {
            "ENGINE_DEPENDENCIES": {"ENABLED": "true", "TOOL": "DEPENDENCY_CHECK"},
        }

        result = runner_engine_dependencies(dict_args, config_tool, token, None)

        mock_init_engine_dependencies.assert_any_call
