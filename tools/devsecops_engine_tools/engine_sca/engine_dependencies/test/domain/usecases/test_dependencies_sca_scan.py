from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan import (
    DependenciesScan,
)

from unittest.mock import patch


def test_init():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan.ToolGateway"
    ) as mock_tool_gateway, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan.DeserializatorGateway"
    ) as mock_deserializator_gateway:
        remote_config = {"remote_config_key": "remote_config_value"}
        dict_args = {"key": "arg"}
        exclusion = {"exclusion_key": "exclusion_value"}
        pipeline_name = "pipeline_name"
        to_scan = "path/"
        secret_tool = "secret_tool"
        dependencies_scan_instance = DependenciesScan(
            mock_tool_gateway,
            mock_deserializator_gateway,
            remote_config,
            dict_args,
            exclusion,
            pipeline_name,
            to_scan,
            secret_tool,
        )

        assert dependencies_scan_instance.tool_run == mock_tool_gateway
        assert (
            dependencies_scan_instance.tool_deserializator
            == mock_deserializator_gateway
        )
        assert dependencies_scan_instance.remote_config == remote_config
        assert dependencies_scan_instance.dict_args == dict_args
        assert dependencies_scan_instance.exclusions == exclusion
        assert dependencies_scan_instance.pipeline_name == pipeline_name
        assert dependencies_scan_instance.to_scan == to_scan
        assert dependencies_scan_instance.secret_tool == secret_tool


def test_process():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan.ToolGateway"
    ) as mock_tool_gateway, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan.DeserializatorGateway"
    ) as mock_deserializator_gateway:
        remote_config = {"remote_config_key": "remote_config_value"}
        dict_args = {"key": "arg", "token_engine_dependencies": None}
        exclusion = {"exclusion_key": "exclusion_value"}
        pipeline_name = "pipeline_name"
        to_scan = "path/"
        secret_tool = "secret_tool"
        dependencies_scan_instance = DependenciesScan(
            mock_tool_gateway,
            mock_deserializator_gateway,
            remote_config,
            dict_args,
            exclusion,
            pipeline_name,
            to_scan,
            secret_tool,
        )
        dependencies_scan_instance.process()

        mock_tool_gateway.run_tool_dependencies_sca.assert_called_once_with(
            remote_config,
            dict_args,
            exclusion,
            pipeline_name,
            to_scan,
            secret_tool,
            None,
        )


def test_deserializator():
    with patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan.ToolGateway"
    ) as mock_tool_gateway, patch(
        "devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.usecases.dependencies_sca_scan.DeserializatorGateway"
    ) as mock_deserializator_gateway:
        remote_config = {"remote_config_key": "remote_config_value"}
        dict_args = {"key": "arg"}
        exclusion = {"exclusion_key": "exclusion_value"}
        pipeline_name = "pipeline_name"
        to_scan = "path/"
        token = "token"
        dependencies_scanned = "scanned.json"

        dependencies_scan_instance = DependenciesScan(
            mock_tool_gateway,
            mock_deserializator_gateway,
            remote_config,
            dict_args,
            exclusion,
            pipeline_name,
            to_scan,
            token,
        )
        dependencies_scan_instance.deserializator(dependencies_scanned)

        mock_deserializator_gateway.get_list_findings.assert_called_once_with(
            dependencies_scanned
        )
