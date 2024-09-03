import unittest
from unittest.mock import Mock, patch
from devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan import (
    DastScan,
    ToolGateway,
    DevopsPlatformGateway
)
class TestDastScan(unittest.TestCase):

    def setUp(self):
        # Mocks
        self.tool_gateway_mock = Mock(spec=ToolGateway)
        self.devops_platform_gateway_mock = Mock(spec=DevopsPlatformGateway)
        self.data_target_mock = Mock()
        self.additional_tools_mock = [Mock(spec=ToolGateway)]

        # Instancia de DastScan
        self.dast_scan = DastScan(
            tool_gateway=self.tool_gateway_mock,
            devops_platform_gateway=self.devops_platform_gateway_mock,
            data_target=self.data_target_mock,
            aditional_tools=self.additional_tools_mock
        )

    @patch('devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan.ConfigTool')
    def test_complete_config_tool(self, ConfigToolMock):
        data_file_tool = {"key": "value"}
        exclusions = {"All": {"tool_name": [{"type": "exclusion"}]},
                      "pipeline_name": {"config_tool": [{"type": "exclusion_scope"}]}}
        tool = "tool_name"

        config_tool_instance = ConfigToolMock.return_value
        config_tool_instance.exclusions = exclusions
        self.devops_platform_gateway_mock.get_variable.return_value = "pipeline_name"

        config_tool, data_target_config = self.dast_scan.complete_config_tool(data_file_tool, exclusions, tool)

        ConfigToolMock.assert_called_once_with(json_data=data_file_tool, tool=tool)
        self.devops_platform_gateway_mock.get_variable.assert_called_once_with("pipeline_name")
        self.assertEqual(config_tool, config_tool_instance)
        self.assertEqual(data_target_config, self.data_target_mock)

    @patch('devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan.InputCore')
    @patch('devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan.ConfigTool')
    @patch('devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan.Exclusions')
    def test_process(self, ExclusionsMock, ConfigToolMock, InputCoreMock):
        dict_args = {"remote_config_repo": "some_repo"}
        dast_token = "some_token"
        config_tool = {"ENGINE_DAST": {"TOOL": "tool_name"}}

        init_config_tool = {"key": "init_value"}
        exclusions = {"All": {"type": "exclusion"}, "pipeline_name": [{"type": "exclusion_scope"}]}
        finding_list = ["finding1", "finding2"]
        path_file_results = "path/to/results"
        extra_finding_list = ["extra_finding1"]

        self.devops_platform_gateway_mock.get_remote_config.side_effect = [init_config_tool, exclusions]
        self.tool_gateway_mock.run_tool.return_value = (finding_list, path_file_results)
        self.additional_tools_mock[0].run_tool.return_value = extra_finding_list

        ExclusionsMock.side_effect = lambda **kwargs: kwargs

        result, input_core = self.dast_scan.process(dict_args, dast_token, config_tool)

        self.devops_platform_gateway_mock.get_remote_config.assert_any_call(
            dict_args["remote_config_repo"], "engine_dast/configTool.json"
        )
        self.devops_platform_gateway_mock.get_remote_config.assert_any_call(
            dict_args["remote_config_repo"], "engine_dast/Exclusions.json"
        )

        self.tool_gateway_mock.run_tool.assert_called_once_with(
            target_data=self.data_target_mock,
            config_tool=ConfigToolMock.return_value,
            token=dast_token,
        )
        self.additional_tools_mock[0].run_tool.assert_called_once_with(
            target_data=self.data_target_mock,
            config_tool=ConfigToolMock.return_value
        )

        self.assertEqual(result, finding_list )