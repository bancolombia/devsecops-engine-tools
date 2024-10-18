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
        self.tool_gateway_mock.TOOL = "jwt"
        self.devops_platform_gateway_mock = Mock(spec=DevopsPlatformGateway)
        self.data_target_mock = Mock()
        self.additional_tools_mock = [self.tool_gateway_mock]

        # Instancia de DastScan
        self.dast_scan = DastScan(
            tool_gateway=self.tool_gateway_mock,
            devops_platform_gateway=self.devops_platform_gateway_mock,
            data_target=self.data_target_mock,
            aditional_tools=self.additional_tools_mock
        )

    @patch('devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan.ConfigTool')
    def test_complete_config_tool(self, config_tool_mock):
        data_file_tool = {"key": "value"}
        exclusions = {"All": {"tool_name": [{"type": "exclusion"}]},
                      "pipeline_name": {"config_tool": [{"type": "exclusion_scope"}]}}
        tool = "tool_name"

        config_tool_instance = config_tool_mock.return_value
        config_tool_instance.exclusions = exclusions
        self.devops_platform_gateway_mock.get_variable.return_value = "pipeline_name"

        config_tool, data_target_config = self.dast_scan.complete_config_tool(data_file_tool, exclusions, tool)

        config_tool_mock.assert_called_once_with(json_data=data_file_tool, tool=tool)
        self.devops_platform_gateway_mock.get_variable.assert_called_once_with("pipeline_name")
        self.assertEqual(config_tool, config_tool_instance)
        self.assertEqual(data_target_config, self.data_target_mock)


    @patch('devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan.ConfigTool')
    @patch('devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan.Exclusions')
    def test_process(self, excluions_mock, config_tool_mock):
        dict_args = {"remote_config_repo": "some_repo",
                     "token_external_checks": "dummie_token"}
        secret_tool = "some_token"
        config_tool = {"TOOL": "tool_name"}

        init_config_tool = {"key": "init_value"}
        exclusions = {"All": {"type": "exclusion"}, "pipeline_name": [{"type": "exclusion_scope"}]}
        finding_list = ["finding1", "finding2"]
        path_file_results = "path/to/results"

        self.devops_platform_gateway_mock.get_remote_config.side_effect = [init_config_tool, exclusions]
        self.tool_gateway_mock.run_tool.return_value = (finding_list, path_file_results)
        self.additional_tools_mock[0].run_tool.return_value = (finding_list, path_file_results)

        excluions_mock.side_effect = lambda **kwargs: kwargs

        result, _ = self.dast_scan.process(dict_args, secret_tool, config_tool)


        self.devops_platform_gateway_mock.get_remote_config.assert_any_call(
            dict_args["remote_config_repo"], "engine_dast/Exclusions.json"
        )

        self.tool_gateway_mock.run_tool.assert_called_with(
            target_data=self.data_target_mock,
            config_tool=config_tool_mock.return_value
        )
        self.additional_tools_mock[0].run_tool.assert_called_with(
            target_data=self.data_target_mock,
            config_tool=config_tool_mock.return_value
        )

        self.assertEqual(result, finding_list)