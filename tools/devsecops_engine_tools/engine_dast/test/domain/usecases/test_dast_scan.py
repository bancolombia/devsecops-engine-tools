import unittest
from unittest.mock import Mock, patch, ANY
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
        self.remote_config_source_gateway = Mock(spec=DevopsPlatformGateway)
        self.data_target_mock = Mock()
        self.additional_tools_mock = [self.tool_gateway_mock]

        # Instancia de DastScan
        self.dast_scan = DastScan(
            tool_gateway=self.tool_gateway_mock,
            devops_platform_gateway=self.devops_platform_gateway_mock,
            remote_config_source_gateway=self.remote_config_source_gateway,
            data_target=self.data_target_mock,
            aditional_tools=self.additional_tools_mock
        )

    def test_complete_config_tool(self):
        data_file_tool = {
            "tool_name": {},
            "key": "value"
        }
        exclusions = {
            "All": {
                "tool_name": [
                    {"type": "exclusion"}
                ]
            },
            "pipeline_name": {
                "tool_name": [
                    {"type": "exclusion_scope"}
                ]
            }
        }
        tool = "tool_name"

        config_tool_instance = {
            "key": "value",
            "tool_name": {},
            "EXCLUSIONS": exclusions,
            "EXCLUSIONS_ALL": exclusions["All"]["tool_name"],
            "EXCLUSIONS_SCOPE": exclusions["pipeline_name"]["tool_name"],
            "SCOPE_PIPELINE": "pipeline_name"
        }

        self.data_target_mock.concurrency = 25
        self.data_target_mock.rate_limit = 150
        self.data_target_mock.response_size = 1048576
        self.data_target_mock.bulk_size = 25
        self.data_target_mock.timeout = 10

        self.devops_platform_gateway_mock.get_variable.return_value = "pipeline_name"
        config_tool, data_target_config = self.dast_scan.complete_config_tool(data_file_tool, exclusions, tool)
        self.devops_platform_gateway_mock.get_variable.assert_called_once_with("pipeline_name")
        self.assertEqual(config_tool, config_tool_instance)
        self.assertEqual(data_target_config, self.data_target_mock)


    @patch('devsecops_engine_tools.engine_dast.src.domain.usecases.dast_scan.Exclusions')
    def test_process(self, exclusions_mock):
        dict_args = {
            "remote_config_repo": "some_repo",
            "token_external_checks": "dummie_token"
        }
        secret_tool = "some_token"
        config_tool = {"TOOL": "tool_name"}

        init_config_tool = {
            "tool_name": {},
            "key": "init_value",
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 1, 
                    "High": 8, 
                    "Medium": 10, 
                    "Low": 15
                },
                "COMPLIANCE": {
                    "Critical": 1
                }
            }
        }
        
        exclusions = {"All": {"type": "exclusion"}, "pipeline_name": [{"type": "exclusion_scope"}]}
        finding_list = ["finding1", "finding2"]
        path_file_results = "path/to/results"

        self.remote_config_source_gateway.get_remote_config.side_effect = [init_config_tool, exclusions]
        self.tool_gateway_mock.run_tool.return_value = (finding_list, path_file_results)
        self.additional_tools_mock[0].run_tool.return_value = (finding_list, path_file_results)

        exclusions_mock.side_effect = lambda **kwargs: kwargs

        result, _ = self.dast_scan.process(dict_args, secret_tool, config_tool)

        self.remote_config_source_gateway.get_remote_config.assert_any_call(
            dict_args["remote_config_repo"], "engine_dast/Exclusions.json"
        )

        self.tool_gateway_mock.run_tool.assert_called_with(
            target_data=self.data_target_mock,
            config_tool=ANY
        )
        self.additional_tools_mock[0].run_tool.assert_called_with(
            target_data=self.data_target_mock,
            config_tool=ANY
        )

        self.assertEqual(result, finding_list)