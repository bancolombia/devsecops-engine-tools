import unittest
from unittest.mock import MagicMock, Mock
from unittest import mock
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
from devsecops_engine_tools.engine_core.src.domain.model.component import Component
from devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan import (
    HandleScan,
)
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionVulnerabilityManagement,
    ExceptionFindingsExcepted,
)


class TestHandleScan(unittest.TestCase):
    def setUp(self):
        self.vulnerability_management = MagicMock()
        self.secrets_manager_gateway = MagicMock()
        self.devops_platform_gateway = MagicMock()
        self.remote_config_source_gateway = MagicMock()
        self.sbom_gateway = MagicMock()
        self.context_extraction_gateway = MagicMock()
        self.threshold = Threshold(
            {
                "VULNERABILITY": {
                    "Critical": 5,
                    "High": 8,
                    "Medium": 10,
                    "Low": 15,
                },
                "COMPLIANCE": {"Critical": 1},
                "PRIORITY": {
                    "Very Critical": 1,
                    "Critical": 3,
                    "High": 5,
                    "Medium Low": 15
                }
            }
        )
        self.risk_score_gateway = mock.Mock()
        self.license_manager_gateway = MagicMock()
        self.handle_scan = HandleScan(
            self.vulnerability_management,
            self.secrets_manager_gateway,
            self.devops_platform_gateway,
            self.remote_config_source_gateway,
            self.sbom_gateway,
            self.risk_score_gateway,
            self.context_extraction_gateway,
            self.license_manager_gateway,
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_iac"
    )
    def test_process_with_engine_iac(self, mock_runner_engine_iac):
        dict_args = {
            "use_secrets_manager": "true",
            "module": "engine_iac",
            "use_vulnerability_management": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": ""
        }
        config_tool = {"VULNERABILITY_MANAGER": {"ENABLED": True}, "ENGINE_IAC": {"ENABLED": "true", "TOOL": "tool"}}
        secret_tool = "some_secret"
        self.secrets_manager_gateway.get_secret.return_value = secret_tool
        self.devops_platform_gateway.get_variable.return_value = "dev"

        # Mock the runner_engine_iac function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_iac.return_value = findings_list, input_core, mock_tool_gateway

        # Mock the send_vulnerability_management method
        self.vulnerability_management.send_vulnerability_management = MagicMock()

        # Mock the get_findings_excepted method
        self.vulnerability_management.get_findings_excepted = MagicMock()
        self.vulnerability_management.get_findings_excepted.return_value = []

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        self.secrets_manager_gateway.get_secret.assert_called_once_with(config_tool)
        mock_runner_engine_iac.assert_called_once_with(
            dict_args,
            config_tool["ENGINE_IAC"]["TOOL"],
            secret_tool,
            self.devops_platform_gateway,
            self.remote_config_source_gateway,
            "dev",
        )
        self.vulnerability_management.send_vulnerability_management.assert_called_once()
        self.vulnerability_management.get_findings_excepted.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_iac"
    )
    def test_process_with_engine_iac_error(self, mock_runner_engine_iac):
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_iac",
            "use_vulnerability_management": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": ""
        }
        config_tool = {"VULNERABILITY_MANAGER": {"ENABLED": True}, "ENGINE_IAC": {"ENABLED": "true", "TOOL": "tool"}}

        # Mock the runner_engine_iac function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=Threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_iac.return_value = findings_list, input_core, mock_tool_gateway

        # Mock the send_vulnerability_management method
        self.vulnerability_management.send_vulnerability_management.side_effect = (
            ExceptionVulnerabilityManagement("Simulated error")
        )

        # Mock the get_findings_excepted method
        self.vulnerability_management.get_findings_excepted.side_effect = (
            ExceptionFindingsExcepted("Simulated error")
        )

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)

        self.vulnerability_management.send_vulnerability_management.assert_called_once()
        self.vulnerability_management.get_findings_excepted.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_container"
    )
    def test_process_with_engine_container(self, mock_runner_engine_container):
        dict_args = {
            "use_secrets_manager": "true",
            "module": "engine_container",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
            "use_vulnerability_management": "true",
        }
        config_tool = {"BREAK_BUILD_MANAGER":{"MODEL": "severity","CLASSIFICATION": ["critical", "high", "medium", "low"]},"ENGINE_CONTAINER": {"ENABLED": "true", "TOOL": "tool"}}
        secret_tool = {"token_prisma_cloud": "test"}
        self.secrets_manager_gateway.get_secret.return_value = secret_tool

        # Mock the runner_engine_iac function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=Threshold(
                {
                    "VULNERABILITY": {
                        "Critical": 5,
                        "High": 8,
                        "Medium": 10,
                        "Low": 15,
                    },
                    "COMPLIANCE": {"Critical": 1},
                    "PRIORITY": {
                        "Very Critical": 1,
                        "Critical": 3,
                        "High": 5,
                        "Medium Low": 15
                    },
                    "QUALITY_VULNERABILITY_MANAGEMENT": {
                        "PTS": [
                            {
                                "PT1": {
                                    "APPS": ["pipeline", "app2", "app3"],
                                    "PROFILE": "STRONG",
                                    "PROFILE_PRIORITY": "STRONG_PRIORITY"
                                }
                            },
                            {
                                "PT2": {
                                    "APPS": "ALL",
                                    "PROFILE": "MODERATE",
                                }
                            },
                        ],
                        "STRONG": {"Critical": 0, "High": 0, "Medium": 5, "Low": 15},
                        "MODERATE": {"Critical": 1, "High": 3, "Medium": 5, "Low": 15},
                        "STRONG_PRIORITY": {"Very Critical": 0, "Critical": 0, "High": 5, "Medium Low": 15},
                        "MODERATE_PRIORITY": {"Very Critical": 1, "Critical": 3, "High": 5, "Medium Low": 15},
                    },
                }
            ),
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        component_list = [Component("component1", "version1"), Component("component2", "version2")]
        mock_tool_gateway = MagicMock()

        mock_runner_engine_container.return_value = findings_list, input_core, component_list, mock_tool_gateway
        mock_product_type = Mock()
        mock_product_type.name = "PT1"
        self.vulnerability_management.get_product_type_pipeline.return_value = mock_product_type

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        self.secrets_manager_gateway.get_secret.assert_called_once_with(config_tool)

    @mock.patch("devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_dast")
    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data='''{
        "endpoint": "https://example.com",
        "operations": [
            {
                "operation": {
                    "headers": {
                        "accept": "/"
                    },
                    "method": "POST",
                    "path": "/example_path",
                    "security_auth": {
                        "type": "jwt"
                    }
                }
            }
        ]
    }''')
    def test_process_with_engine_dast(self, mock_open, mock_runner_engine_dast):
        dict_args = {
            "use_secrets_manager": "true",
            "module": "engine_dast",
            "dast_file_path": "example_dast.json",
            "use_vulnerability_management": "true",
            "remote_config_repo": "dummie_repo"
        }
        secret_tool = {"github_token": "example_token"}
        self.secrets_manager_gateway.get_secret.return_value = secret_tool
        config_tool = {"VULNERABILITY_MANAGER": {"ENABLED": False},"ENGINE_DAST":{"ENABLED": "true", "TOOL": "NUCLEI"}}
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        # Simulates runner_engine_dast return
        mock_runner_engine_dast.return_value = (["finding1", "finding2"], input_core)
        # Call process method
        result_findings_list, result_input_core = self.handle_scan.process(dict_args, config_tool)
        # Verifies mock have been called correctly
        mock_runner_engine_dast.assert_called_once_with(
            dict_args, config_tool["ENGINE_DAST"], secret_tool, self.devops_platform_gateway, self.remote_config_source_gateway
        )
        # Verifica los resultados devueltos
        self.assertEqual(result_findings_list, ["finding1", "finding2"])
        self.assertEqual(result_input_core, input_core)

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_secret_scan"
    )
    def test_process_with_engine_secret(self, mock_runner_secret_scan):
        dict_args = {
            "use_secrets_manager": "true",
            "module": "engine_secret",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
            "use_vulnerability_management": "true",
        }
        config_tool = {"ENGINE_SECRET": {"ENABLED": "true", "TOOL": "trufflehog"}}
        secret_tool = {"token_github_external_rules": "test"}
        self.secrets_manager_gateway.get_secret.return_value = secret_tool

        # Mock the runner_engine_secret function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_runner_secret_scan.return_value = findings_list, input_core

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        mock_runner_secret_scan.assert_called_once_with(
            dict_args, config_tool["ENGINE_SECRET"]["TOOL"], self.devops_platform_gateway, self.remote_config_source_gateway, secret_tool
        )

    @mock.patch("devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_secret_scan")
    def test_process_with_engine_secret_without_secret_manager(self, mock_runner_secret_scan):
        dict_args = {
            "use_secrets_manager": "true",
            "module": "engine_secret",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
            "use_vulnerability_management": "true",
        }
        config_tool = {"ENGINE_SECRET": {"ENABLED": "true", "TOOL": "trufflehog"}}
        secret_tool = None
        self.secrets_manager_gateway.get_secret.return_value = secret_tool

        # Mock the runner_engine_secret function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_runner_secret_scan.return_value = findings_list, input_core

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        mock_runner_secret_scan.assert_called_once_with(
            dict_args, config_tool["ENGINE_SECRET"]["TOOL"], self.devops_platform_gateway, secret_tool
        )

    @mock.patch("devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_secret_scan")
    def test_process_with_engine_secret_without_secret_manager(self, mock_runner_secret_scan):
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_secret",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
            "use_vulnerability_management": "true",
        }
        config_tool = {"ENGINE_SECRET": {"ENABLED": "true", "TOOL": "trufflehog"}}
        secret_tool = None
        self.secrets_manager_gateway.get_secret.return_value = secret_tool

        # Mock the runner_engine_secret function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_runner_secret_scan.return_value = findings_list, input_core

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        mock_runner_secret_scan.assert_called_once_with(
            dict_args, config_tool["ENGINE_SECRET"]["TOOL"], self.devops_platform_gateway, self.remote_config_source_gateway, secret_tool
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_dependencies"
    )
    def test_process_with_engine_dependencies(self, mock_runner_engine_dependencies):
        dict_args = {
            "use_secrets_manager": "true",
            "module": "engine_dependencies",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
            "use_vulnerability_management": "true",
        }
        config_tool = {
            "VULNERABILITY_MANAGER": {"ENABLED": False},
            "ENGINE_DEPENDENCIES": "some_config",
            "ENGINE_DEPENDENCIES": {"TOOL": "some_tool"},
        }
        secret_tool = {"token_xray": "test"}
        self.secrets_manager_gateway.get_secret.return_value = secret_tool

        # Mock the runner_engine_dependencies function and its return values
        findings_list = ["finding1", "finding2"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_dependencies.return_value = findings_list, input_core, None, mock_tool_gateway

        # Call the process method
        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        # Assert the expected values
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        self.secrets_manager_gateway.get_secret.assert_called_once_with(config_tool)
        mock_runner_engine_dependencies.assert_called_once_with(
            dict_args, config_tool, secret_tool, self.devops_platform_gateway, self.remote_config_source_gateway, self.sbom_gateway, self.license_manager_gateway
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_iac"
    )
    def test_context_extraction_invoked_when_enabled(self, mock_runner_engine_iac):
        """Test that context extraction is invoked when context='true'"""
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_iac",
            "use_vulnerability_management": "false",
            "context": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": ""
        }
        config_tool = {"ENGINE_IAC": {"ENABLED": "true", "TOOL": "tool"}}
        
        findings_list = ["finding1"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file/results.json",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_iac.return_value = findings_list, input_core, mock_tool_gateway
        
        # Mock context extraction gateway
        context_extraction_gateway = MagicMock()
        self.handle_scan.context_extraction_gateway = context_extraction_gateway
        
        # Call the process method
        self.handle_scan.process(dict_args, config_tool)
        
        # Assert context extraction was called with correct parameters
        context_extraction_gateway.extract_context.assert_called_once_with(
            module_name="engine_iac",
            path_file_results="test/file/results.json",
            remote_config=config_tool["ENGINE_IAC"],
            config_tool=config_tool,
            print_to_logs=True
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_container"
    )
    def test_context_extraction_invoked_with_print_disabled_when_false(self, mock_runner_engine_container):
        """Test that context extraction is still invoked when context='false', but print_to_logs is disabled"""
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_container",
            "use_vulnerability_management": "false",
            "context": "false",
            "remote_config_repo": "test_repo",
            "remote_config_branch": ""
        }
        config_tool = {"ENGINE_CONTAINER": {"ENABLED": "true", "TOOL": "tool"}}
        
        findings_list = ["finding1"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file/results.json",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_container.return_value = findings_list, input_core, [], mock_tool_gateway
        
        # Mock context extraction gateway
        context_extraction_gateway = MagicMock()
        self.handle_scan.context_extraction_gateway = context_extraction_gateway
        
        # Call the process method
        self.handle_scan.process(dict_args, config_tool)
        
        # Assert context extraction was called but printing to logs was disabled
        context_extraction_gateway.extract_context.assert_called_once_with(
            module_name="engine_container",
            path_file_results="test/file/results.json",
            remote_config=config_tool["ENGINE_CONTAINER"],
            config_tool=config_tool,
            print_to_logs=False
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_dependencies"
    )
    def test_context_extraction_invoked_with_print_disabled_when_undefined(self, mock_runner_engine_dependencies):
        """Test that context extraction is still invoked when context is not defined, with print_to_logs disabled"""
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_dependencies",
            "use_vulnerability_management": "false",
            "remote_config_repo": "test_repo",
            "remote_config_branch": ""
            # Note: 'context' key is not present
        }
        config_tool = {"ENGINE_DEPENDENCIES": {"TOOL": "tool"}}
        
        findings_list = ["finding1"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file/results.json",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_dependencies.return_value = findings_list, input_core, [], mock_tool_gateway
        
        # Mock context extraction gateway
        context_extraction_gateway = MagicMock()
        self.handle_scan.context_extraction_gateway = context_extraction_gateway
        
        # Call the process method
        self.handle_scan.process(dict_args, config_tool)
        
        # Assert context extraction was called but printing to logs was disabled
        context_extraction_gateway.extract_context.assert_called_once_with(
            module_name="engine_dependencies",
            path_file_results="test/file/results.json",
            remote_config=config_tool["ENGINE_DEPENDENCIES"],
            config_tool=config_tool,
            print_to_logs=False
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_iac"
    )
    def test_execution_continues_if_context_extraction_fails(self, mock_runner_engine_iac):
        """Test that execution continues if context extraction fails"""
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_iac",
            "use_vulnerability_management": "false",
            "context": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": ""
        }
        config_tool = {"ENGINE_IAC": {"ENABLED": "true", "TOOL": "tool"}}
        
        findings_list = ["finding1"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file/results.json",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_iac.return_value = findings_list, input_core, mock_tool_gateway
        
        # Mock context extraction gateway to raise an exception
        context_extraction_gateway = MagicMock()
        context_extraction_gateway.extract_context.side_effect = Exception("Context extraction failed")
        self.handle_scan.context_extraction_gateway = context_extraction_gateway
        
        # Call the process method - should not raise exception
        result_findings_list, result_input_core = self.handle_scan.process(dict_args, config_tool)
        
        # Assert execution continued and returned results
        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        context_extraction_gateway.extract_context.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_container"
    )
    def test_context_extraction_order_correct(self, mock_runner_engine_container):
        """Test that context extraction occurs after runner and before vulnerability management"""
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_container",
            "use_vulnerability_management": "true",
            "context": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": ""
        }
        config_tool = {"ENGINE_CONTAINER": {"ENABLED": "true", "TOOL": "tool"}}
        
        findings_list = ["finding1"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="test/file/results.json",
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_container.return_value = findings_list, input_core, [], mock_tool_gateway
        
        # Mock context extraction gateway and vulnerability management
        context_extraction_gateway = MagicMock()
        self.handle_scan.context_extraction_gateway = context_extraction_gateway
        self.vulnerability_management.get_findings_excepted.return_value = []
        
        # Track call order
        call_order = []
        mock_runner_engine_container.side_effect = lambda *args, **kwargs: (
            call_order.append("runner"),
            findings_list,
            input_core,
            [],
            mock_tool_gateway
        )[1:]
        context_extraction_gateway.extract_context.side_effect = lambda *args, **kwargs: call_order.append("context_extraction")
        self.vulnerability_management.send_vulnerability_management.side_effect = lambda *args, **kwargs: call_order.append("vulnerability_management")
        
        # Call the process method
        self.handle_scan.process(dict_args, config_tool)
        
        # Assert correct order: runner -> context_extraction -> vulnerability_management
        self.assertEqual(call_order, ["runner", "context_extraction", "vulnerability_management"])

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_code"
    )
    def test_process_with_engine_code(self, mock_runner_engine_code):
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_code",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
            "use_vulnerability_management": "false",
        }
        config_tool = {"ENGINE_CODE": {"ENABLED": "true", "TOOL": "bearer"}}

        findings_list = ["finding1"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results=None,
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_runner_engine_code.return_value = findings_list, input_core

        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        mock_runner_engine_code.assert_called_once_with(
            dict_args,
            config_tool["ENGINE_CODE"]["TOOL"],
            self.devops_platform_gateway,
            self.remote_config_source_gateway,
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_function"
    )
    def test_process_with_engine_function(self, mock_runner_engine_function):
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_function",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
            "use_vulnerability_management": "false",
        }
        config_tool = {"ENGINE_FUNCTION": {"ENABLED": "true", "TOOL": "prisma"}}

        findings_list = ["finding1"]
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results=None,
            custom_message_break_build="message",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_runner_engine_function.return_value = findings_list, input_core

        result_findings_list, result_input_core = self.handle_scan.process(
            dict_args, config_tool
        )

        self.assertEqual(result_findings_list, findings_list)
        self.assertEqual(result_input_core, input_core)
        mock_runner_engine_function.assert_called_once_with(
            dict_args,
            config_tool["ENGINE_FUNCTION"],
            None,
            self.devops_platform_gateway,
            self.remote_config_source_gateway,
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_container"
    )
    def test_use_vulnerability_management_sends_sbom_when_branch_matches(
        self, mock_runner_engine_container
    ):
        """Covers the send_sbom_components branch when sbom_components + branch_filter matches."""
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_container",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
            "use_vulnerability_management": "true",
        }
        config_tool = {
            "VULNERABILITY_MANAGER": {
                "BRANCH_FILTER": ["main"]
            },
            "ENGINE_CONTAINER": {"ENABLED": "true", "TOOL": "trivy"},
        }

        findings_list = []
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="some/file",
            custom_message_break_build="",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        from devsecops_engine_tools.engine_core.src.domain.model.component import Component
        sbom_components = [Component("comp1", "1.0")]
        mock_tool_gateway = MagicMock()
        mock_runner_engine_container.return_value = findings_list, input_core, sbom_components, mock_tool_gateway

        self.devops_platform_gateway.get_variable.return_value = "main"
        self.vulnerability_management.get_findings_excepted.return_value = []

        self.handle_scan.process(dict_args, config_tool)

        self.vulnerability_management.send_sbom_components.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_iac"
    )
    def test_update_threshold_cve_called_for_default_threshold(self, mock_runner_engine_iac):
        """Covers _update_threshold_cve when threshold name is 'default'."""
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_iac",
            "use_vulnerability_management": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
        }
        config_tool = {"ENGINE_IAC": {"ENABLED": "true", "TOOL": "checkov"}}
        findings_list = []
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="some/file",
            custom_message_break_build="",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_iac.return_value = findings_list, input_core, mock_tool_gateway
        self.vulnerability_management.get_findings_excepted.return_value = []
        self.vulnerability_management.get_black_list.return_value = []

        self.handle_scan.process(dict_args, config_tool)

        self.vulnerability_management.get_black_list.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_container"
    )
    def test_define_threshold_quality_vuln_with_matching_pt(self, mock_runner_engine_container):
        """Covers _define_threshold_quality_vuln when quality_vulnerability_management is set
        and a matching product type is found (model=severity branch)."""
        from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
        quality_threshold = Threshold(
            {
                "VULNERABILITY": {"Critical": 5, "High": 8, "Medium": 10, "Low": 15},
                "COMPLIANCE": {"Critical": 1},
                "PRIORITY": {"Very Critical": 1, "Critical": 3, "High": 5, "Medium Low": 15},
                "QUALITY_VULNERABILITY_MANAGEMENT": {
                    "PTS": [
                        {
                            "PT1": {
                                "APPS": ["pipeline"],
                                "PROFILE": "STRONG",
                                "PROFILE_PRIORITY": "STRONG_PRIORITY",
                            }
                        }
                    ],
                    "STRONG": {"Critical": 0, "High": 0, "Medium": 5, "Low": 15},
                    "STRONG_PRIORITY": {"Very Critical": 0, "Critical": 0, "High": 5, "Medium Low": 15},
                },
            }
        )
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_container",
            "use_vulnerability_management": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
        }
        config_tool = {
            "VULNERABILITY_MANAGER": {},
            "ENGINE_CONTAINER": {"ENABLED": "true", "TOOL": "trivy"},
            "BREAK_BUILD_MANAGER": {"MODEL": "severity"},
        }
        findings_list = []
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=quality_threshold,
            path_file_results="some/file",
            custom_message_break_build="",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_container.return_value = findings_list, input_core, [], mock_tool_gateway

        mock_product_type = Mock()
        mock_product_type.name = "PT1"
        self.vulnerability_management.get_product_type_pipeline.return_value = mock_product_type
        self.vulnerability_management.get_findings_excepted.return_value = []

        self.handle_scan.process(dict_args, config_tool)

        self.vulnerability_management.get_product_type_pipeline.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_container"
    )
    def test_define_threshold_quality_vuln_with_matching_pt_priority_model(
        self, mock_runner_engine_container
    ):
        """Covers _define_threshold_quality_vuln priority model branch."""
        from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
        quality_threshold = Threshold(
            {
                "VULNERABILITY": {"Critical": 5, "High": 8, "Medium": 10, "Low": 15},
                "COMPLIANCE": {"Critical": 1},
                "PRIORITY": {"Very Critical": 1, "Critical": 3, "High": 5, "Medium Low": 15},
                "QUALITY_VULNERABILITY_MANAGEMENT": {
                    "PTS": [
                        {
                            "PT1": {
                                "APPS": "ALL",
                                "PROFILE": "STRONG",
                                "PROFILE_PRIORITY": "STRONG_PRIORITY",
                            }
                        }
                    ],
                    "STRONG": {"Critical": 0, "High": 0, "Medium": 5, "Low": 15},
                    "STRONG_PRIORITY": {"Very Critical": 0, "Critical": 0, "High": 5, "Medium Low": 15},
                },
            }
        )
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_container",
            "use_vulnerability_management": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
        }
        config_tool = {
            "VULNERABILITY_MANAGER": {},
            "ENGINE_CONTAINER": {"ENABLED": "true", "TOOL": "trivy"},
            "BREAK_BUILD_MANAGER": {"MODEL": "priority"},
        }
        findings_list = []
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=quality_threshold,
            path_file_results="some/file",
            custom_message_break_build="",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_container.return_value = findings_list, input_core, [], mock_tool_gateway

        mock_product_type = Mock()
        mock_product_type.name = "PT1"
        self.vulnerability_management.get_product_type_pipeline.return_value = mock_product_type
        self.vulnerability_management.get_findings_excepted.return_value = []

        self.handle_scan.process(dict_args, config_tool)

        self.vulnerability_management.get_product_type_pipeline.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_container"
    )
    def test_define_threshold_quality_vuln_no_matching_pt(self, mock_runner_engine_container):
        """Covers _define_threshold_quality_vuln when product_type is None (no match)."""
        from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
        quality_threshold = Threshold(
            {
                "VULNERABILITY": {"Critical": 5, "High": 8, "Medium": 10, "Low": 15},
                "COMPLIANCE": {"Critical": 1},
                "PRIORITY": {"Very Critical": 1, "Critical": 3, "High": 5, "Medium Low": 15},
                "QUALITY_VULNERABILITY_MANAGEMENT": {
                    "PTS": [{"PT1": {"APPS": ["pipeline"], "PROFILE": "STRONG", "PROFILE_PRIORITY": "STRONG_PRIORITY"}}],
                    "STRONG": {"Critical": 0, "High": 0, "Medium": 5, "Low": 15},
                    "STRONG_PRIORITY": {"Very Critical": 0, "Critical": 0, "High": 5, "Medium Low": 15},
                },
            }
        )
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_container",
            "use_vulnerability_management": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
        }
        config_tool = {
            "VULNERABILITY_MANAGER": {},
            "ENGINE_CONTAINER": {"ENABLED": "true", "TOOL": "trivy"},
            "BREAK_BUILD_MANAGER": {"MODEL": "severity"},
        }
        findings_list = []
        input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=quality_threshold,
            path_file_results="some/file",
            custom_message_break_build="",
            scope_pipeline="pipeline",
            scope_service="service",
            stage_pipeline="Release",
        )
        mock_tool_gateway = MagicMock()
        mock_runner_engine_container.return_value = findings_list, input_core, [], mock_tool_gateway

        self.vulnerability_management.get_product_type_pipeline.return_value = None
        self.vulnerability_management.get_findings_excepted.return_value = []

        self.handle_scan.process(dict_args, config_tool)


    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_license"
    )
    def test_process_with_engine_license_returns_runner_input_core(
        self, mock_runner_engine_license
    ):
        """engine_license is standalone: runner builds the InputCore and the
        handle_scan branch just forwards it. No VM, no risk_score."""
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_license",
            "use_vulnerability_management": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
        }
        config_tool = {
            "VULNERABILITY_MANAGER": {},
            "ENGINE_LICENSE": {"ENABLED": "true"},
        }

        runner_input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results="/abs/svc_LICENSE.json",
            custom_message_break_build="License scan completed",
            scope_pipeline="svc",
            scope_service="svc",
            stage_pipeline="Build",
        )
        mock_runner_engine_license.return_value = (
            [],
            runner_input_core,
            ["sbom_component"],
        )

        findings, input_core = self.handle_scan.process(dict_args, config_tool)

        self.assertEqual(findings, [])
        self.assertIs(input_core, runner_input_core)

        self.vulnerability_management.send_vulnerability_management.assert_not_called()
        self.risk_score_gateway.get_risk_score.assert_called_once()

        mock_runner_engine_license.assert_called_once_with(
            dict_args,
            config_tool,
            mock.ANY,  # secret_tool
            self.devops_platform_gateway,
            self.remote_config_source_gateway,
            self.sbom_gateway,
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_scan.runner_engine_license"
    )
    def test_process_with_engine_license_propagates_runner_failure_input_core(
        self, mock_runner_engine_license
    ):
        """When the runner reports a failed license report, handle_scan still
        returns the InputCore the runner produced."""
        dict_args = {
            "use_secrets_manager": "false",
            "module": "engine_license",
            "use_vulnerability_management": "true",
            "remote_config_repo": "test_repo",
            "remote_config_branch": "",
        }
        config_tool = {
            "VULNERABILITY_MANAGER": {},
            "ENGINE_LICENSE": {"ENABLED": "true"},
        }

        failure_input_core = InputCore(
            totalized_exclusions=[],
            threshold_defined=self.threshold,
            path_file_results=None,
            custom_message_break_build="License scan completed",
            scope_pipeline="svc",
            scope_service="svc",
            stage_pipeline="Build",
        )
        mock_runner_engine_license.return_value = ([], failure_input_core, None)

        findings, input_core = self.handle_scan.process(dict_args, config_tool)
        self.assertEqual(findings, [])
        self.assertIsNone(input_core.path_file_results)
        self.assertEqual(input_core.scope_pipeline, "svc")
