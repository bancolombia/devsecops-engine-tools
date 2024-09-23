import unittest
from unittest.mock import MagicMock
from unittest import mock
from devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk import (
    HandleRisk,
)
from devsecops_engine_tools.engine_core.src.domain.model.customs_exceptions import (
    ExceptionGettingFindings,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore


class TestHandleRisk(unittest.TestCase):
    def setUp(self):
        self.vulnerability_management = MagicMock()
        self.secrets_manager_gateway = MagicMock()
        self.devops_platform_gateway = MagicMock()
        self.print_table_gateway = MagicMock()
        self.handle_risk = HandleRisk(
            self.vulnerability_management,
            self.secrets_manager_gateway,
            self.devops_platform_gateway,
            self.print_table_gateway,
        )

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.runner_engine_risk"
    )
    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.HandleRisk._get_all_from_vm"
    )
    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.HandleRisk._filter_engagements"
    )
    @mock.patch("re.match")
    def test_process(
        self,
        mock_match,
        mock_filter_engagements,
        mock_get_all_from_vm,
        mock_runner_engine_risk,
    ):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_risk",
            "remote_config_repo": "test_repo",
        }
        config_tool = {"ENGINE_RISK": {"ENABLED": "true"}}
        self.devops_platform_gateway.get_remote_config.return_value = {
            "PARENT_ANALYSIS": {"ENABLED": "true", "REGEX_GET_PARENT": "^.*?_id"},
            "HANDLE_SERVICE_NAME": {
                "ENABLED": "true",
                "ADD_SERVICES": ["service1", "service2"],
                "ERASE_SERVICE_ENDING": ["_ending"],
                "REGEX_GET_SERVICE_CODE": "[^_]+",
            },
        }
        self.devops_platform_gateway.get_variable.return_value = (
            "code_pipeline_name_id_test"
        )
        mock_runner_engine_risk.return_value = {"result": "result"}
        mock_get_all_from_vm.return_value = ([], [])
        mock_filter_engagements.return_value = ["service1", "service2"]
        mock_match.side_effect = [
            MagicMock(group=MagicMock(return_value="code_pipeline_name_id_test")),
            MagicMock(group=MagicMock(return_value="code_pipeline_name_id_test")),
        ]

        # Call the process method
        result, input_core = self.handle_risk.process(dict_args, config_tool)

        # Assert the expected values
        assert mock_filter_engagements.call_count == 1
        assert mock_match.call_count == 2
        assert mock_get_all_from_vm.call_count == 3
        assert mock_runner_engine_risk.call_count == 1
        assert result == {"result": "result"}
        assert type(input_core) == InputCore

    @mock.patch("re.search")
    def test_filter_engagements(self, mock_search):
        engagements = [
            MagicMock(name="code_service_id_1"),
            MagicMock(name="code_service_id_2"),
            MagicMock(name="code_service_test_word1_ending"),
            MagicMock(name="code_service_test_word2-ending"),
            MagicMock(name="code_another_service_1"),
            MagicMock(name="code_another_service_2"),
        ]
        service = "code_service_id"
        risk_config = {
            "HANDLE_SERVICE_NAME": {
                "REGEX_GET_WORDS": "[_-]",
                "MIN_WORD_LENGTH": 3,
                "MIN_WORD_AMOUNT": 2,
                "REGEX_CHECK_WORDS": "(-ending$|_ending$)",
            }
        }

        # Call the process method
        self.handle_risk._filter_engagements(engagements, service, risk_config)

        # Assert the expected values
        mock_search.assert_called()

    def test_get_all_from_vm(self):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_risk",
            "remote_config_repo": "test_repo",
        }
        secret_tool = None
        remote_config = {"ENGINE_RISK": {"ENABLED": "true"}}
        service = "pipeline_name_id_test"

        # Call the process method
        self.handle_risk._get_all_from_vm(
            dict_args, secret_tool, remote_config, service
        )

        # Assert the expected values
        self.vulnerability_management.get_all.assert_called_once()

    @mock.patch(
        "devsecops_engine_tools.engine_core.src.domain.usecases.handle_risk.logger.error"
    )
    def test_get_all_from_vm_exception(self, mock_logger_error):
        dict_args = {
            "use_secrets_manager": "true",
            "tool": "engine_risk",
            "remote_config_repo": "test_repo",
        }
        secret_tool = None
        remote_config = {"ENGINE_RISK": {"ENABLED": "true"}}
        service = "pipeline_name_id_test"
        self.vulnerability_management.get_all.side_effect = ExceptionGettingFindings(
            "error"
        )

        # Call the process method
        self.handle_risk._get_all_from_vm(
            dict_args, secret_tool, remote_config, service
        )

        # Assert the expected values
        mock_logger_error.assert_called_with(
            "Error getting finding list in handle risk: error"
        )

    def test_exclude_services(self):
        dict_args = {
            "remote_config_repo": "test_repo",
        }
        pipeline_name = "pipeline_name"
        service_list = ["code_service_1", "code_service_2", "service1", "service2"]
        self.devops_platform_gateway.get_remote_config.return_value = {
            "pipeline_name": {
                "SKIP_SERVICE": {"services": ["code_service_1", "code_service_2"]}
            }
        }

        # Call the process method
        result = self.handle_risk._exclude_services(
            dict_args, pipeline_name, service_list
        )

        # Assert the expected values
        assert type(result) == list
