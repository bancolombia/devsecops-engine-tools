import unittest
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_core.src.domain.usecases.metrics_manager import (
    MetricsManager,
)
from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.metrics_manager_gateway import (
    MetricsManagerGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.threshold import Threshold
import os
import datetime


class TestMetricsManager(unittest.TestCase):
    def setUp(self):
        self.devops_platform_gateway = MagicMock(spec=DevopsPlatformGateway)
        self.metrics_manager_gateway = MagicMock(spec=MetricsManagerGateway)
        self.metrics_manager = MetricsManager(
            self.devops_platform_gateway, self.metrics_manager_gateway
        )

    def test_process_release_stage(self):
        # Arrange
        input_core = InputCore(
            stage_pipeline="Release",
            scope_pipeline="Scope",
            totalized_exclusions=[],
            threshold_defined=Threshold,
            path_file_results="test/file",
            custom_message_break_build="message",
        )
        dict_args = {"tool": "Tool", "environment": "Environment"}
        scan_result = "Scan Result"
        execution_id = "release_id"
        base_directory = "/tmp/log_engine_tools"
        file_path = f"{base_directory}/{datetime.datetime.now()}_{input_core.scope_pipeline}_{execution_id}.json"

        self.devops_platform_gateway.get_variable.return_value = execution_id
        self.metrics_manager_gateway.send_metrics.return_value = None
        os.makedirs = MagicMock()

        # Act
        with patch("builtins.open", create=True) as mock_open:
            self.metrics_manager.process(None, input_core, dict_args, scan_result)

        # Assert
        self.devops_platform_gateway.get_variable.assert_called_with("release_id")
        os.makedirs.assert_called_with(base_directory)
        self.metrics_manager_gateway.send_metrics.assert_called()
