import unittest
from unittest.mock import patch, Mock
from devsecops_engine_tools.engine_sast.engine_code.src.applications.runner_engine_code import (
    runner_engine_code,
)
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_tool import (
    BearerTool
)
from devsecops_engine_tools.engine_utilities.git_cli.infrastructure.git_run import (
    GitRun
)

@patch(
    "devsecops_engine_tools.engine_sast.engine_code.src.applications.runner_engine_code.init_engine_sast_code"
)
class TestRunnerEngineCode(unittest.TestCase):

    def test_runner_engine_code_bearer_tool(self, mock_init_engine_sast_code):
        # Arrange
        dict_args = {"platform_devops": "test"}
        tool = "BEARER"
        devops_platform_gateway = Mock()

        # Act
        runner_engine_code(dict_args, tool, devops_platform_gateway)

        # Assert
        _, kwargs = mock_init_engine_sast_code.call_args
        mock_init_engine_sast_code.assert_called_once()
        self.assertEqual(kwargs["devops_platform_gateway"], devops_platform_gateway)
        self.assertIsInstance(kwargs["tool_gateway"], BearerTool)
        self.assertEqual(kwargs["dict_args"], dict_args)
        self.assertEqual(kwargs["tool"], tool)

    def test_runner_engine_code_git_azure(self, mock_init_engine_sast_code):
        # Arrange
        dict_args = {"platform_devops": "azure"}
        tool = "TEST"
        devops_platform_gateway = Mock()

        # Act
        runner_engine_code(dict_args, tool, devops_platform_gateway)

        # Assert
        _, kwargs = mock_init_engine_sast_code.call_args
        mock_init_engine_sast_code.assert_called_once()
        self.assertEqual(kwargs["devops_platform_gateway"], devops_platform_gateway)
        self.assertIsInstance(kwargs["git_gateway"], GitRun)
        self.assertEqual(kwargs["dict_args"], dict_args)
        self.assertEqual(kwargs["tool"], tool)

    def test_runner_engine_code_git_azure(self, mock_init_engine_sast_code):
        # Arrange
        dict_args = {"platform_devops": "azure"}
        tool = "TEST"
        devops_platform_gateway = Mock()

        # Act
        runner_engine_code(dict_args, tool, devops_platform_gateway)

        # Assert
        _, kwargs = mock_init_engine_sast_code.call_args
        mock_init_engine_sast_code.assert_called_once()
        self.assertEqual(kwargs["devops_platform_gateway"], devops_platform_gateway)
        self.assertIsInstance(kwargs["git_gateway"], GitRun)
        self.assertEqual(kwargs["dict_args"], dict_args)
        self.assertEqual(kwargs["tool"], tool)

    def test_runner_engine_code_exception(self, mock_init_engine_sast_code):
        # Arrange
        dict_args = {"platform_devops": "azure"}
        tool = "BEARER"
        devops_platform_gateway = Mock()

        # Custom exception
        mock_init_engine_sast_code.side_effect = Exception("Simulated error")

        # Act & Assert
        with self.assertRaises(Exception) as context:
            runner_engine_code(dict_args, tool, devops_platform_gateway)

        self.assertEqual(str(context.exception), "Error engine_code : Simulated error")
