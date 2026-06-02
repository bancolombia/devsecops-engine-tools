import unittest
from unittest.mock import Mock, MagicMock, patch
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.context_extraction.context_extraction_manager import (
    ContextExtractionManager,
)


class TestContextExtractionManager(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.mock_risk_score_gateway = Mock()
        self.manager = ContextExtractionManager(self.mock_risk_score_gateway)
        self.mock_iac_gateway = Mock()
        self.mock_container_gateway = Mock()
        self.mock_dependencies_gateway = Mock()
        self.remote_config = {"TOOL": "test", "CONFIG": {}}
        self.config_tool = {
            "PRIORITY_MANAGER": {"USE_PRIORITY": False},
            "ENGINE_IAC": {},
            "ENGINE_CONTAINER": {},
            "ENGINE_DEPENDENCIES": {}
        }

    def test_initialization(self):
        """Test that ContextExtractionManager initializes correctly."""
        self.assertIsNotNone(self.manager._tool_gateways)
        self.assertIsNotNone(self.manager._method_mapping)
        self.assertEqual(len(self.manager._tool_gateways), 0)
        self.assertEqual(len(self.manager._method_mapping), 4)
        self.assertIsNotNone(self.manager._risk_score_gateway)

    def test_register_tool_gateway_iac(self):
        """Test registering an IaC tool gateway."""
        self.manager.register_tool_gateway("engine_iac", self.mock_iac_gateway)
        
        self.assertIn("engine_iac", self.manager._tool_gateways)
        self.assertEqual(self.manager._tool_gateways["engine_iac"], self.mock_iac_gateway)

    def test_register_tool_gateway_container(self):
        """Test registering a Container tool gateway."""
        self.manager.register_tool_gateway("engine_container", self.mock_container_gateway)
        
        self.assertIn("engine_container", self.manager._tool_gateways)
        self.assertEqual(self.manager._tool_gateways["engine_container"], self.mock_container_gateway)

    def test_register_tool_gateway_dependencies(self):
        """Test registering a Dependencies tool gateway."""
        self.manager.register_tool_gateway("engine_dependencies", self.mock_dependencies_gateway)
        
        self.assertIn("engine_dependencies", self.manager._tool_gateways)
        self.assertEqual(self.manager._tool_gateways["engine_dependencies"], self.mock_dependencies_gateway)

    def test_register_multiple_gateways(self):
        """Test registering multiple tool gateways."""
        self.manager.register_tool_gateway("engine_iac", self.mock_iac_gateway)
        self.manager.register_tool_gateway("engine_container", self.mock_container_gateway)
        self.manager.register_tool_gateway("engine_dependencies", self.mock_dependencies_gateway)
        
        self.assertEqual(len(self.manager._tool_gateways), 3)
        self.assertIn("engine_iac", self.manager._tool_gateways)
        self.assertIn("engine_container", self.manager._tool_gateways)
        self.assertIn("engine_dependencies", self.manager._tool_gateways)

    def test_extract_context_iac(self):
        """Test extracting context for IaC module."""
        path_file_results = "/path/to/iac_results.json"
        self.manager.register_tool_gateway("engine_iac", self.mock_iac_gateway)
        self.mock_iac_gateway.get_iac_context_from_results.return_value = []
        
        self.manager.extract_context(
            "engine_iac",
            path_file_results,
            self.remote_config,
            self.config_tool
        )
        
        # Verify the correct method was called
        self.mock_iac_gateway.get_iac_context_from_results.assert_called_once_with(
            path_file_results
        )

    def test_extract_context_container(self):
        """Test extracting context for Container module."""
        path_file_results = "/path/to/container_results.json"
        self.manager.register_tool_gateway("engine_container", self.mock_container_gateway)
        self.mock_container_gateway.get_container_context_from_results.return_value = []
        
        self.manager.extract_context(
            "engine_container",
            path_file_results,
            self.remote_config,
            self.config_tool
        )
        
        # Verify the correct method was called
        self.mock_container_gateway.get_container_context_from_results.assert_called_once_with(
            path_file_results
        )

    def test_extract_context_dependencies(self):
        """Test extracting context for Dependencies module."""
        path_file_results = "/path/to/dependencies_results.json"
        self.manager.register_tool_gateway("engine_dependencies", self.mock_dependencies_gateway)
        self.mock_dependencies_gateway.get_dependencies_context_from_results.return_value = []
        
        self.manager.extract_context(
            "engine_dependencies",
            path_file_results,
            self.remote_config,
            self.config_tool
        )
        
        # Verify the correct method was called with remote_config
        self.mock_dependencies_gateway.get_dependencies_context_from_results.assert_called_once_with(
            path_file_results,
            remote_config=self.remote_config
        )

    def test_extract_context_dependencies_with_kwargs(self):
        """Test extracting context for Dependencies with additional kwargs."""
        path_file_results = "/path/to/dependencies_results.json"
        self.manager.register_tool_gateway("engine_dependencies", self.mock_dependencies_gateway)
        self.mock_dependencies_gateway.get_dependencies_context_from_results.return_value = []
        
        self.manager.extract_context(
            "engine_dependencies",
            path_file_results,
            self.remote_config,
            self.config_tool,
            extra_param="value"
        )
        
        # Verify kwargs are passed
        self.mock_dependencies_gateway.get_dependencies_context_from_results.assert_called_once_with(
            path_file_results,
            remote_config=self.remote_config,
            extra_param="value"
        )

    def test_extract_context_without_path(self):
        """Test that extraction is skipped when path_file_results is None."""
        self.manager.register_tool_gateway("engine_iac", self.mock_iac_gateway)
        
        self.manager.extract_context(
            "engine_iac",
            None,
            self.remote_config,
            self.config_tool
        )
        
        # Verify method was not called
        self.mock_iac_gateway.get_iac_context_from_results.assert_not_called()

    def test_extract_context_without_registered_gateway(self):
        """Test that extraction is skipped when gateway is not registered."""
        path_file_results = "/path/to/results.json"
        
        # Don't register any gateway
        self.manager.extract_context(
            "engine_iac",
            path_file_results,
            self.remote_config,
            self.config_tool
        )
        
        # No exception should be raised, just logged warning

    def test_extract_context_with_unknown_module(self):
        """Test extraction with a module not in the method mapping."""
        path_file_results = "/path/to/results.json"
        mock_gateway = Mock()
        
        self.manager.register_tool_gateway("unknown_module", mock_gateway)
        
        self.manager.extract_context(
            "unknown_module",
            path_file_results,
            self.remote_config,
            self.config_tool
        )
        
        # No method should be called since module is not in mapping

    def test_extract_context_handles_file_not_found(self):
        """Test that FileNotFoundError is caught and logged."""
        path_file_results = "/path/to/nonexistent.json"
        self.mock_iac_gateway.get_iac_context_from_results.side_effect = FileNotFoundError("File not found")
        self.manager.register_tool_gateway("engine_iac", self.mock_iac_gateway)
        
        # Should not raise exception
        self.manager.extract_context(
            "engine_iac",
            path_file_results,
            self.remote_config,
            self.config_tool
        )
        
        # Verify method was called
        self.mock_iac_gateway.get_iac_context_from_results.assert_called_once()

    def test_extract_context_handles_value_error(self):
        """Test that ValueError is caught and logged."""
        path_file_results = "/path/to/invalid.json"
        self.mock_container_gateway.get_container_context_from_results.side_effect = ValueError("Invalid format")
        self.manager.register_tool_gateway("engine_container", self.mock_container_gateway)
        
        # Should not raise exception
        self.manager.extract_context(
            "engine_container",
            path_file_results,
            self.remote_config,
            self.config_tool
        )
        
        # Verify method was called
        self.mock_container_gateway.get_container_context_from_results.assert_called_once()

    def test_extract_context_handles_generic_exception(self):
        """Test that generic exceptions are caught and logged."""
        path_file_results = "/path/to/results.json"
        self.mock_dependencies_gateway.get_dependencies_context_from_results.side_effect = Exception("Unexpected error")
        self.manager.register_tool_gateway("engine_dependencies", self.mock_dependencies_gateway)
        
        # Should not raise exception
        self.manager.extract_context(
            "engine_dependencies",
            path_file_results,
            self.remote_config,
            self.config_tool
        )
        
        # Verify method was called
        self.mock_dependencies_gateway.get_dependencies_context_from_results.assert_called_once()

    def test_extract_context_with_different_paths(self):
        """Test extraction with various file paths."""
        test_paths = [
            "/path/to/results.json",
            "/another/path/output.json",
            "relative/path/scan.json",
            "/path/with spaces/results.json"
        ]
        
        self.manager.register_tool_gateway("engine_iac", self.mock_iac_gateway)
        self.mock_iac_gateway.get_iac_context_from_results.return_value = []
        
        for path in test_paths:
            self.mock_iac_gateway.reset_mock()
            self.manager.extract_context("engine_iac", path, self.remote_config, self.config_tool)
            self.mock_iac_gateway.get_iac_context_from_results.assert_called_once_with(path)

    def test_method_mapping_contains_all_modules(self):
        """Test that method mapping contains entries for all supported modules."""
        expected_modules = ["engine_iac", "engine_container", "engine_dependencies"]
        
        for module in expected_modules:
            self.assertIn(module, self.manager._method_mapping)

    def test_method_mapping_has_correct_method_names(self):
        """Test that method mapping has correct method names for each module."""
        expected_mapping = {
            "engine_iac": "get_iac_context_from_results",
            "engine_container": "get_container_context_from_results",
            "engine_dependencies": "get_dependencies_context_from_results",
        }
        
        for module, method_name in expected_mapping.items():
            self.assertEqual(self.manager._method_mapping[module], method_name)

    def test_gateway_replacement(self):
        """Test that registering a new gateway for the same module replaces the old one."""
        mock_gateway_1 = Mock()
        mock_gateway_2 = Mock()
        mock_gateway_2.get_iac_context_from_results.return_value = []
        
        self.manager.register_tool_gateway("engine_iac", mock_gateway_1)
        self.assertEqual(self.manager._tool_gateways["engine_iac"], mock_gateway_1)
        
        # Register a different gateway for the same module
        self.manager.register_tool_gateway("engine_iac", mock_gateway_2)
        self.assertEqual(self.manager._tool_gateways["engine_iac"], mock_gateway_2)
        
        # Verify the new gateway is used
        path_file_results = "/path/to/results.json"
        self.manager.extract_context("engine_iac", path_file_results, self.remote_config, self.config_tool)
        
        mock_gateway_1.get_iac_context_from_results.assert_not_called()
        mock_gateway_2.get_iac_context_from_results.assert_called_once()

    def test_extract_context_with_gateway_missing_method(self):
        """Test extraction when gateway doesn't implement the required method."""
        path_file_results = "/path/to/results.json"
        mock_gateway_without_method = Mock(spec=[])  # Gateway without the method
        
        self.manager.register_tool_gateway("engine_iac", mock_gateway_without_method)
        
        # Should not raise exception, just log error
        self.manager.extract_context(
            "engine_iac",
            path_file_results,
            self.remote_config,
            self.config_tool
        )

    def test_extract_context_license(self):
        """Test extracting context for License module."""
        path_file_results = "/path/to/svc_LICENSE.json"
        mock_license_gateway = Mock()
        mock_license_gateway.get_license_context_from_results.return_value = []
        self.manager.register_tool_gateway("engine_license", mock_license_gateway)

        self.manager.extract_context(
            "engine_license",
            path_file_results,
            self.remote_config,
            self.config_tool
        )

        mock_license_gateway.get_license_context_from_results.assert_called_once_with(
            path_file_results
        )

    def test_extract_context_license_prints_output(self):
        """Test that license context extraction prints the correct JSON between markers."""
        from io import StringIO
        import sys
        from dataclasses import dataclass, field
        from typing import List, Optional

        @dataclass
        class FakeContextLicense:
            name: str
            version: str
            licenses: List[str]
            policy_applied: str
            policy_reason: str
            policy_pattern_matched: str
            severity: str
            priority: Optional[str] = field(default=None)

        context_items = [
            FakeContextLicense(
                name="ngrx",
                version="1.0.0",
                licenses=["AGPL-3.0"],
                policy_applied="fail",
                policy_reason="Matched AGPL-*",
                policy_pattern_matched="AGPL-*",
                severity="critical",
            )
        ]

        mock_license_gateway = Mock()
        mock_license_gateway.get_license_context_from_results.return_value = context_items
        self.manager.register_tool_gateway("engine_license", mock_license_gateway)

        # Mock risk_score_gateway to set priority
        def set_priority(findings, config_tool, module):
            from devsecops_engine_tools.engine_core.src.domain.model.finding import Priority
            for f in findings:
                f.priority = Priority(score=1.0, scale="very critical")

        self.mock_risk_score_gateway.get_risk_score.side_effect = set_priority

        captured = StringIO()
        sys.stdout = captured
        try:
            self.manager.extract_context(
                "engine_license",
                "/path/to/svc_LICENSE.json",
                self.remote_config,
                self.config_tool
            )
        finally:
            sys.stdout = sys.__stdout__

        output = captured.getvalue()
        assert "===== BEGIN CONTEXT OUTPUT =====" in output
        assert "===== END CONTEXT OUTPUT =====" in output
        assert '"license_context"' in output
        assert '"ngrx"' in output
        assert '"very critical"' in output

if __name__ == '__main__':
    unittest.main()
