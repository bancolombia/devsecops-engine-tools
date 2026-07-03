import unittest
import os
from unittest.mock import patch, Mock, mock_open, call
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen import CdxGen
from devsecops_engine_tools.engine_core.src.domain.model.component import Component


class TestCdxGen(unittest.TestCase):

    def setUp(self):
        self.cdxgen = CdxGen()
        self.artifact = "/path/to/project"
        self.service_name = "test_service"
        
        # Mock configuration
        self.mock_config = {
            "CDXGEN": {
                "CDXGEN_VERSION": "10.2.0",
                "SLIM_BINARY": False,
                "OUTPUT_FORMAT": "json",
                "EXCLUDE_TYPES": [],
                "EXCLUDE_PATHS": [],
                "RECURSE": True,
                "DEBUG_PIPELINES": [],
                "REQUIRED_ONLY_PIPELINES": []
            }
        }
        
        self.mock_config_slim = {
            "CDXGEN": {
                "CDXGEN_VERSION": "10.2.0",
                "SLIM_BINARY": True,
                "OUTPUT_FORMAT": "json",
                "EXCLUDE_TYPES": [],
                "EXCLUDE_PATHS": [],
                "RECURSE": True,
                "DEBUG_PIPELINES": [],
                "REQUIRED_ONLY_PIPELINES": []
            }
        }
        
        # Mock components list
        self.mock_components = [
            Component(name="test-component-1", version="1.0.0"),
            Component(name="test-component-2", version="2.0.0")
        ]

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_linux_success(self, mock_platform, mock_get_list_component):
        # Arrange
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None) as mock_check:
            with patch.object(self.cdxgen, '_install_tool_unix', return_value='./cdxgen-linux-amd64') as mock_install:
                with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                    # Act
                    result = self.cdxgen.get_components(self.artifact, self.mock_config, self.service_name)
        
        # Assert
        self.assertEqual(result, self.mock_components)
        mock_check.assert_called_once()
        mock_install.assert_called_once_with(
            "cdxgen-linux-amd64",
            "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-linux-amd64",
            "cdxgen"
        )
        mock_run.assert_called_once_with('./cdxgen-linux-amd64', self.artifact, self.service_name, [], [], True, True, False, False, '1.6', [])
        mock_get_list_component.assert_called_once_with('test_service_SBOM.json', 'json')

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.machine')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_linux_success_arm64(self, mock_platform, mock_get_list_component, mock_machine):
        # Arrange
        mock_platform.return_value = "Linux"
        mock_machine.return_value = "aarch64"
        mock_get_list_component.return_value = self.mock_components
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None) as mock_check:
            with patch.object(self.cdxgen, '_install_tool_unix', return_value='./cdxgen-linux-arm64') as mock_install:
                with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                    # Act
                    result = self.cdxgen.get_components(self.artifact, self.mock_config, self.service_name)
        
        # Assert
        self.assertEqual(result, self.mock_components)
        mock_check.assert_called_once()
        mock_install.assert_called_once_with(
            "cdxgen-linux-arm64",
            "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-linux-arm64",
            "cdxgen"
        )
        mock_run.assert_called_once_with('./cdxgen-linux-arm64', self.artifact, self.service_name, [], [], True, True, False, False, '1.6', [])
        mock_get_list_component.assert_called_once_with('test_service_SBOM.json', 'json')

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_linux_slim_binary(self, mock_platform, mock_get_list_component):
        # Arrange
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None) as mock_check:
            with patch.object(self.cdxgen, '_install_tool_unix', return_value='./cdxgen-linux-amd64-slim') as mock_install:
                with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                    # Act
                    result = self.cdxgen.get_components(self.artifact, self.mock_config_slim, self.service_name)
        
        # Assert
        self.assertEqual(result, self.mock_components)
        mock_check.assert_called_once()
        mock_install.assert_called_once_with(
            "cdxgen-linux-amd64-slim",
            "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-linux-amd64-slim",
            "cdxgen"
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_darwin_success(self, mock_platform, mock_get_list_component):
        # Arrange
        mock_platform.return_value = "Darwin"
        mock_get_list_component.return_value = self.mock_components
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None) as mock_check:
            with patch.object(self.cdxgen, '_install_tool_unix', return_value='./cdxgen-darwin-amd64') as mock_install:
                with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                    # Act
                    result = self.cdxgen.get_components(self.artifact, self.mock_config, self.service_name)
        
        # Assert
        self.assertEqual(result, self.mock_components)
        mock_check.assert_called_once()
        mock_install.assert_called_once_with(
            "cdxgen-darwin-amd64",
            "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-darwin-amd64",
            "cdxgen"
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.machine')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_darwin_success_arm64(self, mock_platform, mock_get_list_component, mock_machine):
        # Arrange
        mock_platform.return_value = "Darwin"
        mock_machine.return_value = "arm64"
        mock_get_list_component.return_value = self.mock_components
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None) as mock_check:
            with patch.object(self.cdxgen, '_install_tool_unix', return_value='./cdxgen-darwin-arm64') as mock_install:
                with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                    # Act
                    result = self.cdxgen.get_components(self.artifact, self.mock_config, self.service_name)
        
        # Assert
        self.assertEqual(result, self.mock_components)
        mock_check.assert_called_once()
        mock_install.assert_called_once_with(
            "cdxgen-darwin-arm64",
            "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-darwin-arm64",
            "cdxgen"
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_windows_success(self, mock_platform, mock_get_list_component):
        # Arrange
        mock_platform.return_value = "Windows"
        mock_get_list_component.return_value = self.mock_components
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None) as mock_check:
            with patch.object(self.cdxgen, '_install_tool_windows', return_value='cdxgen-windows-amd64.exe') as mock_install:
                with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                    # Act
                    result = self.cdxgen.get_components(self.artifact, self.mock_config, self.service_name)
        
        # Assert
        self.assertEqual(result, self.mock_components)
        mock_check.assert_called_once()
        mock_install.assert_called_once_with(
            "cdxgen-windows-amd64.exe",
            "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-windows-amd64.exe",
            "cdxgen.exe"
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_unsupported_platform(self, mock_platform, mock_logger):
        # Arrange
        mock_platform.return_value = "FreeBSD"
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None):
            # Act
            result = self.cdxgen.get_components(self.artifact, self.mock_config, self.service_name)
        
        # Assert
        self.assertIsNone(result)
        mock_logger.warning.assert_called_once_with("FreeBSD is not supported.")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_exception_handling(self, mock_platform, mock_logger):
        # Arrange
        mock_platform.return_value = "Linux"
        error_message = "Installation failed"
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None):
            with patch.object(self.cdxgen, '_install_tool_unix', side_effect=Exception(error_message)):
                # Act
                result = self.cdxgen.get_components(self.artifact, self.mock_config, self.service_name)
        
        # Assert
        self.assertIsNone(result)
        mock_logger.error.assert_called_once_with(f"Error generating SBOM: {error_message}")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_success(self, mock_subprocess):
        # Arrange
        command_prefix = "/usr/local/bin/cdxgen"
        exclude_types = []
        exclude_paths = []
        recurse = True
        install_deps = True
        enable_debug = False
        required_only = False
        mock_result = Mock(returncode=0, stdout="", stderr="")
        mock_subprocess.return_value = mock_result
        expected_result_file = f"{self.service_name}_SBOM.json"
        expected_command = [command_prefix, self.artifact, "-o", expected_result_file, "--spec-version", "1.6"]
        
        # Act
        with patch('builtins.print') as mock_print:
            result = self.cdxgen._run_cdxgen(command_prefix, self.artifact, self.service_name, exclude_types, exclude_paths, recurse, install_deps, required_only, enable_debug)
        
        # Assert
        self.assertEqual(result, expected_result_file)
        mock_subprocess.assert_called_once_with(
            expected_command,
            stdout=unittest.mock.ANY,
            stderr=unittest.mock.ANY,
            text=True
        )
        mock_print.assert_called_once_with(f"SBOM generated and saved to: {expected_result_file}")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_failure(self, mock_subprocess, mock_logger):
        # Arrange
        command_prefix = "/usr/local/bin/cdxgen"
        exclude_types = []
        exclude_paths = []
        recurse = True
        install_deps = True
        enable_debug = False
        required_only = False
        error_message = "Command execution failed"
        mock_subprocess.side_effect = Exception(error_message)
        
        # Act
        result = self.cdxgen._run_cdxgen(command_prefix, self.artifact, self.service_name, exclude_types, exclude_paths, recurse, install_deps, required_only, enable_debug)
        
        # Assert
        self.assertIsNone(result)
        mock_logger.error.assert_called_once_with(f"Error running cdxgen: {error_message}")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    def test_run_cdxgen_debug_mode_enabled(self, mock_logger, mock_subprocess):
        # Arrange
        command_prefix = "/usr/local/bin/cdxgen"
        exclude_types = []
        exclude_paths = []
        recurse = True
        install_deps = True
        enable_debug = True
        required_only = False
        mock_result = Mock(returncode=0, stdout="Debug stdout output", stderr="Debug stderr output")
        mock_subprocess.return_value = mock_result
        expected_result_file = f"{self.service_name}_SBOM.json"
        
        # Act
        with patch('builtins.print') as mock_print:
            result = self.cdxgen._run_cdxgen(command_prefix, self.artifact, self.service_name, exclude_types, exclude_paths, recurse, install_deps, required_only, enable_debug)
        
        # Assert
        self.assertEqual(result, expected_result_file)
        # Verify that debug info is logged (based on actual implementation)
        mock_logger.info.assert_any_call("CDXGEN stdout: Debug stdout output")
        mock_logger.info.assert_any_call("CDXGEN stderr: Debug stderr output")
        
        # Verify the final print call
        mock_print.assert_called_with(f"SBOM generated and saved to: {expected_result_file}")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    def test_get_components_debug_mode_service_in_list(self, mock_logger, mock_platform, mock_get_list_component):
        # Arrange
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components
        
        # Config with DEBUG_PIPELINES containing our service
        debug_config = {
            "CDXGEN": {
                "CDXGEN_VERSION": "10.2.0",
                "SLIM_BINARY": False,
                "OUTPUT_FORMAT": "json",
                "EXCLUDE_TYPES": [],
                "EXCLUDE_PATHS": [],
                "RECURSE": True,
                "INSTALL_DEPENDENCIES": False,
                "DEBUG_PIPELINES": ["test_service", "another_service"],
                "REQUIRED_ONLY_PIPELINES": []
            }
        }
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None):
            with patch.object(self.cdxgen, '_install_tool_unix', return_value='./cdxgen-linux-amd64') as mock_install:
                with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                    # Act
                    result = self.cdxgen.get_components(self.artifact, debug_config, self.service_name)
        
        # Assert
        self.assertEqual(result, self.mock_components)
        mock_logger.info.assert_called_with(f"Enabling debug mode for pipeline: {self.service_name}")
        mock_run.assert_called_once_with('./cdxgen-linux-amd64', self.artifact, self.service_name, [], [], True, False, False, True, '1.6', [])

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_debug_mode_service_not_in_list(self, mock_platform, mock_get_list_component):
        # Arrange
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components
        
        # Config with DEBUG_PIPELINES not containing our service
        debug_config = {
            "CDXGEN": {
                "CDXGEN_VERSION": "10.2.0",
                "SLIM_BINARY": False,
                "OUTPUT_FORMAT": "json",
                "EXCLUDE_TYPES": [],
                "EXCLUDE_PATHS": [],
                "RECURSE": True,
                "DEBUG_PIPELINES": ["other_service", "another_service"],
                "REQUIRED_ONLY_PIPELINES": []
            }
        }
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None):
            with patch.object(self.cdxgen, '_install_tool_unix', return_value='./cdxgen-linux-amd64') as mock_install:
                with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                    # Act
                    result = self.cdxgen.get_components(self.artifact, debug_config, self.service_name)
        
        # Assert
        self.assertEqual(result, self.mock_components)
        mock_run.assert_called_once_with('./cdxgen-linux-amd64', self.artifact, self.service_name, [], [], True, True, False, False, '1.6', [])

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_required_only_service_in_list(self, mock_platform, mock_get_list_component):
        # Arrange
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components

        required_only_config = {
            "CDXGEN": {
                "CDXGEN_VERSION": "10.2.0",
                "SLIM_BINARY": False,
                "OUTPUT_FORMAT": "json",
                "EXCLUDE_TYPES": [],
                "EXCLUDE_PATHS": [],
                "RECURSE": True,
                "DEBUG_PIPELINES": [],
                "REQUIRED_ONLY_PIPELINES": ["test_service", "another_service"]
            }
        }

        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=None):
            with patch.object(self.cdxgen, '_install_tool_unix', return_value='./cdxgen-linux-amd64'):
                with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                    result = self.cdxgen.get_components(self.artifact, required_only_config, self.service_name)

        # Assert: required_only=True because service_name is in REQUIRED_ONLY_PIPELINES
        self.assertEqual(result, self.mock_components)
        mock_run.assert_called_once_with('./cdxgen-linux-amd64', self.artifact, self.service_name, [], [], True, True, True, False, '1.6', [])

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_fetch_license_enabled_sets_env(self, mock_platform, mock_get_list_component):
        # Arrange
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components

        fetch_license_config = {
            "CDXGEN": {
                "CDXGEN_VERSION": "10.2.0",
                "SLIM_BINARY": False,
                "OUTPUT_FORMAT": "json",
                "EXCLUDE_TYPES": [],
                "EXCLUDE_PATHS": [],
                "RECURSE": True,
                "FETCH_LICENSE": True,
                "DEBUG_PIPELINES": [],
                "REQUIRED_ONLY_PIPELINES": []
            }
        }

        with patch.object(self.cdxgen, '_install_tool_unix', return_value='/usr/local/bin/cdxgen') as mock_install:
            with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                with patch.dict(os.environ, {}, clear=True):
                    # Act
                    result = self.cdxgen.get_components(self.artifact, fetch_license_config, self.service_name)

                    # Assert
                    self.assertEqual(result, self.mock_components)
                    self.assertEqual(os.environ.get("FETCH_LICENSE"), "true")
                    mock_install.assert_called_once()
                    mock_run.assert_called_once_with('/usr/local/bin/cdxgen', self.artifact, self.service_name, [], [], True, True, False, False, '1.6', [])

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_fetch_license_disabled_does_not_set_env(self, mock_platform, mock_get_list_component):
        # Arrange
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components

        fetch_license_config = {
            "CDXGEN": {
                "CDXGEN_VERSION": "10.2.0",
                "SLIM_BINARY": False,
                "OUTPUT_FORMAT": "json",
                "EXCLUDE_TYPES": [],
                "EXCLUDE_PATHS": [],
                "RECURSE": True,
                "FETCH_LICENSE": False,
                "DEBUG_PIPELINES": [],
                "REQUIRED_ONLY_PIPELINES": []
            }
        }

        with patch.object(self.cdxgen, '_install_tool_unix', return_value='/usr/local/bin/cdxgen') as mock_install:
            with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                with patch.dict(os.environ, {}, clear=True):
                    # Act
                    result = self.cdxgen.get_components(self.artifact, fetch_license_config, self.service_name)

                    # Assert
                    self.assertEqual(result, self.mock_components)
                    self.assertIsNone(os.environ.get("FETCH_LICENSE"))
                    mock_install.assert_called_once()
                    mock_run.assert_called_once_with('/usr/local/bin/cdxgen', self.artifact, self.service_name, [], [], True, True, False, False, '1.6', [])

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_with_exclude_types_list(self, mock_subprocess):
        # Arrange
        command_prefix = "/usr/local/bin/cdxgen"
        exclude_types = ["npm", "pip"]
        exclude_paths = []
        recurse = True
        install_deps = True
        enable_debug = False
        required_only = False
        mock_result = Mock(returncode=0, stdout="", stderr="")
        mock_subprocess.return_value = mock_result
        expected_result_file = f"{self.service_name}_SBOM.json"
        expected_command = [command_prefix, self.artifact, "-o", expected_result_file, "--spec-version", "1.6", "--exclude-type", "npm", "--exclude-type", "pip"]
        
        # Act
        with patch('builtins.print') as mock_print:
            result = self.cdxgen._run_cdxgen(command_prefix, self.artifact, self.service_name, exclude_types, exclude_paths, recurse, install_deps, required_only, enable_debug)
        
        # Assert
        self.assertEqual(result, expected_result_file)
        mock_subprocess.assert_called_once_with(
            expected_command,
            stdout=unittest.mock.ANY,
            stderr=unittest.mock.ANY,
            text=True
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_with_exclude_paths_list(self, mock_subprocess):
        # Arrange
        command_prefix = "/usr/local/bin/cdxgen"
        exclude_types = []
        exclude_paths = ["node_modules", "vendor"]
        recurse = True
        install_deps = True
        enable_debug = False
        required_only = False
        mock_result = Mock(returncode=0, stdout="", stderr="")
        mock_subprocess.return_value = mock_result
        expected_result_file = f"{self.service_name}_SBOM.json"
        expected_command = [command_prefix, self.artifact, "-o", expected_result_file, "--spec-version", "1.6", "--exclude", "node_modules", "--exclude", "vendor"]
        
        # Act
        with patch('builtins.print') as mock_print:
            result = self.cdxgen._run_cdxgen(command_prefix, self.artifact, self.service_name, exclude_types, exclude_paths, recurse, install_deps, required_only, enable_debug)
        
        # Assert
        self.assertEqual(result, expected_result_file)
        mock_subprocess.assert_called_once_with(
            expected_command,
            stdout=unittest.mock.ANY,
            stderr=unittest.mock.ANY,
            text=True
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_no_recurse(self, mock_subprocess):
        # Arrange
        command_prefix = "/usr/local/bin/cdxgen"
        exclude_types = []
        exclude_paths = []
        recurse = False
        enable_debug = False
        install_deps = True
        required_only = False
        mock_result = Mock(returncode=0, stdout="", stderr="")
        mock_subprocess.return_value = mock_result
        expected_result_file = f"{self.service_name}_SBOM.json"
        expected_command = [command_prefix, self.artifact, "-o", expected_result_file, "--spec-version", "1.6", "--no-recurse"]
        
        # Act
        with patch('builtins.print') as mock_print:
            result = self.cdxgen._run_cdxgen(command_prefix, self.artifact, self.service_name, exclude_types, exclude_paths, recurse, install_deps, required_only, enable_debug)
        
        # Assert
        self.assertEqual(result, expected_result_file)
        mock_subprocess.assert_called_once_with(
            expected_command,
            stdout=unittest.mock.ANY,
            stderr=unittest.mock.ANY,
            text=True
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_check_cdxgen_in_path_found_unix(self, mock_platform, mock_subprocess):
        # Arrange
        mock_platform.return_value = "Linux"
        cdxgen_path = "/usr/local/bin/cdxgen"
        
        # Mock both which and version check
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout=f"{cdxgen_path}\n", stderr=""),
            Mock(returncode=0, stdout="10.2.0", stderr="")
        ]
        
        # Act
        result = self.cdxgen._check_cdxgen_in_path()
        
        # Assert
        self.assertEqual(result, cdxgen_path)
        self.assertEqual(mock_subprocess.call_count, 2)

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_check_cdxgen_in_path_found_windows(self, mock_platform, mock_subprocess):
        # Arrange
        mock_platform.return_value = "Windows"
        cdxgen_path = "C:\\Program Files\\cdxgen\\cdxgen.exe"
        
        # Mock both where and version check
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout=f"{cdxgen_path}\n", stderr=""),
            Mock(returncode=0, stdout="10.2.0", stderr="")
        ]
        
        # Act
        result = self.cdxgen._check_cdxgen_in_path()
        
        # Assert
        self.assertEqual(result, cdxgen_path)

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_check_cdxgen_in_path_not_found(self, mock_platform, mock_subprocess):
        # Arrange
        mock_platform.return_value = "Linux"
        mock_subprocess.return_value = Mock(returncode=1, stdout="", stderr="")
        
        # Act
        result = self.cdxgen._check_cdxgen_in_path()
        
        # Assert
        self.assertIsNone(result)

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_check_cdxgen_in_path_version_check_fails(self, mock_platform, mock_subprocess, mock_logger):
        # Arrange
        mock_platform.return_value = "Linux"
        cdxgen_path = "/usr/local/bin/cdxgen"
        
        # Mock which succeeds but version check fails
        mock_subprocess.side_effect = [
            Mock(returncode=0, stdout=f"{cdxgen_path}\n", stderr=""),
            Mock(returncode=1, stdout="", stderr="error")
        ]
        
        # Act
        result = self.cdxgen._check_cdxgen_in_path()
        
        # Assert
        self.assertIsNone(result)

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_check_cdxgen_in_path_exception(self, mock_subprocess, mock_logger):
        # Arrange
        error_message = "Command failed"
        mock_subprocess.side_effect = Exception(error_message)
        
        # Act
        result = self.cdxgen._check_cdxgen_in_path()
        
        # Assert
        self.assertIsNone(result)
        mock_logger.debug.assert_called_once_with(f"cdxgen not found in PATH: {error_message}")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    def test_get_components_uses_cdxgen_from_path(self, mock_logger, mock_platform, mock_get_list_component):
        # Arrange
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components
        cdxgen_path = "/usr/local/bin/cdxgen"
        
        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value=cdxgen_path):
            with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                # Act
                result = self.cdxgen.get_components(self.artifact, self.mock_config, self.service_name)
        
        # Assert
        self.assertEqual(result, self.mock_components)
        mock_logger.info.assert_called_with(f"Using cdxgen from PATH: {cdxgen_path}")
        mock_run.assert_called_once_with(cdxgen_path, self.artifact, self.service_name, [], [], True, True, False, False, '1.6', [])

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_install_tool_unix_success(self, mock_subprocess):
        # Arrange
        file = "cdxgen-linux-amd64"
        url = "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-linux-amd64"
        command_prefix = "cdxgen"
        
        mock_subprocess.return_value = Mock(returncode=0)
        
        with patch.object(self.cdxgen, '_download_tool') as mock_download:
            # Act
            result = self.cdxgen._install_tool_unix(file, url, command_prefix)
        
        # Assert
        self.assertEqual(result, f"./{file}")
        mock_download.assert_called_once_with(file, url)
        
        # Verify chmod call
        mock_subprocess.assert_called_once_with(
            ["chmod", "+x", f"./{file}"],
            stdout=unittest.mock.ANY,
            stderr=unittest.mock.ANY
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_install_tool_unix_download_failure(self, mock_subprocess, mock_logger):
        # Arrange
        file = "cdxgen-linux-amd64"
        url = "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-linux-amd64"
        command_prefix = "cdxgen"
        error_message = "Download failed"
        
        with patch.object(self.cdxgen, '_download_tool', side_effect=Exception(error_message)):
            # Act
            result = self.cdxgen._install_tool_unix(file, url, command_prefix)
        
        # Assert
        self.assertIsNone(result)
        mock_logger.error.assert_called_once_with(f"Error installing cdxgen: {error_message}")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_install_tool_windows_success(self, mock_subprocess):
        # Arrange
        file = "cdxgen-windows-amd64.exe"
        url = "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-windows-amd64.exe"
        command_prefix = "cdxgen.exe"
        
        with patch.object(self.cdxgen, '_download_tool') as mock_download:
            # Act
            result = self.cdxgen._install_tool_windows(file, url, command_prefix)
        
        # Assert
        self.assertEqual(result, file)
        mock_download.assert_called_once_with(file, url)

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_install_tool_windows_download_failure(self, mock_subprocess, mock_logger):
        # Arrange
        file = "cdxgen-windows-amd64.exe"
        url = "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-windows-amd64.exe"
        command_prefix = "cdxgen.exe"
        error_message = "Download failed"
        
        with patch.object(self.cdxgen, '_download_tool', side_effect=Exception(error_message)):
            # Act
            result = self.cdxgen._install_tool_windows(file, url, command_prefix)
        
        # Assert
        self.assertIsNone(result)
        mock_logger.error.assert_called_once_with(f"Error installing cdxgen: {error_message}")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.requests.get')
    def test_download_tool_success(self, mock_requests_get):
        # Arrange
        file = "cdxgen-linux-amd64"
        url = "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-linux-amd64"
        mock_content = b"binary content"
        
        mock_response = Mock()
        mock_response.content = mock_content
        mock_requests_get.return_value = mock_response
        
        mock_file = mock_open()
        
        # Act
        with patch('builtins.open', mock_file):
            self.cdxgen._download_tool(file, url)
        
        # Assert
        mock_requests_get.assert_called_once_with(url, allow_redirects=True)
        mock_file.assert_called_once_with(file, "wb")
        mock_file().write.assert_called_once_with(mock_content)

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.requests.get')
    def test_download_tool_failure(self, mock_requests_get, mock_logger):
        # Arrange
        file = "cdxgen-linux-amd64"
        url = "https://github.com/CycloneDX/cdxgen/releases/download/v10.2.0/cdxgen-linux-amd64"
        error_message = "Network error"
        
        mock_requests_get.side_effect = Exception(error_message)
        
        # Act
        self.cdxgen._download_tool(file, url)
        
        # Assert
        mock_logger.error.assert_called_once_with(f"Error downloading cdxgen: {error_message}")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_override_registries(self, mock_platform, mock_get_list_component):
        """Covers OVERRIDE_REGISTRIES=True branch (lines 39-41)."""
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = []

        config = {
            "CDXGEN": {
                "CDXGEN_VERSION": "10.2.0",
                "SLIM_BINARY": False,
                "OUTPUT_FORMAT": "json",
                "EXCLUDE_TYPES": [],
                "EXCLUDE_PATHS": [],
                "RECURSE": True,
                "INSTALL_DEPENDENCIES": True,
                "DEBUG_PIPELINES": [],
                "REQUIRED_ONLY_PIPELINES": [],
                "OVERRIDE_REGISTRIES": True,
                "REGISTRIES": {"MY_PRIVATE_REG": "http://my-registry.example.com"},
            }
        }

        with patch.object(self.cdxgen, '_install_tool_unix', return_value='/usr/local/bin/cdxgen'):
            with patch.object(self.cdxgen, '_run_cdxgen', return_value=None):
                with patch.dict(os.environ, {}, clear=False):
                    self.cdxgen.get_components(self.artifact, config, self.service_name)
                    self.assertEqual(os.environ.get("MY_PRIVATE_REG"), "http://my-registry.example.com")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_with_required_only(self, mock_subprocess):
        """Covers required_only=True branch: --required-only flag is appended to the command."""
        command_prefix = "/usr/local/bin/cdxgen"
        exclude_types = []
        exclude_paths = []
        recurse = True
        install_deps = True
        enable_debug = False
        required_only = True
        mock_result = Mock(returncode=0, stdout="", stderr="")
        mock_subprocess.return_value = mock_result
        expected_result_file = f"{self.service_name}_SBOM.json"
        expected_command = [command_prefix, self.artifact, "-o", expected_result_file, "--spec-version", "1.6", "--required-only"]

        with patch('builtins.print'):
            result = self.cdxgen._run_cdxgen(
                command_prefix, self.artifact, self.service_name,
                exclude_types, exclude_paths, recurse, install_deps,
                required_only, enable_debug
            )

        self.assertEqual(result, expected_result_file)
        mock_subprocess.assert_called_once_with(
            expected_command,
            stdout=unittest.mock.ANY,
            stderr=unittest.mock.ANY,
            text=True,
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_no_install_deps(self, mock_subprocess):
        """Covers install_deps=False branch (line 122)."""
        command_prefix = "/usr/local/bin/cdxgen"
        exclude_types = []
        exclude_paths = []
        recurse = True
        install_deps = False
        enable_debug = False
        required_only = False
        mock_result = Mock(returncode=0, stdout="", stderr="")
        mock_subprocess.return_value = mock_result
        expected_result_file = f"{self.service_name}_SBOM.json"
        expected_command = [command_prefix, self.artifact, "-o", expected_result_file, "--spec-version", "1.6", "--no-install-deps"]

        with patch('builtins.print'):
            result = self.cdxgen._run_cdxgen(
                command_prefix, self.artifact, self.service_name,
                exclude_types, exclude_paths, recurse, install_deps,
                required_only, enable_debug
            )

        self.assertEqual(result, expected_result_file)
        mock_subprocess.assert_called_once_with(
            expected_command,
            stdout=unittest.mock.ANY,
            stderr=unittest.mock.ANY,
            text=True,
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_nonzero_returncode(self, mock_subprocess, mock_logger):
        """Covers raise Exception when returncode != 0 (line 144) → caught by logger.error."""
        command_prefix = "/usr/local/bin/cdxgen"
        exclude_types = []
        exclude_paths = []
        recurse = True
        install_deps = True
        enable_debug = False
        required_only = False
        mock_result = Mock(returncode=1, stdout="", stderr="some cdxgen error")
        mock_subprocess.return_value = mock_result

        result = self.cdxgen._run_cdxgen(
            command_prefix, self.artifact, self.service_name,
            exclude_types, exclude_paths, recurse, install_deps,
            required_only, enable_debug
        )

        self.assertIsNone(result)
        mock_logger.error.assert_called_once_with(
            "Error running cdxgen: CDXGEN command failed with return code: 1"
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.remove')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.path.exists')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_gradle_build_failed_pattern_breaks_execution(
        self, mock_subprocess, mock_logger, mock_exists, mock_remove
    ):
        """cdxgen can return 0 even when the underlying Gradle build failed."""
        command_prefix = "/usr/local/bin/cdxgen"
        mock_result = Mock(returncode=0, stdout="Some output\nBUILD FAILED\nmore output", stderr="")
        mock_subprocess.return_value = mock_result
        mock_exists.return_value = True

        result = self.cdxgen._run_cdxgen(
            command_prefix, self.artifact, self.service_name,
            [], [], True, True, False, False, "1.6", ["BUILD FAILED"]
        )

        self.assertIsNone(result)
        expected_result_file = f"{self.service_name}_SBOM.json"
        mock_remove.assert_called_once_with(expected_result_file)
        mock_logger.error.assert_called_once_with(
            "Error running cdxgen: Detected build failure pattern 'BUILD FAILED' in cdxgen output for "
            f"'{self.service_name}'. The underlying build likely failed; aborting to avoid "
            "generating an incomplete or empty SBOM."
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.path.exists')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_maven_build_failure_pattern_case_insensitive(self, mock_subprocess, mock_logger, mock_exists):
        """Pattern matching is case-insensitive (e.g. Maven's 'BUILD FAILURE')."""
        command_prefix = "/usr/local/bin/cdxgen"
        mock_result = Mock(returncode=0, stdout="", stderr="[INFO] build failure summary")
        mock_subprocess.return_value = mock_result
        mock_exists.return_value = False

        result = self.cdxgen._run_cdxgen(
            command_prefix, self.artifact, self.service_name,
            [], [], True, True, False, False, "1.6", ["BUILD FAILURE"]
        )

        self.assertIsNone(result)
        self.assertIn(
            "Detected build failure pattern 'BUILD FAILURE'",
            mock_logger.error.call_args[0][0]
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.remove')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.path.exists')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_regex_failure_pattern(self, mock_subprocess, mock_exists, mock_remove):
        """Patterns supplied via config are treated as regular expressions."""
        command_prefix = "/usr/local/bin/cdxgen"
        mock_result = Mock(returncode=0, stdout="npm ERR! code E404", stderr="")
        mock_subprocess.return_value = mock_result
        mock_exists.return_value = True

        result = self.cdxgen._run_cdxgen(
            command_prefix, self.artifact, self.service_name,
            [], [], True, True, False, False, "1.6", [r"npm ERR!\s+code\s+E\d+"]
        )

        self.assertIsNone(result)
        mock_remove.assert_called_once_with(f"{self.service_name}_SBOM.json")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_invalid_regex_pattern_is_skipped(self, mock_subprocess, mock_logger):
        """An invalid regex pattern is logged and skipped instead of raising."""
        command_prefix = "/usr/local/bin/cdxgen"
        mock_result = Mock(returncode=0, stdout="all good", stderr="")
        mock_subprocess.return_value = mock_result
        expected_result_file = f"{self.service_name}_SBOM.json"

        with patch('builtins.print'):
            result = self.cdxgen._run_cdxgen(
                command_prefix, self.artifact, self.service_name,
                [], [], True, True, False, False, "1.6", ["("]
            )

        self.assertEqual(result, expected_result_file)
        mock_logger.debug.assert_called_once()

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.subprocess.run')
    def test_run_cdxgen_no_failure_patterns_configured(self, mock_subprocess):
        """When no patterns are configured, output is not inspected and success proceeds."""
        command_prefix = "/usr/local/bin/cdxgen"
        mock_result = Mock(returncode=0, stdout="BUILD FAILED", stderr="")
        mock_subprocess.return_value = mock_result
        expected_result_file = f"{self.service_name}_SBOM.json"

        with patch('builtins.print'):
            result = self.cdxgen._run_cdxgen(
                command_prefix, self.artifact, self.service_name,
                [], [], True, True, False, False, "1.6", []
            )

        self.assertEqual(result, expected_result_file)

    def test_detect_build_failure_no_match(self):
        result = self.cdxgen._detect_build_failure(
            "everything compiled successfully", ["BUILD FAILED", "BUILD FAILURE"]
        )
        self.assertIsNone(result)

    def test_detect_build_failure_empty_output(self):
        result = self.cdxgen._detect_build_failure("", ["BUILD FAILED"])
        self.assertIsNone(result)

    def test_detect_build_failure_no_patterns(self):
        result = self.cdxgen._detect_build_failure("BUILD FAILED", [])
        self.assertIsNone(result)

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.remove')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.path.exists')
    def test_remove_incomplete_sbom_removes_existing_file(self, mock_exists, mock_remove):
        mock_exists.return_value = True
        self.cdxgen._remove_incomplete_sbom("test_service_SBOM.json")
        mock_remove.assert_called_once_with("test_service_SBOM.json")

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.remove')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.path.exists')
    def test_remove_incomplete_sbom_missing_file_is_noop(self, mock_exists, mock_remove):
        mock_exists.return_value = False
        self.cdxgen._remove_incomplete_sbom("test_service_SBOM.json")
        mock_remove.assert_not_called()

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.logger')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.remove')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.os.path.exists')
    def test_remove_incomplete_sbom_handles_os_error(self, mock_exists, mock_remove, mock_logger):
        mock_exists.return_value = True
        mock_remove.side_effect = OSError("permission denied")
        self.cdxgen._remove_incomplete_sbom("test_service_SBOM.json")
        mock_logger.debug.assert_called_once_with(
            "Could not remove incomplete SBOM file 'test_service_SBOM.json': permission denied"
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_break_on_build_failure_config_disabled(self, mock_platform, mock_get_list_component):
        """When BREAK_ON_BUILD_FAILURE is False, _run_cdxgen receives an empty pattern list."""
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components

        config = {
            "CDXGEN": {
                "CDXGEN_VERSION": "10.2.0",
                "SLIM_BINARY": False,
                "OUTPUT_FORMAT": "json",
                "EXCLUDE_TYPES": [],
                "EXCLUDE_PATHS": [],
                "RECURSE": True,
                "DEBUG_PIPELINES": [],
                "REQUIRED_ONLY_PIPELINES": [],
                "BUILD_FAILURE_PATTERNS": ["BUILD FAILED"],
                "BREAK_ON_BUILD_FAILURE": False
            }
        }

        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value='/usr/local/bin/cdxgen'):
            with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                result = self.cdxgen.get_components(self.artifact, config, self.service_name)

        self.assertEqual(result, self.mock_components)
        mock_run.assert_called_once_with(
            '/usr/local/bin/cdxgen', self.artifact, self.service_name, [], [], True, True, False, False, '1.6', []
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_build_failure_patterns_passed_through(self, mock_platform, mock_get_list_component):
        """All build-failure patterns come exclusively from the remote config, no built-in defaults."""
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components

        config = {
            "CDXGEN": {
                "CDXGEN_VERSION": "10.2.0",
                "SLIM_BINARY": False,
                "OUTPUT_FORMAT": "json",
                "EXCLUDE_TYPES": [],
                "EXCLUDE_PATHS": [],
                "RECURSE": True,
                "DEBUG_PIPELINES": [],
                "REQUIRED_ONLY_PIPELINES": [],
                "BUILD_FAILURE_PATTERNS": ["BUILD FAILED", r"npm ERR!\s+code\s+E\d+"]
            }
        }

        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value='/usr/local/bin/cdxgen'):
            with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                result = self.cdxgen.get_components(self.artifact, config, self.service_name)

        self.assertEqual(result, self.mock_components)
        mock_run.assert_called_once_with(
            '/usr/local/bin/cdxgen', self.artifact, self.service_name, [], [], True, True, False, False, '1.6',
            ["BUILD FAILED", r"npm ERR!\s+code\s+E\d+"]
        )

    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.get_list_component')
    @patch('devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.cdxgen.cdxgen.platform.system')
    def test_get_components_no_build_failure_patterns_configured(self, mock_platform, mock_get_list_component):
        """When the config does not define BUILD_FAILURE_PATTERNS, an empty list is used (no defaults)."""
        mock_platform.return_value = "Linux"
        mock_get_list_component.return_value = self.mock_components

        with patch.object(self.cdxgen, '_check_cdxgen_in_path', return_value='/usr/local/bin/cdxgen'):
            with patch.object(self.cdxgen, '_run_cdxgen', return_value='test_service_SBOM.json') as mock_run:
                result = self.cdxgen.get_components(self.artifact, self.mock_config, self.service_name)

        self.assertEqual(result, self.mock_components)
        mock_run.assert_called_once_with(
            '/usr/local/bin/cdxgen', self.artifact, self.service_name, [], [], True, True, False, False, '1.6', []
        )
