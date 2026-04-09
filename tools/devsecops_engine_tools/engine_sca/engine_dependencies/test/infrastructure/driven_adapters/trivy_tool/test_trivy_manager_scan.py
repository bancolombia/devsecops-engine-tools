import unittest
import json
from unittest.mock import patch, Mock, mock_open
from devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan import TrivyScanSBOM
from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.context_dependencies import ContextDependencies


class TestTrivyScanSBOM(unittest.TestCase):

    def setUp(self):
        self.trivy_scanner = TrivyScanSBOM()
        self.sample_sbom_path = "/tmp/test_pipeline_SBOM.json"
        self.sample_result_path = "/tmp/test_pipeline_SBOM_scan_result.json"

        # Mock data for tests
        self.mock_remote_config = {
            "TRIVY": {
                "TRIVY_VERSION": "0.45.0"
            }
        }

        self.mock_trivy_result = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-12345",
                            "Severity": "HIGH",
                            "PkgID": "package@1.0.0",
                            "PkgName": "test-package",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.1, 1.0.2",
                            "Description": "Test vulnerability description\nwith newlines",
                            "References": ["https://example.com/cve-2021-12345"]
                        },
                        {
                            "VulnerabilityID": "CVE-2021-67890",
                            "Severity": "MEDIUM",
                            "PkgID": "another-package@2.0.0",
                            "PkgName": "another-package",
                            "InstalledVersion": "2.0.0",
                            "FixedVersion": "2.1.0",
                            "Description": "Another test vulnerability",
                            "References": ["https://example.com/cve-2021-67890"]
                        }
                    ]
                }
            ]
        }

    @patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.subprocess.run')
    def test_scan_dependencies_sbom_success(self, mock_subprocess_run):
        # Arrange
        command_prefix = "/usr/bin/trivy"
        sbom_path = self.sample_sbom_path
        expected_result_file = self.sample_result_path

        mock_subprocess_run.return_value = Mock(returncode=0)

        # Act
        with patch('builtins.print') as mock_print:
            result = self.trivy_scanner._scan_dependencies_sbom(command_prefix, sbom_path)

        # Assert
        self.assertEqual(result, expected_result_file)
        mock_subprocess_run.assert_called_once_with(
            [command_prefix, "sbom", sbom_path, "-f", "json", "--scanners", "vuln", "-o", expected_result_file],
            check=True,
            stdout=unittest.mock.ANY,
            stderr=unittest.mock.ANY,
            text=True
        )
        mock_print.assert_called_once_with(f"The SBOM {sbom_path} was scanned")

    @patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.logger')
    @patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.subprocess.run')
    def test_scan_dependencies_sbom_failure(self, mock_subprocess_run, mock_logger):
        # Arrange
        command_prefix = "/usr/bin/trivy"
        sbom_path = self.sample_sbom_path
        error_message = "Command failed"

        mock_subprocess_run.side_effect = Exception(error_message)

        # Act & Assert
        with self.assertRaises(Exception) as context:
            self.trivy_scanner._scan_dependencies_sbom(command_prefix, sbom_path)

        self.assertEqual(str(context.exception), error_message)
        mock_logger.error.assert_called_once_with(f"Error during SBOM scan of {sbom_path}: {error_message}")

    @patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.os.path.exists')
    @patch('devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils.identify_os_and_install')
    def test_run_tool_dependencies_sca_success(self, mock_identify_os, mock_exists):
        # Arrange
        mock_identify_os.return_value = "/usr/bin/trivy"
        mock_exists.return_value = True

        dict_args = {}
        exclusion = []
        pipeline_name = "test_pipeline"
        to_scan = []
        secret_tool = None
        token_engine_dependencies = "test_token"

        expected_result_file = f"{pipeline_name}_SBOM_scan_result.json"

        # Act
        with patch.object(self.trivy_scanner, '_scan_dependencies_sbom', return_value=expected_result_file) as mock_scan:
            result = self.trivy_scanner.run_tool_dependencies_sca(
                self.mock_remote_config,
                dict_args,
                exclusion,
                pipeline_name,
                to_scan,
                secret_tool,
                token_engine_dependencies
            )

        # Assert
        self.assertEqual(result, expected_result_file)
        mock_identify_os.assert_called_once_with("0.45.0")
        mock_scan.assert_called_once_with("/usr/bin/trivy", f"{pipeline_name}_SBOM.json")

    @patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.os.path.exists')
    @patch('devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils.identify_os_and_install')
    def test_run_tool_dependencies_sca_no_command_prefix(self, mock_identify_os, mock_exists):
        # Arrange
        mock_identify_os.return_value = None

        dict_args = {}
        exclusion = []
        pipeline_name = "test_pipeline"
        to_scan = []
        secret_tool = None
        token_engine_dependencies = "test_token"

        # Act
        result = self.trivy_scanner.run_tool_dependencies_sca(
            self.mock_remote_config,
            dict_args,
            exclusion,
            pipeline_name,
            to_scan,
            secret_tool,
            token_engine_dependencies
        )

        # Assert
        self.assertIsNone(result)

    @patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.os.path.exists')
    @patch('devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils.identify_os_and_install')
    def test_run_tool_dependencies_sca_sbom_not_found(self, mock_identify_os, mock_exists):
        # Arrange
        mock_identify_os.return_value = "/usr/bin/trivy"
        mock_exists.return_value = False

        dict_args = {}
        exclusion = []
        pipeline_name = "test_pipeline"
        to_scan = []
        secret_tool = None
        token_engine_dependencies = "test_token"

        # Act & Assert
        with self.assertRaises(FileNotFoundError) as context:
            self.trivy_scanner.run_tool_dependencies_sca(
                self.mock_remote_config,
                dict_args,
                exclusion,
                pipeline_name,
                to_scan,
                secret_tool,
                token_engine_dependencies
            )

        self.assertEqual(str(context.exception), "SBOM file not found, enable SBOM generation to scan with Trivy.")

    def test_get_dependencies_context_from_results_success(self):
        # Arrange
        mock_file_content = json.dumps(self.mock_trivy_result).encode()
        expected_contexts_count = 2

        # Act
        with patch('builtins.open', mock_open(read_data=mock_file_content)):
            result = self.trivy_scanner.get_dependencies_context_from_results(
                self.sample_result_path,
                self.mock_remote_config
            )

        # Assert - verificar que retorna una lista con el número correcto de contextos
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), expected_contexts_count)

        # Verificar el contenido de los contextos
        self.assertEqual(result[0].cve_id, ["CVE-2021-12345"])
        self.assertEqual(result[0].severity, "high")
        self.assertEqual(result[1].cve_id, ["CVE-2021-67890"])
        self.assertEqual(result[1].severity, "medium")

    def test_get_dependencies_context_from_results_with_context_creation(self):
        # Arrange
        mock_file_content = json.dumps(self.mock_trivy_result).encode()

        # Act
        with patch('builtins.open', mock_open(read_data=mock_file_content)):
            result = self.trivy_scanner.get_dependencies_context_from_results(
                self.sample_result_path,
                self.mock_remote_config
            )

        # Assert - verificar el contenido de la lista retornada
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)

        # Verificar el primer contexto
        first_context = result[0]
        self.assertEqual(first_context.cve_id, ["CVE-2021-12345"])
        self.assertEqual(first_context.severity, "high")
        self.assertEqual(first_context.component, "package@1.0.0")
        self.assertEqual(first_context.package_name, "test-package")
        self.assertEqual(first_context.installed_version, "1.0.0")
        self.assertEqual(first_context.fixed_version, ["1.0.1", "1.0.2"])
        self.assertEqual(first_context.description, "Test vulnerability descriptionwith newlines")
        self.assertEqual(first_context.source_tool, "Trivy")

        # Verificar el segundo contexto
        second_context = result[1]
        self.assertEqual(second_context.cve_id, ["CVE-2021-67890"])
        self.assertEqual(second_context.severity, "medium")
        self.assertEqual(second_context.component, "another-package@2.0.0")

    def test_get_dependencies_context_from_results_empty_results(self):
        # Arrange
        empty_result = {"Results": []}
        mock_file_content = json.dumps(empty_result).encode()

        # Act
        with patch('builtins.open', mock_open(read_data=mock_file_content)):
            result = self.trivy_scanner.get_dependencies_context_from_results(
                self.sample_result_path,
                self.mock_remote_config
            )

        # Assert
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_get_dependencies_context_from_results_missing_vulnerabilities(self):
        # Arrange
        result_without_vulns = {"Results": [{}]}
        mock_file_content = json.dumps(result_without_vulns).encode()

        # Act
        with patch('builtins.open', mock_open(read_data=mock_file_content)):
            result = self.trivy_scanner.get_dependencies_context_from_results(
                self.sample_result_path,
                self.mock_remote_config
            )

        # Assert
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_get_dependencies_context_from_results_unknown_values(self):
        # Arrange
        result_with_missing_fields = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            # Solo algunos campos presentes para probar valores "unknown"
                            "VulnerabilityID": "CVE-2021-99999",
                            "Severity": "LOW"
                            # Faltan otros campos
                        }
                    ]
                }
            ]
        }
        mock_file_content = json.dumps(result_with_missing_fields).encode()

        # Act
        with patch('builtins.open', mock_open(read_data=mock_file_content)):
            result = self.trivy_scanner.get_dependencies_context_from_results(
                self.sample_result_path,
                self.mock_remote_config
            )

        # Assert
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)

        context = result[0]
        self.assertEqual(context.cve_id, ["CVE-2021-99999"])
        self.assertEqual(context.severity, "low")
        self.assertEqual(context.component, "unknown")
        self.assertEqual(context.package_name, "unknown")
        self.assertEqual(context.installed_version, "unknown")
        self.assertEqual(context.fixed_version, ["unknown"])
        self.assertEqual(context.description, "unknown")
        self.assertEqual(context.references, "unknown")

    @patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.os.path.exists')
    @patch('devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils.identify_os_and_install')
    def test_run_tool_dependencies_sca_backward_compat_cli_version(self, mock_identify_os, mock_exists):
        """Test backward compatibility: CLI_VERSION should still work"""
        # Arrange - using CLI_VERSION instead of TRIVY_VERSION
        legacy_config = {
            "TRIVY": {
                "CLI_VERSION": "0.50.0"
            }
        }
        mock_identify_os.return_value = "/usr/bin/trivy"
        mock_exists.return_value = True

        dict_args = {}
        exclusion = []
        pipeline_name = "test_pipeline"
        to_scan = []
        secret_tool = None
        token_engine_dependencies = "test_token"

        expected_result_file = f"{pipeline_name}_SBOM_scan_result.json"

        # Act
        with patch.object(self.trivy_scanner, '_scan_dependencies_sbom', return_value=expected_result_file) as mock_scan:
            result = self.trivy_scanner.run_tool_dependencies_sca(
                legacy_config,
                dict_args,
                exclusion,
                pipeline_name,
                to_scan,
                secret_tool,
                token_engine_dependencies
            )

        # Assert - should use CLI_VERSION value
        self.assertEqual(result, expected_result_file)
        mock_identify_os.assert_called_once_with("0.50.0")
        mock_scan.assert_called_once_with("/usr/bin/trivy", f"{pipeline_name}_SBOM.json")

    @patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.os.path.exists')
    @patch('devsecops_engine_tools.engine_utilities.trivy_utils.infrastructure.driven_adapters.trivy_manager_scan_utils.TrivyManagerScanUtils.identify_os_and_install')
    @patch('devsecops_engine_tools.engine_sca.engine_dependencies.src.infrastructure.driven_adapters.trivy_tool.trivy_manager_scan.logger')
    def test_run_tool_dependencies_sca_no_version(self, mock_logger, mock_identify_os, mock_exists):
        """Test error when no version key is present"""
        # Arrange - config with neither TRIVY_VERSION nor CLI_VERSION
        bad_config = {
            "TRIVY": {
                "PRINT_SBOM": ["pipeline_name_1"]
            }
        }
        mock_exists.return_value = True

        dict_args = {}
        exclusion = []
        pipeline_name = "test_pipeline"
        to_scan = []
        secret_tool = None
        token_engine_dependencies = "test_token"

        # Act
        result = self.trivy_scanner.run_tool_dependencies_sca(
            bad_config,
            dict_args,
            exclusion,
            pipeline_name,
            to_scan,
            secret_tool,
            token_engine_dependencies
        )

        # Assert - should return None and log error
        self.assertIsNone(result)
        mock_logger.error.assert_called_once()
        self.assertIn("Trivy version not found", mock_logger.error.call_args[0][0])
