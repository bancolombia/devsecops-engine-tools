import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding, Category
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.devops_platform_gateway import DevopsPlatformGateway
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_deserealizator import SecretScanDeserealizator

class TestSecretScanDeserealizator(unittest.TestCase):

    def setUp(self):
        self.deserealizator = SecretScanDeserealizator()
        self.mock_devops_gateway = MagicMock(spec=DevopsPlatformGateway)

    def test_get_list_vulnerability(self):
        with patch.dict('os.environ', {'AGENT_OS': 'Linux'}):
            results_scan_list = [
                {
                    "DetectorName": "ExampleDetector",
                    "SourceMetadata": {
                        "Data": {
                            "Filesystem": {
                                "line": 10,
                                "file": "/path/to/file.py"
                            }
                        }
                    }
                }
            ]
            
            # Mocking the return value of get_variable method
            self.mock_devops_gateway.get_variable.return_value = "/path/to"
            
            # Testing the method
            vulnerabilities = self.deserealizator.get_list_vulnerability(results_scan_list, self.mock_devops_gateway)

            # Assertions
            self.assertEqual(len(vulnerabilities), 1)
            vulnerability = vulnerabilities[0]
            self.assertIsInstance(vulnerability, Finding)
            self.assertEqual(vulnerability.id, "SECRET_SCANNING")
            self.assertIsNone(vulnerability.cvss)
            self.assertEqual(vulnerability.where, "/file.py, Line: 10")
            self.assertEqual(vulnerability.description, "Sensitive information in source code")
            self.assertEqual(vulnerability.severity, "critical")
            self.assertEqual(vulnerability.identification_date, datetime.now().strftime("%d%m%Y"))
            self.assertEqual(vulnerability.module, "engine_secret")
            self.assertEqual(vulnerability.category, Category.VULNERABILITY)
            self.assertEqual(vulnerability.requirements, "ExampleDetector")
            self.assertEqual(vulnerability.tool, "Trufflehog")

    def test_get_where_correctly_linux(self):
        with patch.dict('os.environ', {'AGENT_OS': 'Linux'}):
            result = {
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "line": 10,
                            "file": r"/path/to/file.py"  # Simulating Linux path
                        }
                    }
                }
            }
            self.mock_devops_gateway.get_variable.return_value = "/path/to"
            self.assertEqual(
                self.deserealizator.get_where_correctly(result, self.mock_devops_gateway),
                ("/file.py", "10")
            )

    def test_get_where_correctly_windows(self):
        with patch.dict('os.environ', {'AGENT_OS': 'Windows'}):
            result = {
                "SourceMetadata": {
                    "Data": {
                        "Filesystem": {
                            "line": 10,
                            "file": r"C:\path\to\file.py"  # Simulating Windows path
                        }
                    }
                }
            }
            
            self.mock_devops_gateway.get_variable.return_value = "C:\\path\\to"
            self.assertEqual(
                self.deserealizator.get_where_correctly(result, self.mock_devops_gateway),
                ("\\file.py", "10")
            )