import unittest
from unittest.mock import patch
from datetime import datetime
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding, Category
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_deserealizator import SecretScanDeserealizator

class TestSecretScanDeserealizator(unittest.TestCase):

    def setUp(self):
        self.deserealizator = SecretScanDeserealizator()

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
                    },
                    "Raw": "secret"
                }
            ]
            
            # Testing the method
            vulnerabilities = self.deserealizator.get_list_vulnerability(results_scan_list, "Linux", "/path/to", )

            # Assertions
            self.assertEqual(len(vulnerabilities), 1)
            vulnerability = vulnerabilities[0]
            self.assertIsInstance(vulnerability, Finding)
            self.assertEqual(vulnerability.id, "SECRET_SCANNING")
            self.assertIsNone(vulnerability.cvss)
            self.assertEqual(vulnerability.where, "/file.py, Secret: sec*********ret")
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
                },
                "Raw": "secret"
            }
            self.assertEqual(
                self.deserealizator.get_where_correctly(result, "linux", "/path/to", ),
                ("/file.py", "sec*********ret")
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
                },
                "Raw": "secret"
            }
            
            self.assertEqual(
                self.deserealizator.get_where_correctly(result,  "Win", "C:\\path\\to", ),
                ("\\file.py", "sec*********ret")
            )