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
                },
                {
                    "DetectorName": "ExampleDetector",
                    "SourceMetadata": {
                        "Data": {
                            "Filesystem": {
                                "line": 20,
                                "file": "/path/to/file.py"
                            }
                        }
                    },
                    "ExtraData": {
                        "name" : "ActuatorRule"
                    },
                    "Raw": "management.endpoints.web.exposure.include=env,heapdump,threaddump,loggers"
                }
            ]
            
            # Testing the method
            vulnerabilities = self.deserealizator.get_list_vulnerability(results_scan_list, "Linux", "/path/to", )

            # Assertions
            self.assertEqual(len(vulnerabilities), 2)
            vulnerabilitySecret = vulnerabilities[0]
            self.assertIsInstance(vulnerabilitySecret, Finding)
            self.assertEqual(vulnerabilitySecret.id, "SECRET_SCANNING")
            self.assertIsNone(vulnerabilitySecret.cvss)
            self.assertEqual(vulnerabilitySecret.where, "/file.py, Secret: sec*********ret")
            self.assertEqual(vulnerabilitySecret.description, "Sensitive information in source code")
            self.assertEqual(vulnerabilitySecret.severity, "critical")
            self.assertEqual(vulnerabilitySecret.identification_date, datetime.now().strftime("%d%m%Y"))
            self.assertEqual(vulnerabilitySecret.module, "engine_secret")
            self.assertEqual(vulnerabilitySecret.category, Category.VULNERABILITY)
            self.assertEqual(vulnerabilitySecret.requirements, "ExampleDetector")
            self.assertEqual(vulnerabilitySecret.tool, "Trufflehog")
            vulnerabilityActuator = vulnerabilities[1]
            self.assertIsInstance(vulnerabilityActuator, Finding)
            self.assertEqual(vulnerabilityActuator.id, "MISCONFIGURATION_SCANNING")
            self.assertIsNone(vulnerabilityActuator.cvss)
            self.assertEqual(vulnerabilityActuator.where, "/file.py, Misconfiguration: man*********ers")
            self.assertEqual(vulnerabilityActuator.description, "Actuator misconfiguration can leak sensitive information")
            self.assertEqual(vulnerabilityActuator.severity, "critical")
            self.assertEqual(vulnerabilityActuator.identification_date, datetime.now().strftime("%d%m%Y"))
            self.assertEqual(vulnerabilityActuator.module, "engine_secret")
            self.assertEqual(vulnerabilityActuator.category, Category.VULNERABILITY)
            self.assertEqual(vulnerabilityActuator.requirements, "ExampleDetector")
            self.assertEqual(vulnerabilityActuator.tool, "Trufflehog")
            

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