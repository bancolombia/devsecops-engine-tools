import unittest
from datetime import datetime
from unittest.mock import patch
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.trufflehog.trufflehog_deserealizator import SecretScanDeserealizator, Finding, Category

class TestSecretScanDeserealizator(unittest.TestCase):

    def setUp(self):
        self.deserealizator = SecretScanDeserealizator()

    def test_get_list_vulnerability(self):
        results_scan_list = [
            {"SourceMetadata": {"Data": {"Filesystem": {"line": 10, "file": "/path/to/file.txt"}}},
             "DetectorName": "SensitiveDataDetector"},
            {"SourceMetadata": {"Data": {"Filesystem": {"line": None, "file": "/path/to/another_file.txt"}}},
             "DetectorName": "SecretFinder"}
        ]
        os_patch = patch.dict('os.environ', {'AGENT_OS': 'Linux'})
        os_patch.start()
        self.addCleanup(os_patch.stop)
        expected_findings = [
            Finding(
                id="SECRET_SCANNING",
                cvss=None,
                where="/path/to/file.txt, Line: 10",
                description="Sensitive information in source code",
                severity="critical",
                identification_date=datetime.now().strftime("%d%m%Y"),
                module="Sast-secrets manager",
                category=Category.VULNERABILITY,
                requirements="SensitiveDataDetector",
                tool="Trufflehog"
            ),
            Finding(
                id="SECRET_SCANNING",
                cvss=None,
                where="/path/to/another_file.txt, Line: Multiline",
                description="Sensitive information in source code",
                severity="critical",
                identification_date=datetime.now().strftime("%d%m%Y"),
                module="Sast-secrets manager",
                category=Category.VULNERABILITY,
                requirements="SecretFinder",
                tool="Trufflehog"
            )
        ]
        self.assertEqual(self.deserealizator.get_list_vulnerability(results_scan_list), expected_findings)

    def test_get_where_correctly(self):
        result = {"SourceMetadata": {"Data": {"Filesystem": {"line": 10, "file": "/path/to/file.txt"}}}}
        os_patch = patch.dict('os.environ', {'AGENT_OS': 'Windows'})
        os_patch.start()
        self.addCleanup(os_patch.stop)
        expected_result = ("/path/to/file.txt", "10")
        self.assertEqual(self.deserealizator.get_where_correctly(result), expected_result)

    def test_get_where_correctly_linux(self):
        result = {"SourceMetadata": {"Data": {"Filesystem": {"line": 10, "file": r"\path\to\file.txt"}}}}
        os_patch = patch.dict('os.environ', {'AGENT_OS': 'Linux'})
        os_patch.start()
        self.addCleanup(os_patch.stop)
        expected_result = ("/path/to/file.txt", "10")
        self.assertEqual(self.deserealizator.get_where_correctly(result), expected_result)
