import unittest
from unittest.mock import patch
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding, Category
from devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_deserealizator import (
    GitleaksDeserealizator
)

class TestGitleaksDeserealizator(unittest.TestCase):

    def setUp(self):
        self.deserealizator = GitleaksDeserealizator()

    @patch("devsecops_engine_tools.engine_sast.engine_secret.src.infrastructure.driven_adapters.gitleaks.gitleaks_deserealizator.datetime")
    def test_get_list_vulnerability(self, MockDatetime):
        # Arrange
        MockDatetime.now.return_value.strftime.return_value = "27012024"

        results_scan_list = [
            {
                "RuleID": "GITLEAKS_RULE_1",
                "Description": "Hardcoded secret found",
                "File": "/path/to/repo/file1.txt",
                "Secret": "ABCDEFG123456789"
            },
            {
                "RuleID": "GITLEAKS_RULE_2",
                "Description": "API key detected",
                "File": "/path/to/repo/file2.txt",
                "Secret": "ABCDEFG123456789"
            }
        ]
        os = "Linux"
        path_directory = "/path/to/repo"
        
        # Act
        vulnerabilities = self.deserealizator.get_list_vulnerability(results_scan_list, path_directory, os)
        
        # Assert
        self.assertEqual(len(vulnerabilities), 2)

        vulnerability = vulnerabilities[0]
        self.assertIsInstance(vulnerability, Finding)
        self.assertEqual(vulnerability.id, "GITLEAKS_RULE_1")
        self.assertEqual(vulnerability.description, "Hardcoded secret found")
        self.assertEqual(vulnerability.severity, "critical")
        self.assertEqual(vulnerability.identification_date, "27012024")
        self.assertEqual(vulnerability.tool, "Gitleaks")
        self.assertEqual(vulnerability.category, Category.VULNERABILITY)
        self.assertEqual(vulnerability.where, "/file1.txt, Secret: ABC*********789")

        vulnerability2 = vulnerabilities[1]
        self.assertEqual(vulnerability2.id, "GITLEAKS_RULE_2")
        self.assertEqual(vulnerability2.description, "API key detected")
        self.assertEqual(vulnerability2.where, "/file2.txt, Secret: ABC*********789")

    def test_get_where_correctly(self):
        # Arrange
        result = {
            "File": "/path/to/repo/file1.txt",
            "Secret": "ABCDEFG123456789"
        }
        path_directory = "/path/to/repo"
        
        # Act
        where_correctly = self.deserealizator.get_where_correctly(result, path_directory)
        
        # Assert
        self.assertEqual(where_correctly, "/file1.txt, Secret: ABC*********789")
