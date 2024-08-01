import unittest
from unittest.mock import patch
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_deserealizator import (
    KicsDeserealizator
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kics.kics_tool import (
    KicsTool
)
from datetime import datetime

class TestKicsDeserealizator(unittest.TestCase):

    def setUp(self):
        self.deserealizator = KicsDeserealizator()

    def test_get_list_finding_empty_list(self):
        results_scan_list = []
        expected_list = []

        actual_list = self.deserealizator.get_list_finding(results_scan_list)

        self.assertEqual(actual_list, expected_list)

    def test_get_list_finding_single_finding(self):
        results_scan_list = [
            {
                "severity": "High",
                "description": "Test",
                "file_name": "/some/path",
                "id": "1"
            }
        ]
        expected_list = [
            Finding(
                id="1",
                cvss=None,
                where="/some/path",
                description="Test",
                severity="high",
                identification_date=datetime.now().strftime("%d%m%Y"),
                published_date_cve=None,
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="Kics"
            )
        ]

        actual_list = self.deserealizator.get_list_finding(results_scan_list)

        self.assertEqual(len(actual_list), 1)
        self.assertEqual(actual_list[0], expected_list[0])

    def test_get_findings_empty_data(self):
        data = {}
        expected = []
        result = self.deserealizator.get_findings(data)
        self.assertEqual(result, expected)

    def test_get_findings_queries_with_various_severities(self):
        data = {
            "queries": [
                {
                    "severity": "LOW",
                    "query_name": "Test Query 1",
                    "query_id": "1",
                    "files": [
                        {"file_name": "file1.py"}
                    ]
                },
                {
                    "severity": "MEDIUM",
                    "query_name": "Test Query 2",
                    "query_id": "2",
                    "files": [
                        {"file_name": "file2.py"}
                    ]
                },
                {
                    "severity": "HIGH",
                    "query_name": "Test Query 3",
                    "query_id": "3",
                    "files": [
                        {"file_name": "file3.py"}
                    ]
                },
                {
                    "severity": "CRITICAL",
                    "query_name": "Test Query 4",
                    "query_id": "4",
                    "files": [
                        {"file_name": "file4.py"}
                    ]
                },
                {
                    "severity": "INFO",
                    "query_name": "Test Query 5",
                    "query_id": "5",
                    "files": [
                        {"file_name": "file5.py"}
                    ]
                }
            ]
        }
        expected = [
            {"severity": "LOW", "description": "Test Query 1", "file_name": "file1.py", "id": "1"},
            {"severity": "MEDIUM", "description": "Test Query 2", "file_name": "file2.py", "id": "2"},
            {"severity": "HIGH", "description": "Test Query 3", "file_name": "file3.py", "id": "3"},
            {"severity": "CRITICAL", "description": "Test Query 4", "file_name": "file4.py", "id": "4"}
        ]
        result = self.deserealizator.get_findings(data)
        self.assertEqual(result, expected)

    def test_get_finding_queries_with_no_files(self):
        data = {
            "queries": [
                {
                    "severity": "HIGH",
                    "query_name": "Test Query 1",
                    "query_id": "1",
                    "files": []
                }
            ]
        }
        expected = []
        result = self.deserealizator.get_findings(data)
        self.assertEqual(result, expected)

    def test_calculate_total_vulnerabilities_empty_data(self):
        data = {}
        expected = 0
        result = self.deserealizator.calculate_total_vulnerabilities(data)
        self.assertEqual(result, expected)

    def test_calculate_total_vulnerabilities_no_vulnerabilities(self):
        data = {"severity_counters": {}}
        expected = 0
        result = self.deserealizator.calculate_total_vulnerabilities(data)
        self.assertEqual(result, expected)

    def test_calculate_total_vulnerabilities_with_vulnerabilities(self):
        data = {
            "severity_counters": {
                "CRITICAL": 10,
                "HIGH": 5,
                "MEDIUM": 2,
                "LOW": 1
            }
        }
        expected = 18
        result = self.deserealizator.calculate_total_vulnerabilities(data)
        self.assertEqual(result, expected)