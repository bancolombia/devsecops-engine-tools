import unittest
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_deserealizator import (
    KubescapeDeserealizator
)
from datetime import datetime


class TestKubescapeDeserealizator(unittest.TestCase):

    def setUp(self):
        self.deserealizator = KubescapeDeserealizator()

    def test_get_list_finding_empty_list(self):
        results_scan_list = []
        expected_list = []

        actual_list = self.deserealizator.get_list_finding(results_scan_list)

        self.assertEqual(actual_list, expected_list)

    def test_get_list_finding_single_finding(self):
        results_scan_list = [
            {
                "id": "1",
                "where": "/some/path",
                "description": "Test finding",
                "severity": "High"
            }
        ]
        expected_list = [
            Finding(
                id="1",
                cvss=None,
                where="/some/path",
                description="Test finding",
                severity="high",
                identification_date=datetime.now().strftime("%d%m%Y"),
                published_date_cve=None,
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="kubescape"
            )
        ]

        actual_list = self.deserealizator.get_list_finding(results_scan_list)

        self.assertEqual(len(actual_list), 1)
        self.assertEqual(actual_list[0], expected_list[0])

    def test_extract_failed_controls_no_failures(self):
        data = {
            "results": [
                {
                    "resourceID": "res1",
                    "controls": [
                        {"controlID": "ctrl1", "status": {"status": "passed"}}
                    ]
                }
            ],
            "resources": [
                {"resourceID": "res1", "source": {"relativePath": "path/to/res1"}}
            ],
            "summaryDetails": {
                "frameworks": []
            }
        }
        result = self.deserealizator.extract_failed_controls(data)
        self.assertEqual(result, [])

    def test_extract_failed_controls_with_failures(self):
        data = {
            "results": [
                {
                    "resourceID": "res1",
                    "controls": [
                        {"controlID": "ctrl1", "name": "Control 1", "status": {"status": "failed"}}
                    ]
                }
            ],
            "resources": [
                {"resourceID": "res1", "source": {"path": "path/to/res1"}}
            ],
            "summaryDetails": {
                "frameworks": [{"controls": {"ctrl1": {"scoreFactor": 5}}}]
            }
        }
        result = self.deserealizator.extract_failed_controls(data)
        expected_result = [{
            "id": "ctrl1",
            "description": "Control 1",
            "where": "path/to/res1",
            "severity": "medium"
        }]
        self.assertEqual(result, expected_result)

    def test_get_severity_score_none(self):
        frameworks = [{"controls": {"control1": {"scoreFactor": 0.0}}}]
        result = self.deserealizator.get_severity_score(frameworks, "control1")
        self.assertEqual(result, "none")

    def test_get_severity_score_medium(self):
        frameworks = [{"controls": {"control1": {"scoreFactor": 5.0}}}]
        result = self.deserealizator.get_severity_score(frameworks, "control1")
        self.assertEqual(result, "medium")

    def test_get_severity_score_high(self):
        frameworks = [{"controls": {"control1": {"scoreFactor": 8.0}}}]
        result = self.deserealizator.get_severity_score(frameworks, "control1")
        self.assertEqual(result, "high")

    def test_get_severity_score_critical(self):
        frameworks = [{"controls": {"control1": {"scoreFactor": 9.5}}}]
        result = self.deserealizator.get_severity_score(frameworks, "control1")
        self.assertEqual(result, "critical")
