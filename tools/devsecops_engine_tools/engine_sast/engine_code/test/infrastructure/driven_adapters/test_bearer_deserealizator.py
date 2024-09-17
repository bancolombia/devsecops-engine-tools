import unittest
from unittest.mock import patch, mock_open
from datetime import datetime
import json
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
from devsecops_engine_tools.engine_sast.engine_code.src.infrastructure.driven_adapters.bearer.bearer_deserealizator import (
    BearerDeserealizator,
)

class TestBearerDeserealizator(unittest.TestCase):

    @patch("builtins.open", 
           new_callable=mock_open, 
           read_data=json.dumps({
                "high": [
                    {
                        "id": "vul1",
                        "description": "## Description\nThis is a vulnerability description.\n##",
                        "full_filename": "/agent/work/folder/test/file1.js"
                    }
                ],
                "medium": [
                    {
                        "id": "vul2",
                        "description": "## Description\nAnother vulnerability description.\n##",
                        "full_filename": "/agent/work/folder/test/file2.js"
                    }
                ]
            }
        )
    )
    def test_get_list_finding(self, mock_open):
        # Arrange
        expected_findings = [
            Finding(
                id="vul1",
                cvss="",
                where="/test/file1.js",
                description="This is a vulnerability description.\n",
                severity="high",
                identification_date=datetime.now().strftime("%d%m%Y"),
                published_date_cve=None,
                module="engine_code",
                category=Category.VULNERABILITY,
                requirements="",
                tool="Bearer"
            ),
            Finding(
                id="vul2",
                cvss="",
                where="/test/file2.js",
                description="Another vulnerability description.\n",
                severity="medium",
                identification_date=datetime.now().strftime("%d%m%Y"),
                published_date_cve=None,
                module="engine_code",
                category=Category.VULNERABILITY,
                requirements="",
                tool="Bearer"
            )
        ]

        # Act
        findings = BearerDeserealizator.get_list_finding("test_path.json", "/agent/work/folder", list_rules=["vul1", "vul2"])
        
        # Assert
        self.assertEqual(len(findings), 2)
        mock_open.assert_called_once_with("test_path.json", encoding="utf-8")
        for finding, expected_finding in zip(findings, expected_findings):
            self.assertEqual(finding.id, expected_finding.id)
            self.assertEqual(finding.where, expected_finding.where)
            self.assertEqual(finding.description, expected_finding.description)
            self.assertEqual(finding.severity, expected_finding.severity)
            self.assertEqual(finding.identification_date, expected_finding.identification_date)
            self.assertEqual(finding.module, expected_finding.module)
            self.assertEqual(finding.category, expected_finding.category)
            self.assertEqual(finding.tool, expected_finding.tool)

    @patch(
        "builtins.open", 
        new_callable=mock_open
    )
    @patch(
        "json.load", 
        side_effect=ValueError("Invalid JSON")
    )
    def test_get_list_finding_invalid_json(self, mock_json_load, mock_open):
        # Act
        findings = BearerDeserealizator.get_list_finding("test_path.json", "/agent/work/folder")
        
        # Assert
        mock_open.assert_called_once_with("test_path.json", encoding="utf-8")
        mock_json_load.assert_called_once()
        self.assertEqual(findings, [])
