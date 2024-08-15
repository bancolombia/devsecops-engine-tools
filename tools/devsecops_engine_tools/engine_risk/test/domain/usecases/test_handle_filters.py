import unittest
from unittest.mock import MagicMock, patch
from devsecops_engine_tools.engine_risk.src.domain.usecases.handle_filters import (
    HandleFilters,
)
from devsecops_engine_tools.engine_core.src.domain.model.report import Report


class TestHandleFilters(unittest.TestCase):
    def setUp(self):
        self.findings = [
            Report(
                id=[{"vulnerability_id": "CVE-2021-1234"}],
                date="21022024",
                status="stat2",
                where="path",
                tags=["tag1"],
                severity="low",
                active=True,
            ),
            Report(
                id=[{"vulnerability_id": "CVE-2021-1234"}],
                date="21022024",
                status="stat2",
                where="path2",
                tags=["tag2"],
                severity="low",
                active=None,
            ),
            Report(
                id=[{"vulnerability_id": "vuln_id"}],
                date="21022024",
                status="stat3",
                where="path3",
                tags=["tag3"],
                severity="info",
                active=True,
            ),
        ]
        self.handle_filters = HandleFilters()

    @patch(
        "devsecops_engine_tools.engine_risk.src.domain.usecases.handle_filters.HandleFilters._get_active_findings"
    )
    @patch(
        "devsecops_engine_tools.engine_risk.src.domain.usecases.handle_filters.HandleFilters._get_priority_vulnerability"
    )
    def test_filter(self, mock_get_priority_vulnerability, mock_get_active_findings):
        mock_get_active_findings.return_value = ["Finding1", "Finding2"]

        result = self.handle_filters.filter(self.findings)

        assert len(result) == 2
    
    def test__get_active_findings(self):
        result = self.handle_filters._get_active_findings(self.findings)

        assert len(result) == 2

    def test__get_priority_vulnerability(self):
        result = self.handle_filters._get_priority_vulnerability(self.findings)

        assert len(result) == 3
