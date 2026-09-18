import unittest
import pytest
from unittest.mock import patch
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.printer_pretty_table.printer_pretty_table import (
    PrinterPrettyTable,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding, EngineCodeFinding
from devsecops_engine_tools.engine_core.src.domain.model.report import Report


class TestPrinterPrettyTable(unittest.TestCase):
    @patch("builtins.print")
    def test_print_table_with_findings_engine_iac(self, mock_print):
        # Arrange
        finding_list = [
            Finding(
                id="1",
                cvss="7.8",
                where="Location 1",
                description="Description 1",
                severity="high",
                identification_date="2021-01-01",
                published_date_cve=None,
                module="engine_iac",
                category="vulnerability",
                requirements="Requirement 1",
                tool="Tool 1",
            )
        ]
        printer = PrinterPrettyTable()
        manager = {"MODEL": "severity", "CLASSIFICATION": ["critical", "high", "medium", "low"]}

        # Act
        printer.print_table_findings(finding_list, manager)

        # Assert
        assert mock_print.called
        # Add more assertions to validate the output

    @patch("builtins.print")
    def test_print_table_with_findings_engine_container(self, mock_print):
        # Arrange
        finding_list = [
            Finding(
                id="1",
                cvss="7.8",
                where="Location 1",
                description="Description 1",
                severity="high",
                identification_date="2021-01-01",
                published_date_cve="2021-01-01",
                module="engine_container",
                category="vulnerability",
                requirements="Requirement 1",
                tool="Tool 1",
            ),
            Finding(
                id="2",
                cvss="2.4",
                where="Location 2",
                description="Description 2",
                severity="medium",
                identification_date="2021-01-02",
                published_date_cve="2021-01-01",
                module="engine_container",
                category="compliance",
                requirements="Requirement 2",
                tool="Tool 2",
            ),
            Finding(
                id="3",
                cvss="5.6",
                where="Location 3",
                description="Description 3",
                severity="low",
                identification_date="2021-01-03",
                published_date_cve="2021-01-01",
                module="engine_container",
                category="vulnerability",
                requirements="Requirement 3",
                tool="Tool 3",
            ),
        ]
        printer = PrinterPrettyTable()
        manager = {"MODEL": "severity", "CLASSIFICATION": ["critical", "high", "medium", "low"]}

        # Act
        printer.print_table_findings(finding_list, manager)

        # Assert
        assert mock_print.called
        # Add more assertions to validate the output

    @patch("builtins.print")
    def test_print_table_without_findings(self, mock_print):
        # Arrange
        finding_list = []
        printer = PrinterPrettyTable()
        manager = {"MODEL": "severity", "CLASSIFICATION": ["critical", "high", "medium", "low"]}

        # Act
        printer.print_table_findings(finding_list, manager)

        # Assert
        assert not mock_print.called
        # Add more assertions if needed

    @patch("builtins.print")
    def test_print_table_exclusions(self, mock_print):
        # Arrange
        exclusions = [
            {
                "severity": "severity",
                "id": "id",
                "where": "path",
                "create_date": "01042023",
                "expired_date": "04032023",
                "reason": "reason",
            }
        ]
        manager = {"MODEL": "severity", "CLASSIFICATION": ["critical", "high", "medium", "low"]}
        
        printer = PrinterPrettyTable()
    
        # Act
        printer.print_table_exclusions(exclusions, manager)

        # Assert
        assert mock_print.called
        # Add more assertions to validate the output

    @patch("builtins.print")
    def test_print_table_exclusions_without_dates(self, mock_print):
        # Exclusions without dates are valid, the model defaults them to an empty
        # string, so rendering them must not break the execution.
        exclusions = [
            {
                "severity": "critical",
                "id": "CKV_AWS_18",
                "where": "all",
                "create_date": "",
                "expired_date": "",
                "reason": "Excepted check (soft fail)",
            }
        ]
        manager = {"MODEL": "severity", "CLASSIFICATION": ["critical", "high", "medium", "low"]}

        printer = PrinterPrettyTable()

        printer.print_table_exclusions(exclusions, manager)

        assert mock_print.called
        printed_table = str(mock_print.call_args[0][0])
        assert "CKV_AWS_18" in printed_table
        assert printed_table.count("NA") == 2

    @patch("builtins.print")
    def test_print_table_report_model_risk(self, mock_print):
        # Arrange
        report_list = [
            Report(
                risk_score=1,
                vm_id="id1 id2",
                vm_id_url="url1 url2",
                status="stat2",
                where="path",
                tags=["tag1"],
                severity="low",
                active=True,
                service="service1",
            ),
        ]
        printer = PrinterPrettyTable()

        # Act
        printer.print_table_report(report_list, "RISK")

        # Assert
        assert mock_print.called
    
    @patch("builtins.print")
    def test_print_table_report_model_priority(self, mock_print):
        report_list = [
            Report(
                priority=1,
                vm_id="id1 id2",
                vm_id_url="url1 url2",
                status="stat2",
                where="path",
                tags=["tag1"],
                severity="low",
                active=True,
                service="service1",
            ),
        ]
        printer = PrinterPrettyTable()

        printer.print_table_report(report_list, "PRIORITY")

        assert mock_print.called

    @patch("builtins.print")
    def test_print_table_report_exlusions(self, mock_print):
        # Arrange
        exclusions = [
            {
                "vm_id": "id",
                "vm_id_url": "url",
                "tags": ["tag1"],
                "service": "service1",
                "create_date": "01042023",
                "expired_date": "04032023",
                "reason": "reason",
            }
        ]
        printer = PrinterPrettyTable()

        # Act
        printer.print_table_report_exclusions(exclusions)

        # Assert
        assert mock_print.called

    @patch("builtins.print")
    def test_print_table_with_findings_engine_code(self, mock_print):
        finding_list = [
            EngineCodeFinding(
                id="1",
                cvss="7.8",
                where="Location 1",
                description="Description 1",
                severity="high",
                identification_date="2021-01-01",
                published_date_cve=None,
                module="engine_code",
                category="vulnerability",
                requirements="",
                tool="Tool 1",
                analysis_url="http://example.com",
                analysis_code="code1",
                label="label1",
                application_business_value="high",
                defect_type="SQL Injection",
            )
        ]
        manager = {"MODEL": "severity", "CLASSIFICATION": ["critical", "high", "medium", "low"]}
        printer = PrinterPrettyTable()

        printer.print_table_findings(finding_list, manager)

        assert mock_print.called

    def test_print_table_report_exclusions_raises_error(self):
        exclusions = [{"vm_id": "id"}]  # missing required keys
        printer = PrinterPrettyTable()

        with pytest.raises(RuntimeError):
            printer.print_table_report_exclusions(exclusions)

    @patch("builtins.print")
    def test_print_table_exclusions_engine_container(self, mock_print):
        exclusions = [
            {
                "severity": "high",
                "id": "CVE-2021-001",
                "where": "path/to/file",
                "create_date": "01042023",
                "expired_date": "04032023",
                "reason": "reason",
                "module": "engine_container",
                "fixed in": "1.0.1",
            }
        ]
        manager = {"MODEL": "severity", "CLASSIFICATION": ["critical", "high", "medium", "low"]}
        printer = PrinterPrettyTable()

        printer.print_table_exclusions(exclusions, manager)

        assert mock_print.called

    def test_print_table_exclusions_raises_error(self):
        exclusions = [
            {
                "severity": "high",
                "id": "CVE-2021-001",
                "module": None,
            }  # missing required keys like 'where', 'create_date', etc.
        ]
        manager = {"MODEL": "severity", "CLASSIFICATION": ["critical", "high", "medium", "low"]}
        printer = PrinterPrettyTable()

        with pytest.raises(RuntimeError):
            printer.print_table_exclusions(exclusions, manager)
