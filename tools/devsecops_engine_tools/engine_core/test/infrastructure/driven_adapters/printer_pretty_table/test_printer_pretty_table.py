from unittest.mock import patch
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.printer_pretty_table.printer_pretty_table import (
    PrinterPrettyTable,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding


class TestPrinterPrettyTable:
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
                module="engine_iac",
                category="vulnerability",
                requirements="Requirement 1",
                tool="Tool 1",
            )
        ]
        printer = PrinterPrettyTable()

        # Act
        printer.print_table_findings(finding_list)

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
                module="engine_container",
                category="vulnerability",
                requirements="Requirement 3",
                tool="Tool 3",
            ),
        ]
        printer = PrinterPrettyTable()

        # Act
        printer.print_table_findings(finding_list)

        # Assert
        assert mock_print.called
        # Add more assertions to validate the output

    @patch("builtins.print")
    def test_print_table_without_findings(self, mock_print):
        # Arrange
        finding_list = []
        printer = PrinterPrettyTable()

        # Act
        printer.print_table_findings(finding_list)

        # Assert
        assert not mock_print.called
        # Add more assertions if needed

    @patch("builtins.print")
    def test_print_table_exclusions(self, mock_print):
        # Arrange
        exclusions = [{"id": "id", "where": "path", "create_date": "01042023", "expired_date": "04032023"}]
        printer = PrinterPrettyTable()

        # Act
        printer.print_table_exclusions(exclusions)

        # Assert
        assert mock_print.called
        # Add more assertions to validate the output