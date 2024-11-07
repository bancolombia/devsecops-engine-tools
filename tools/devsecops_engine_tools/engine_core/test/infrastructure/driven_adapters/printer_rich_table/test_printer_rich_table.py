from unittest.mock import patch
from devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.printer_rich_table.printer_rich_table import (
    PrinterRichTable,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding
from devsecops_engine_tools.engine_core.src.domain.model.report import Report


class TestPrinterRichTable:
    def test_print_table_findings(self):
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
        printer = PrinterRichTable()

        result = printer.print_table_findings(finding_list)

        assert result is None

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.printer_rich_table.printer_rich_table.Console"
    )
    def test_print_table_report(self, mock_console):
        report_list = [
            Report(
                risk_score=7.8,
                vm_id="1 2",
                tags=["tag1"],
                service="service1 service2",
            )
        ]
        printer = PrinterRichTable()

        printer.print_table_report(report_list)

        mock_console().print.assert_called_once()

    @patch(
        "devsecops_engine_tools.engine_core.src.infrastructure.driven_adapters.printer_rich_table.printer_rich_table.Console"
    )
    def test_print_table_exclusions(self, mock_console):
        exclusions_list = [
            {
                "vm_id": "1 2",
                "tags": ["tag1"],
                "service": "service1 service2",
                "create_date": "01012021",
                "expired_date": "02012021",
                "reason": "reason1",
                "vm_id_url": "url1",
                "service_url": "url2",
            }
        ]
        printer = PrinterRichTable()

        printer.print_table_exclusions(exclusions_list)

        mock_console().print.assert_called_once()
