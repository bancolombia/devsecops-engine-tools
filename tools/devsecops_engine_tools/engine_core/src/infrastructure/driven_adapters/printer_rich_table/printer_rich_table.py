from dataclasses import dataclass

from devsecops_engine_tools.engine_core.src.domain.model.gateway.printer_table_gateway import (
    PrinterTableGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
)
from devsecops_engine_tools.engine_core.src.domain.model.report import (
    Report,
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.util import (
    format_date,
)
from rich.console import Console
from rich.table import Table
from rich import box


@dataclass
class PrinterRichTable(PrinterTableGateway):
    def print_table_findings(self, finding_list: "list[Finding]"):
        # To implement
        return

    def print_table_report(self, report_list: "list[Report]"):
        sorted_report_list = sorted(
            report_list, key=lambda report: report.risk_score, reverse=True
        )
        headers = ["Risk Score", "ID", "Tags", "Services"]
        table = Table(
            show_header=True, header_style="bold magenta", box=box.DOUBLE_EDGE
        )
        for header in headers:
            table.add_column(header)
        for report in sorted_report_list:
            row_data = [
                str(report.risk_score),
                self._check_spaces(report.vm_id, report.vm_id_url),
                ", ".join(report.tags),
                report.service,
            ]
            table.add_row(*row_data)
        console = Console()
        console.print(table)

    def print_table_exclusions(self, exclusions_list):
        headers = []
        if exclusions_list:
            headers = ["ID", "Tags", "Service", "Create Date", "Expired Date", "Reason"]
        table = Table(
            show_header=True, header_style="bold magenta", box=box.DOUBLE_EDGE
        )
        for header in headers:
            table.add_column(header)
        for exclusion in exclusions_list:
            row_data = [
                self._check_spaces(exclusion["vm_id"], exclusion["vm_id_url"]),
                ", ".join(exclusion["tags"]),
                exclusion["service"],
                format_date(exclusion["create_date"], "%d%m%Y", "%d/%m/%Y"),
                (
                    format_date(exclusion["expired_date"], "%d%m%Y", "%d/%m/%Y")
                    if exclusion["expired_date"]
                    and exclusion["expired_date"] != "undefined"
                    else "NA"
                ),
                exclusion["reason"],
            ]
            table.add_row(*row_data)
        console = Console()
        console.print(table)

    def _check_spaces(self, value, url):
        values = value.split()
        urls = url.split()
        new_value = ""
        if len(values) > 1 or len(urls) > 1:
            for value, url in zip(values, urls):
                new_value += self._make_hyperlink(value, url) + " "
        else:
            new_value = self._make_hyperlink(values[0], urls[0])
        return new_value

    def _make_hyperlink(self, value, url):
        return f"[link={url}]{value}[/link]"
