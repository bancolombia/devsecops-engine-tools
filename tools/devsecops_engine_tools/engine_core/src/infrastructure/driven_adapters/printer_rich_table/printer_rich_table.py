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
    format_optional_date,
    format_expired_date,
)
from rich.console import Console
from rich.table import Table
from rich import box
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


@dataclass
class PrinterRichTable(PrinterTableGateway):
    def print_table_findings(self, finding_list: "list[Finding]", break_build_manager):
        # To implement
        return

    def print_table_report(self, report_list: "list[Report]", model):
        model_header = "Priority" if model == "PRIORITY" else "Risk Score"
        service_header = "Priority Class" if model == "PRIORITY" else "Services"
        sorted_report_list = sorted(
            report_list, key=lambda report: report.risk_score, reverse=True
        )
        headers = [model_header, "ID", "Tags", service_header]
        table = Table(
            show_header=True, header_style="bold magenta", box=box.DOUBLE_EDGE
        )
        for header in headers:
            table.add_column(header)
        for report in sorted_report_list:
            row_data = [
                str(report.priority if model == "PRIORITY" else report.risk_score),
                self._check_spaces(report.vm_id, report.vm_id_url),
                ", ".join(report.tags),
                report.priority_classification if model == "PRIORITY" else report.service,
            ]
            table.add_row(*row_data)
        console = Console()
        console.print(table)

    def print_table_exclusions(self, exclusions, break_build_manager):
        headers = ["ID", "Tags", "Service", "Create Date", "Expired Date", "Reason"]
        table = Table(
            show_header=True, header_style="bold magenta", box=box.DOUBLE_EDGE
        )
        for header in headers:
            table.add_column(header)
        for exclusion in exclusions:
            try:
                row_data = [
                    self._check_spaces(exclusion["vm_id"], exclusion["vm_id_url"]),
                    ", ".join(exclusion["tags"]),
                    exclusion["service"],
                    format_optional_date(exclusion["create_date"]),
                    format_expired_date(exclusion["expired_date"]),
                    exclusion["reason"],
                ]
                table.add_row(*row_data)
            except (KeyError, TypeError, ValueError) as e:
                self._raise_exclusion_error(exclusion, e)
        console = Console()
        console.print(table)

    def print_table_report_exclusions(self, exclusions):
        headers = ["VM ID", "Services", "Tags", "Created Date", "Expired Date", "Reason"]
        table = Table(
            show_header=True, header_style="bold magenta", box=box.DOUBLE_EDGE
        )
        for header in headers:
            table.add_column(header)
        for exclusion in exclusions:
            try:
                row_data = [
                    self._check_spaces(exclusion["vm_id"], exclusion["vm_id_url"]),
                    exclusion.get("service", ""),
                    ", ".join(exclusion["tags"]),
                    format_optional_date(exclusion["create_date"]),
                    format_expired_date(exclusion["expired_date"]),
                    exclusion["reason"],
                ]
                table.add_row(*row_data)
            except (KeyError, TypeError, ValueError) as e:
                self._raise_exclusion_error(exclusion, e)
        console = Console()
        console.print(table)

    def _raise_exclusion_error(self, exclusion, e):
        error_msg = (
            f"Error processing exclusion VM ID "
            f"{exclusion.get('vm_id', 'Unknown')}: {type(e).__name__}: {str(e)}"
        )
        logger.error(error_msg)
        raise RuntimeError(error_msg) from e

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
