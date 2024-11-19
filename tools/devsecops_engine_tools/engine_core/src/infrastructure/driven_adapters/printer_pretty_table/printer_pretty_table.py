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
from prettytable import PrettyTable, DOUBLE_BORDER


@dataclass
class PrinterPrettyTable(PrinterTableGateway):
    def _create_table(self, headers, finding_list):
        table = PrettyTable(headers)

        for finding in finding_list:
            row_data = [
                finding.severity,
                finding.id,
                finding.description,
                finding.where,
            ]
            if (finding.module == "engine_container") or (
                finding.module == "engine_dependencies"
            ):
                row_data.append(finding.requirements)

            table.add_row(row_data)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        sorted_table = PrettyTable()
        sorted_table.field_names = table.field_names
        sorted_table.add_rows(
            sorted(table._rows, key=lambda row: severity_order[row[0]])
        )

        for column in table.field_names:
            sorted_table.align[column] = "l"

        sorted_table.set_style(DOUBLE_BORDER)
        return sorted_table

    def print_table_findings(self, finding_list: "list[Finding]"):
        if (
            finding_list
            and (finding_list[0].module != "engine_container")
            and (finding_list[0].module != "engine_dependencies")
        ):
            headers = ["Severity", "ID", "Description", "Where"]
        else:
            headers = ["Severity", "ID", "Description", "Where", "Fixed in"]

        sorted_table = self._create_table(headers, finding_list)

        if len(sorted_table.rows) > 0:
            print(sorted_table)

    def print_table_report(self, report_list: "list[Report]"):
        headers = ["Risk Score", "VM ID", "Services", "Tags"]
        table = PrettyTable(headers)
        for report in report_list:
            row_data = [
                report.risk_score,
                self._check_spaces(report.vm_id),
                self._check_spaces(report.service),
                ", ".join(report.tags),
            ]
            table.add_row(row_data)

        sorted_table = PrettyTable()
        sorted_table.field_names = table.field_names
        sorted_table.add_rows(sorted(table._rows, key=lambda row: row[0], reverse=True))

        for column in table.field_names:
            sorted_table.align[column] = "l"

        sorted_table.set_style(DOUBLE_BORDER)

        if len(sorted_table.rows) > 0:
            print(sorted_table)

    def print_table_report_exlusions(self, exclusions):
        if exclusions:
            headers = [
                "VM ID",
                "Services",
                "Tags",
                "Created Date",
                "Expired Date",
                "Reason",
            ]

        table = PrettyTable(headers)

        for exclusion in exclusions:
            row_data = [
                self._check_spaces(exclusion["vm_id"]),
                self._check_spaces(exclusion["service"]),
                ", ".join(exclusion["tags"]),
                format_date(exclusion["create_date"], "%d%m%Y", "%d/%m/%Y"),
                (
                    format_date(exclusion["expired_date"], "%d%m%Y", "%d/%m/%Y")
                    if exclusion["expired_date"]
                    and exclusion["expired_date"] != "undefined"
                    else "NA"
                ),
                exclusion["reason"],
            ]
            table.add_row(row_data)

        for column in table.field_names:
            table.align[column] = "l"

        table.set_style(DOUBLE_BORDER)
        if len(table.rows) > 0:
            print(table)

    def print_table_exclusions(self, exclusions):
        if exclusions:
            headers = [
                "Severity",
                "ID",
                "Where",
                "Create Date",
                "Expired Date",
                "Reason",
            ]

        table = PrettyTable(headers)

        for exclusion in exclusions:
            row_data = [
                exclusion["severity"],
                exclusion["id"],
                exclusion["where"],
                format_date(exclusion["create_date"], "%d%m%Y", "%d/%m/%Y"),
                (
                    format_date(exclusion["expired_date"], "%d%m%Y", "%d/%m/%Y")
                    if exclusion["expired_date"]
                    and exclusion["expired_date"] != "undefined"
                    else "NA"
                ),
                exclusion["reason"],
            ]
            table.add_row(row_data)

        for column in table.field_names:
            table.align[column] = "l"

        table.set_style(DOUBLE_BORDER)
        if len(table.rows) > 0:
            print(table)

    def _check_spaces(self, value):
        values = value.split()
        new_value = ""
        if len(values) > 1:
            new_value = "\n".join(values)
        else:
            new_value = f"{values[0]}"
        return new_value
