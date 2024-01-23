from dataclasses import dataclass

from devsecops_engine_tools.engine_core.src.domain.model.gateway.printer_table_gateway import (
    PrinterTableGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
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

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_table = PrettyTable()
        sorted_table.field_names = table.field_names
        sorted_table.add_rows(
            sorted(table._rows, key=lambda row: severity_order[row[0]])
        )

        for column in table.field_names:
            sorted_table.align[column] = "l"

        sorted_table.set_style(DOUBLE_BORDER)
        return sorted_table

    def print_table(self, finding_list: "list[Finding]"):
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
