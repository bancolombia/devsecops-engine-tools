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
    def print_table(self, finding_list: "list[Finding]"):
        finding_table = PrettyTable(["Severity", "ID", "Description", "Where"])

        for finding in finding_list:
            finding_table.add_row(
                [
                    finding.severity,
                    finding.id,
                    finding.description,
                    finding.where,
                ]
            )

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_table = PrettyTable()
        sorted_table.field_names = finding_table.field_names
        sorted_table.add_rows(
            sorted(finding_table._rows, key=lambda row: severity_order[row[0]])
        )

        sorted_table.align["Severity"] = "l"
        sorted_table.align["Description"] = "l"
        sorted_table.align["ID"] = "l"
        sorted_table.align["Where"] = "l"
        sorted_table.set_style(DOUBLE_BORDER)

        if len(sorted_table.rows) > 0:
            print(sorted_table)
