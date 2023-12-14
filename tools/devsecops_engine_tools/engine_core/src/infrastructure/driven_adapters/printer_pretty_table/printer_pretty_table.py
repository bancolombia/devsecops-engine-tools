from dataclasses import dataclass

from devsecops_engine_tools.engine_core.src.domain.model.gateway.printer_table_gateway import (
    PrinterTableGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability import (
    Vulnerability,
)
from prettytable import PrettyTable, DOUBLE_BORDER


@dataclass
class PrinterPrettyTable(PrinterTableGateway):
    def print_table(self, vulnerability_list: "list[Vulnerability]"):
        vulnerability_table = PrettyTable(["Severity", "ID", "Description", "Where"])

        for vulnerability in vulnerability_list:
            vulnerability_table.add_row(
                [
                    vulnerability.severity,
                    vulnerability.id,
                    vulnerability.description,
                    vulnerability.where_vulnerability,
                ]
            )

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_table = PrettyTable()
        sorted_table.field_names = vulnerability_table.field_names
        sorted_table.add_rows(
            sorted(vulnerability_table._rows, key=lambda row: severity_order[row[0]])
        )

        sorted_table.align["Severity"] = "l"
        sorted_table.align["Description"] = "l"
        sorted_table.align["ID"] = "l"
        sorted_table.align["Where"] = "l"
        sorted_table.set_style(DOUBLE_BORDER)

        if len(sorted_table.rows) > 0:
            print(sorted_table)
