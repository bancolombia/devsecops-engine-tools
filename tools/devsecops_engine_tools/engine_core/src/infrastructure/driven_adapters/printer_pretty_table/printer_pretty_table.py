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
from prettytable import PrettyTable, DOUBLE_BORDER
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


@dataclass
class PrinterPrettyTable(PrinterTableGateway):
    def _create_table(self, headers, finding_list, break_build_manager):
        model = break_build_manager.get("MODEL", "severity")
        table = PrettyTable(headers)
        
        for finding in finding_list:
            row_data = [
                finding.severity if model == "severity" else finding.priority.scale,
                finding.id,
                finding.description,
                finding.where,
            ]
            if finding.module in ("engine_container", "engine_dependencies", "engine_function"):
                row_data.append(finding.requirements)
            elif finding.module == "engine_code":
                row_data.append(finding.cvss)
                row_data.append(finding.defect_type)
            table.add_row(row_data)

        severity_order = {break_build_manager.get("CLASSIFICATION", "critical")[0]: 0,
                          break_build_manager.get("CLASSIFICATION", "high")[1]: 1,
                          break_build_manager.get("CLASSIFICATION", "medium")[2]: 2,
                          break_build_manager.get("CLASSIFICATION", "low")[3]: 3,
                          "unknown": 4}
        sorted_table = PrettyTable()
        sorted_table.field_names = table.field_names
        sorted_table.add_rows(
            sorted(table._rows, key=lambda row: severity_order[row[0]])
        )

        for column in table.field_names:
            sorted_table.align[column] = "l"

        sorted_table.set_style(DOUBLE_BORDER)
        return sorted_table

    def print_table_findings(self, finding_list: "list[Finding]", break_build_manager):
        model_header = "Priority" if break_build_manager.get("MODEL", "Severity") == "priority" else "Severity"
        if (
            finding_list
            and (
                finding_list[0].module in ["engine_container","engine_dependencies", "engine_function"]
            )
        ):
            headers = [model_header, "ID", "Description", "Where", "Fixed in"]
        elif finding_list and finding_list[0].module == "engine_code":
            headers = [model_header, "ID", "Description", "Where", "Rule", "Defect Type"]

        else:
            headers = [model_header, "ID", "Description", "Where"]

        sorted_table = self._create_table(headers, finding_list, break_build_manager)

        if len(sorted_table.rows) > 0:
            print(sorted_table)

    def print_table_report(self, report_list: "list[Report]", model):
        score_header = "Priority" if model == "PRIORITY" else "Risk Score"
        service_header = "Priority Class" if model == "PRIORITY" else "Services"
        headers = [score_header, "VM ID", service_header, "Tags"]
        table = PrettyTable(headers)
        for report in report_list:
            row_data = [
                report.priority if model == "PRIORITY" else report.risk_score,
                self._check_spaces(report.vm_id),
                report.priority_classification if model == "PRIORITY" else self._check_spaces(report.service),
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

    def print_table_report_exclusions(self, exclusions):
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
            try:
                row_data = [
                    self._check_spaces(exclusion["vm_id"]),
                    self._check_spaces(exclusion["service"]),
                    ", ".join(exclusion["tags"]),
                    format_optional_date(exclusion["create_date"]),
                    format_expired_date(exclusion["expired_date"]),
                    exclusion["reason"],
                ]
                table.add_row(row_data)
            
            except (KeyError, TypeError, ValueError) as e:
                error_msg = (
                    f"Error processing exclusion entry for VM ID "
                    f"{exclusion.get('vm_id', 'Unknown')}: {type(e).__name__}: {str(e)}"
                )
                logger.error(error_msg)
                raise RuntimeError(error_msg) from e

        for column in table.field_names:
            table.align[column] = "l"

        table.set_style(DOUBLE_BORDER)
        if len(table.rows) > 0:
            print(table)

    def print_table_exclusions(self, exclusions, break_build_manager):
        model_header = "Priority" if break_build_manager.get("MODEL", "Severity") == "priority" else "Severity"
        headers = [
            model_header,
            "ID",
            "Where",
            "Create Date",
            "Expired Date",
            "Reason",
        ]
        
        if exclusions[0].get("module") in ("engine_container", "engine_dependencies", "engine_function"):
            headers.insert(6, "Fixed in")

        table = PrettyTable(headers)
        
        for exclusion in exclusions:
            try:
                row_data = [
                    exclusion["severity"],
                    exclusion["id"],
                    exclusion["where"],
                    format_optional_date(exclusion["create_date"]),
                    format_expired_date(exclusion["expired_date"]),
                    exclusion["reason"],
                ]
                if exclusion.get("module") in ("engine_container", "engine_dependencies", "engine_function"):
                    row_data.append(exclusion["fixed in"])
                table.add_row(row_data)
            except (KeyError, TypeError, ValueError) as e:
                error_msg = (
                    f"Error processing exclusion finding ID "
                    f"{exclusion.get('id', 'Unknown')}: {type(e).__name__}: {str(e)}"
                )
                logger.error(error_msg)
                raise RuntimeError(error_msg) from e

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