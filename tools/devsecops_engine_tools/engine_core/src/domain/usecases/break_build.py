from dataclasses import dataclass, replace
from functools import reduce
from prettytable import PrettyTable, DOUBLE_BORDER

from devsecops_engine_tools.engine_core.src.domain.model.InputCore import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.Vulnerability import (
    Vulnerability,
)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageResultPipeline,
    AzureMessageLoggingPipeline,
)


@dataclass
class BreakBuild:
    vulnerabilities_list: list
    input_core: InputCore

    def print_table(
        self, vulnerabilities_without_exclusions_list: "list[Vulnerability]"
    ):
        vulnerability_table = PrettyTable(["Severity", "ID", "Description", "Where"])

        for vulnerability in vulnerabilities_without_exclusions_list:
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

    def __post_init__(self):
        level_compliance = self.input_core.level_compliance_defined
        exclusions = self.input_core.totalized_exclusions

        if len(self.vulnerabilities_list) != 0:
            vulnerabilities_list = self.vulnerabilities_list

            # Esta lista de excluidas no se imprimira para dejar un resultado más limpio
            vulnerabilities_excluded_list = list(
                filter(
                    lambda item: any(
                        exclusion["id"] == item.id
                        and exclusion["where"] in item.where_vulnerability
                        for exclusion in exclusions
                    ),
                    vulnerabilities_list,
                )
            )

            vulnerabilities_without_exclusions_list = list(
                filter(
                    lambda v: v not in vulnerabilities_excluded_list,
                    vulnerabilities_list,
                )
            )

            vulnerabilities_critical = reduce(
                lambda count, vulnerability: count + 1
                if vulnerability.severity == "critical"
                else count,
                vulnerabilities_without_exclusions_list,
                0,
            )
            vulnerabilities_high = reduce(
                lambda count, vulnerability: count + 1
                if vulnerability.severity == "high"
                else count,
                vulnerabilities_without_exclusions_list,
                0,
            )
            vulnerabilities_medium = reduce(
                lambda count, vulnerability: count + 1
                if vulnerability.severity == "medium"
                else count,
                vulnerabilities_without_exclusions_list,
                0,
            )
            vulnerabilities_low = reduce(
                lambda count, vulnerability: count + 1
                if vulnerability.severity == "low"
                else count,
                vulnerabilities_without_exclusions_list,
                0,
            )
            vulnerabilities_unknown = reduce(
                lambda count, vulnerability: count + 1
                if vulnerability.severity == "unknown"
                else count,
                vulnerabilities_without_exclusions_list,
                0,
            )

            if (
                vulnerabilities_critical >= level_compliance.critical
                or vulnerabilities_high >= level_compliance.high
                or vulnerabilities_medium >= level_compliance.medium
                or vulnerabilities_low >= level_compliance.low
            ):
                self.print_table(vulnerabilities_without_exclusions_list)
                print(
                    AzureMessageLoggingPipeline.ErrorLogging.get_message(
                        "Security count issues (critical: {0}, high: {1}, medium: {2}, low: {3}) is greater than or equal to failure criteria (critical: {4}, high: {5}, medium: {6}, low:{7}, operator: or)".format(
                            vulnerabilities_critical,
                            vulnerabilities_high,
                            vulnerabilities_medium,
                            vulnerabilities_low,
                            level_compliance.critical,
                            level_compliance.high,
                            level_compliance.medium,
                            level_compliance.low,
                        )
                    )
                )
                print(AzureMessageResultPipeline.Failed.value)
            else:
                self.print_table(vulnerabilities_without_exclusions_list)
                print(
                    AzureMessageLoggingPipeline.WarningLogging.get_message(
                        "Security count issues (critical: {0}, high: {1}, medium: {2}, low: {3}) is not greater than or equal to failure criteria (critical: {4}, high: {5}, medium: {6}, low:{7}, operator: or)".format(
                            vulnerabilities_critical,
                            vulnerabilities_high,
                            vulnerabilities_medium,
                            vulnerabilities_low,
                            level_compliance.critical,
                            level_compliance.high,
                            level_compliance.medium,
                            level_compliance.low,
                        )
                    )
                )
                print(AzureMessageResultPipeline.Succeeded.value)
        else:
            print(
                AzureMessageLoggingPipeline.SucceededLogging.get_message(
                    "There are no vulnerabilities"
                )
            )
            print(AzureMessageResultPipeline.Succeeded.value)

        print(
            AzureMessageLoggingPipeline.InfoLogging.get_message(
                "If you have doubts, visit https://discuss.apps.bancolombia.com/t/lanzamiento-csa-analisis-de-seguridad-en-contenedores/6199"
            )
        )
