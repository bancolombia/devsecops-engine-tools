from dataclasses import dataclass
from functools import reduce

from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.printer_table_gateway import (
    PrinterTableGateway,
)


@dataclass
class BreakBuild:
    devops_platform_gateway: DevopsPlatformGateway
    printer_table_gateway: PrinterTableGateway
    findings_list: "list[Finding]"
    input_core: InputCore

    def __post_init__(self):
        devops_platform_gateway = self.devops_platform_gateway
        printer_table_gateway = self.printer_table_gateway
        threshold = self.input_core.threshold_defined
        exclusions = self.input_core.totalized_exclusions
        custom_message = self.input_core.custom_message_break_build

        if len(self.findings_list) != 0:
            findings_list = self.findings_list

            # Esta lista de excluidas no se imprimira para dejar un resultado más limpio
            findings_excluded_list = list(
                filter(
                    lambda item: any(
                        exclusion.id == item.id
                        and (exclusion.where in item.where or "all" in exclusion.where)
                        for exclusion in exclusions
                    ),
                    findings_list,
                )
            )

            findings_without_exclusions_list = list(
                filter(
                    lambda v: v not in findings_excluded_list,
                    findings_list,
                )
            )

            vulnerabilities_without_exclusions_list = list(
                filter(
                    lambda v: v.category == Category.VULNERABILITY,
                    findings_without_exclusions_list,
                )
            )

            comliances_without_exclusions_list = list(
                filter(
                    lambda v: v.category == Category.COMPLIANCE,
                    findings_without_exclusions_list,
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

            compliance_critical = reduce(
                lambda count, compliance: count + 1
                if compliance.severity == "critical"
                else count,
                comliances_without_exclusions_list,
                0,
            )

            if (
                sum(
                    [
                        vulnerabilities_critical,
                        vulnerabilities_high,
                        vulnerabilities_medium,
                        vulnerabilities_low,
                    ]
                )
                == 0
            ):
                print(
                    devops_platform_gateway.logging(
                        "succeeded", "There are no vulnerabilities"
                    )
                )
                print(devops_platform_gateway.result_pipeline("succeeded"))
            elif (
                vulnerabilities_critical >= threshold.vulnerability.critical
                or vulnerabilities_high >= threshold.vulnerability.high
                or vulnerabilities_medium >= threshold.vulnerability.medium
                or vulnerabilities_low >= threshold.vulnerability.low
            ):
                print(devops_platform_gateway.logging("info", "Below are all vulnerabilities detected."))
                printer_table_gateway.print_table(
                    vulnerabilities_without_exclusions_list
                )
                print(
                    devops_platform_gateway.logging(
                        "error",
                        "Security count issues (critical: {0}, high: {1}, medium: {2}, low: {3}) is greater than or equal to failure criteria (critical: {4}, high: {5}, medium: {6}, low:{7}, operator: or)".format(
                            vulnerabilities_critical,
                            vulnerabilities_high,
                            vulnerabilities_medium,
                            vulnerabilities_low,
                            threshold.vulnerability.critical,
                            threshold.vulnerability.high,
                            threshold.vulnerability.medium,
                            threshold.vulnerability.low,
                        ),
                    )
                )
                print(devops_platform_gateway.result_pipeline("failed"))
            else:
                print(devops_platform_gateway.logging("info", "Below are all vulnerabilities detected."))
                printer_table_gateway.print_table(
                    vulnerabilities_without_exclusions_list
                )
                print(
                    devops_platform_gateway.logging(
                        "warning",
                        "Security count issues (critical: {0}, high: {1}, medium: {2}, low: {3}) is not greater than or equal to failure criteria (critical: {4}, high: {5}, medium: {6}, low:{7}, operator: or)".format(
                            vulnerabilities_critical,
                            vulnerabilities_high,
                            vulnerabilities_medium,
                            vulnerabilities_low,
                            threshold.vulnerability.critical,
                            threshold.vulnerability.high,
                            threshold.vulnerability.medium,
                            threshold.vulnerability.low,
                        ),
                    )
                )
                print(devops_platform_gateway.result_pipeline("succeeded"))
            print()
            if len(comliances_without_exclusions_list) > 0:
                print(devops_platform_gateway.logging("info", "Below are all compliances issues detected."))
                printer_table_gateway.print_table(comliances_without_exclusions_list)
                if compliance_critical >= threshold.compliance.critical:
                    print(
                        devops_platform_gateway.logging(
                            "error",
                            "Compliance issues count greater than or equal to failure criteria (critical: {0})".format(
                                1,
                            ),
                        )
                    )
                    print(devops_platform_gateway.result_pipeline("failed"))
            else:
                print(devops_platform_gateway.logging("succeeded", "There are no compliances issues"))
                print(devops_platform_gateway.result_pipeline("succeeded"))

        else:
            print(devops_platform_gateway.logging("succeeded", "There are no findings"))
            print(devops_platform_gateway.result_pipeline("succeeded"))

        print(
            devops_platform_gateway.logging(
                "info",
                custom_message,
            )
        )
