from dataclasses import dataclass
from functools import reduce

from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.printer_table_gateway import (
    PrinterTableGateway,
)


@dataclass
class BreakBuild:
    def __init__(
        self,
        devops_platform_gateway: DevopsPlatformGateway,
        printer_table_gateway: PrinterTableGateway,
    ):
        self.devops_platform_gateway = devops_platform_gateway
        self.printer_table_gateway = printer_table_gateway

    def process(self, findings_list: "list[Finding]", input_core: InputCore):
        devops_platform_gateway = self.devops_platform_gateway
        printer_table_gateway = self.printer_table_gateway
        threshold = input_core.threshold_defined
        exclusions = input_core.totalized_exclusions
        custom_message = input_core.custom_message_break_build

        scan_result = {
            "findings_excluded": [],
            "vulnerabilities": {},
            "compliances": {},
        }

        if len(findings_list) != 0:
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

            scan_result["findings_excluded"] = list(
                map(
                    lambda item: {
                        "id": item.id,
                        "severity": item.severity,
                        "category": item.category.value,
                    },
                    findings_excluded_list,
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

            compliances_without_exclusions_list = list(
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
                compliances_without_exclusions_list,
                0,
            )
            print()
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
                    devops_platform_gateway.message(
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
                print("Below are all vulnerabilities detected.")
                printer_table_gateway.print_table(
                    vulnerabilities_without_exclusions_list
                )
                print(
                    devops_platform_gateway.message(
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

                scan_result["vulnerabilities"] = {
                    "threshold": {
                        "critical": vulnerabilities_critical,
                        "high": vulnerabilities_high,
                        "medium": vulnerabilities_medium,
                        "low": vulnerabilities_low,
                    },
                    "status": "failed",
                    "found": list(
                        map(
                            lambda item: {
                                "id": item.id,
                                "severity": item.severity,
                            },
                            vulnerabilities_without_exclusions_list,
                        )
                    ),
                }
            else:
                print("Below are all vulnerabilities detected.")
                printer_table_gateway.print_table(
                    vulnerabilities_without_exclusions_list
                )
                print(
                    devops_platform_gateway.message(
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

                scan_result["vulnerabilities"] = {
                    "threshold": {
                        "critical": vulnerabilities_critical,
                        "high": vulnerabilities_high,
                        "medium": vulnerabilities_medium,
                        "low": vulnerabilities_low,
                    },
                    "status": "succeeded",
                    "found": list(
                        map(
                            lambda item: {
                                "id": item.id,
                                "severity": item.severity,
                            },
                            vulnerabilities_without_exclusions_list,
                        )
                    ),
                }
            print()
            if len(compliances_without_exclusions_list) > 0:
                print("Below are all compliances issues detected.")
                printer_table_gateway.print_table(compliances_without_exclusions_list)
                status = "succeeded"
                if compliance_critical >= threshold.compliance.critical:
                    print(
                        devops_platform_gateway.message(
                            "error",
                            "Compliance issues count (critical: {0}) is greater than or equal to failure criteria (critical: {1})".format(
                                compliance_critical, threshold.compliance.critical
                            ),
                        )
                    )
                    print(devops_platform_gateway.result_pipeline("failed"))
                    status = "failed"
                scan_result["compliances"] = {
                    "threshold": {"critical": compliance_critical},
                    "status": status,
                    "found": list(
                        map(
                            lambda item: {
                                "id": item.id,
                                "severity": item.severity,
                            },
                            compliances_without_exclusions_list,
                        )
                    ),
                }
            else:
                print(
                    devops_platform_gateway.message(
                        "succeeded", "There are no compliances issues"
                    )
                )
                print(devops_platform_gateway.result_pipeline("succeeded"))

        else:
            print(devops_platform_gateway.message("succeeded", "There are no findings"))
            print(devops_platform_gateway.result_pipeline("succeeded"))
        print()
        print(
            devops_platform_gateway.message(
                "info",
                custom_message,
            )
        )
        return scan_result
