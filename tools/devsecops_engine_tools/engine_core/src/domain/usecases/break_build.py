import sys
import re
from dataclasses import dataclass
from functools import reduce

from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import Exclusions
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.printer_table_gateway import (
    PrinterTableGateway,
)

from collections import Counter
from datetime import timedelta, datetime
import pytz


@dataclass
class BreakBuild:
    def __init__(
        self,
        devops_platform_gateway: DevopsPlatformGateway,
        printer_table_gateway: PrinterTableGateway,
    ):
        self.devops_platform_gateway = devops_platform_gateway
        self.printer_table_gateway = printer_table_gateway

    def _apply_policie_exception_new_vulnerability_industry(
        self, findings_list: "list[Finding]", exclusions: "list[Exclusions]", args: any
    ):
        if args["tool"] in ["engine_container", "engine_dependencies"]:
            date_actual = datetime.now(pytz.utc)
            for item in findings_list:
                if item.published_date_cve:
                    date_initial = datetime.fromisoformat(item.published_date_cve)
                    date_final = date_initial + timedelta(days=5)
                    if date_initial <= date_actual <= date_final:
                        exclusions.append(
                            Exclusions(
                                **{
                                    "id": item.id,
                                    "where": "all",
                                    "create_date": date_initial.strftime("%d%m%Y"),
                                    "expired_date": date_final.strftime("%d%m%Y"),
                                    "reason": "New vulnerability in the industry",
                                }
                            )
                        )

    def process(self, findings_list: "list[Finding]", input_core: InputCore, args: any):
        sys.stdout.reconfigure(encoding='utf-8')
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

        if threshold.custom_vulnerability and bool(re.match(threshold.custom_vulnerability.pattern_apps, input_core.scope_pipeline, re.IGNORECASE)):
            threshold.vulnerability = threshold.custom_vulnerability.vulnerability

        if len(findings_list) != 0:
            self._apply_policie_exception_new_vulnerability_industry(
                findings_list, exclusions, args
            )

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
                lambda count, vulnerability: (
                    count + 1 if vulnerability.severity == "critical" else count
                ),
                vulnerabilities_without_exclusions_list,
                0,
            )
            vulnerabilities_high = reduce(
                lambda count, vulnerability: (
                    count + 1 if vulnerability.severity == "high" else count
                ),
                vulnerabilities_without_exclusions_list,
                0,
            )
            vulnerabilities_medium = reduce(
                lambda count, vulnerability: (
                    count + 1 if vulnerability.severity == "medium" else count
                ),
                vulnerabilities_without_exclusions_list,
                0,
            )
            vulnerabilities_low = reduce(
                lambda count, vulnerability: (
                    count + 1 if vulnerability.severity == "low" else count
                ),
                vulnerabilities_without_exclusions_list,
                0,
            )
            vulnerabilities_unknown = reduce(
                lambda count, vulnerability: (
                    count + 1 if vulnerability.severity == "unknown" else count
                ),
                vulnerabilities_without_exclusions_list,
                0,
            )

            compliance_critical = reduce(
                lambda count, compliance: (
                    count + 1 if compliance.severity == "critical" else count
                ),
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
                printer_table_gateway.print_table_findings(
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
                printer_table_gateway.print_table_findings(
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
                
                if devops_platform_gateway.get_variable("stage") == "build":
                    print(devops_platform_gateway.result_pipeline("succeeded_with_issues"))
                else:
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

            ids_vulnerabilitites = list(
                map(lambda x: x.id, vulnerabilities_without_exclusions_list)
            )
            ids_match = list(filter(lambda x: x in ids_vulnerabilitites, threshold.cve))
            if len(ids_match) > 0:
                print(
                    devops_platform_gateway.message(
                        "error",
                        "Scan Failed due to vulnerability policy violations: CVEs Vulnerabilities: {0}".format(
                            ",".join(ids_match)
                        ),
                    )
                )
                print(devops_platform_gateway.result_pipeline("failed"))

            print()
            if len(compliances_without_exclusions_list) > 0:
                print("Below are all compliances issues detected.")
                printer_table_gateway.print_table_findings(
                    compliances_without_exclusions_list
                )
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
                else:
                    if devops_platform_gateway.get_variable("stage") == "build":
                        print(devops_platform_gateway.result_pipeline("succeeded_with_issues"))
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
            print()
            if len(findings_excluded_list) > 0:
                exclusions_list = list(
                    map(
                        lambda item: {
                            "severity": item.severity,
                            "id": item.id,
                            "where": item.where,
                            "create_date": next(
                                (
                                    elem.create_date
                                    for elem in exclusions
                                    if elem.id == item.id and (elem.where in item.where or "all" in elem.where)
                                ),
                                None,
                            ),
                            "expired_date": next(
                                (
                                    elem.expired_date
                                    for elem in exclusions
                                    if elem.id == item.id and (elem.where in item.where or "all" in elem.where)
                                ),
                                None,
                            ),
                            "reason": next(
                                (
                                    elem.reason
                                    for elem in exclusions
                                    if elem.id == item.id and (elem.where in item.where or "all" in elem.where)
                                ),
                                None,
                            ),
                        },
                        findings_excluded_list,
                    )
                )
                print(
                    devops_platform_gateway.message(
                        "warning", "Bellow are all findings that were excepted."
                    )
                )
                printer_table_gateway.print_table_exclusions(exclusions_list)
                for reason, total in Counter(
                    map(lambda x: x["reason"], exclusions_list)
                ).items():
                    print("{0} findings count: {1}".format(reason, total))
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