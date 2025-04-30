import sys
from itertools import chain
from dataclasses import dataclass

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

    def process(self, findings_list: "list[Finding]", input_core: InputCore, args: any, warning_release: bool):
        sys.stdout.reconfigure(encoding="utf-8")
        devops_platform_gateway = self.devops_platform_gateway
        threshold = input_core.threshold_defined
        exclusions = input_core.totalized_exclusions
        custom_message = input_core.custom_message_break_build

        scan_result = {
            "findings_excluded": [],
            "vulnerabilities": {},
            "compliances": {},
        }

        if findings_list:
            self._apply_policie_exception_new_vulnerability_industry(
                findings_list, exclusions, args
            )

            findings_excluded, findings_without_exclusions = self._filter_findings(findings_list, exclusions)
            scan_result["findings_excluded"] = [self._map_finding_excluded(item) for item in findings_excluded]

            vulnerabilities = [v for v in findings_without_exclusions if v.category == Category.VULNERABILITY]
            compliances = [v for v in findings_without_exclusions if v.category == Category.COMPLIANCE]

            vulnerability_counts = self._count_severities(vulnerabilities)
            compliance_counts = self._count_severities(compliances)

            self._handle_vulnerabilities(vulnerability_counts, vulnerabilities, threshold, warning_release, scan_result)
            self._handle_cve_policy(vulnerabilities, threshold)
            self._handle_compliances(compliance_counts, compliances, threshold, warning_release, scan_result)
            self._handle_exclusions(findings_excluded, exclusions)
        else:
            print(devops_platform_gateway.message("succeeded", "There are no findings"))
            print(devops_platform_gateway.result_pipeline("succeeded"))

        print()
        print(devops_platform_gateway.message("info", custom_message))
        return scan_result
    
    def _apply_policie_exception_new_vulnerability_industry(
        self, findings_list: "list[Finding]", exclusions: "list[Exclusions]", args: any
    ):
        if args["module"] in ["engine_container", "engine_dependencies"]:
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

    def _filter_findings(self, findings_list, exclusions):
        findings_excluded_list = [
            item for item in findings_list if any(
                exclusion.id == item.id and
                (exclusion.where in item.where or "all" in exclusion.where) and
                exclusion.severity == item.severity
                for exclusion in exclusions
            )
        ]
        findings_without_exclusions_list = [
            v for v in findings_list if v not in findings_excluded_list
        ]
        return findings_excluded_list, findings_without_exclusions_list

    def _map_finding_excluded(self, item):
        return {
            "id": item.id,
            "severity": item.severity,
            "category": item.category.value,
        }

    def _count_severities(self, findings_list):
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        for finding in findings_list:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _handle_vulnerabilities(self, counts, vulnerabilities_list, threshold, warning_release, scan_result):
        devops_platform_gateway = self.devops_platform_gateway
        printer_table_gateway = self.printer_table_gateway
        print()

        total = sum(counts[severity] for severity in ["critical", "high", "medium", "low"])
        if total == 0:
            print(devops_platform_gateway.message("succeeded", "There are no vulnerabilities"))
            print(devops_platform_gateway.result_pipeline("succeeded"))
            return

        if (counts["critical"] >= threshold.vulnerability.critical or
            counts["high"] >= threshold.vulnerability.high or
            counts["medium"] >= threshold.vulnerability.medium or
            counts["low"] >= threshold.vulnerability.low):
            
            print("Below are all vulnerabilities detected.")
            printer_table_gateway.print_table_findings(vulnerabilities_list)
            print(devops_platform_gateway.message(
                "error",
                "Security count issues (critical: {0}, high: {1}, medium: {2}, low: {3}) is greater than or equal to failure criteria (critical: {4}, high: {5}, medium: {6}, low:{7}, operator: or)".format(
                    counts["critical"], counts["high"], counts["medium"], counts["low"],
                    threshold.vulnerability.critical, threshold.vulnerability.high,
                    threshold.vulnerability.medium, threshold.vulnerability.low
                )
            ))
            print(devops_platform_gateway.result_pipeline("failed"))

            scan_result["vulnerabilities"] = {
                "threshold": counts,
                "status": "failed",
                "found": [{"id": item.id, "severity": item.severity} for item in vulnerabilities_list],
            }
        else:
            print("Below are all vulnerabilities detected.")
            printer_table_gateway.print_table_findings(vulnerabilities_list)
            print(devops_platform_gateway.message(
                "warning",
                "Security count issues (critical: {0}, high: {1}, medium: {2}, low: {3}) is not greater than or equal to failure criteria (critical: {4}, high: {5}, medium: {6}, low:{7}, operator: or)".format(
                    counts["critical"], counts["high"], counts["medium"], counts["low"],
                    threshold.vulnerability.critical, threshold.vulnerability.high,
                    threshold.vulnerability.medium, threshold.vulnerability.low
                )
            ))
            result = "succeeded_with_issues" if warning_release or devops_platform_gateway.get_variable("stage") == "build" else "succeeded"
            print(devops_platform_gateway.result_pipeline(result))

            scan_result["vulnerabilities"] = {
                "threshold": counts,
                "status": "succeeded",
                "found": [{"id": item.id, "severity": item.severity} for item in vulnerabilities_list],
            }

    def _handle_cve_policy(self, vulnerabilities_list: "list[Finding]", threshold):
        devops_platform_gateway = self.devops_platform_gateway

        ids_vulnerabilities = list(
            chain.from_iterable(
                ([x.id, x.description] if x.tool == "XRAY" else [x.id]) for x in vulnerabilities_list
            )
        )
        ids_match = [x for x in threshold.cve if x in ids_vulnerabilities]
        if ids_match:
            print(devops_platform_gateway.message(
                "error",
                "Scan Failed due to vulnerability policy violations: CVEs Vulnerabilities: {0}".format(",".join(ids_match))
            ))
            print(devops_platform_gateway.result_pipeline("failed"))

    def _handle_compliances(self, counts, compliances_list, threshold, warning_release, scan_result):
        devops_platform_gateway = self.devops_platform_gateway
        printer_table_gateway = self.printer_table_gateway
        print()

        if compliances_list:
            print("Below are all compliances issues detected.")
            printer_table_gateway.print_table_findings(compliances_list)
            status = "succeeded"
            if counts["critical"] >= threshold.compliance.critical:
                print(devops_platform_gateway.message(
                    "error",
                    "Compliance issues count (critical: {0}) is greater than or equal to failure criteria (critical: {1})".format(
                        counts["critical"], threshold.compliance.critical
                    )
                ))
                print(devops_platform_gateway.result_pipeline("failed"))
                status = "failed"
            else:
                if warning_release or devops_platform_gateway.get_variable("stage") == "build":
                    print(devops_platform_gateway.result_pipeline("succeeded_with_issues"))
            
            scan_result["compliances"] = {
                "threshold": {"critical": counts["critical"]},
                "status": status,
                "found": [{"id": item.id, "severity": item.severity} for item in compliances_list],
            }
        else:
            print(devops_platform_gateway.message("succeeded", "There are no compliances issues"))
            print(devops_platform_gateway.result_pipeline("succeeded"))

    def _handle_exclusions(self, findings_excluded_list, exclusions):
        devops_platform_gateway = self.devops_platform_gateway
        printer_table_gateway = self.printer_table_gateway
        print()

        if findings_excluded_list:
            exclusions_list = []
            for item in findings_excluded_list:
                matching = next(
                    (e for e in exclusions if e.id == item.id and (e.where in item.where or "all" in e.where) and e.severity == item.severity),
                    None
                )
                if matching:
                    exclusions_list.append({
                        "severity": item.severity,
                        "id": item.id,
                        "where": item.where,
                        "create_date": matching.create_date,
                        "expired_date": matching.expired_date,
                        "reason": matching.reason,
                    })
            
            print(devops_platform_gateway.message("warning", "Below are all findings that were excepted."))
            printer_table_gateway.print_table_exclusions(exclusions_list)
            
            for reason, total in Counter(x["reason"] for x in exclusions_list).items():
                print("{0} findings count: {1}".format(reason, total))
