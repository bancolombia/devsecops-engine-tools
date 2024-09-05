from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.printer_table_gateway import (
    PrinterTableGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.report import (
    Report,
)
from devsecops_engine_tools.engine_core.src.domain.model.exclusions import (
    Exclusions,
)

from collections import Counter
import copy


class BreakBuild:
    def __init__(
        self,
        devops_platform_gateway: DevopsPlatformGateway,
        printer_table_gateway: PrinterTableGateway,
        remote_config: any,
        exclusions: "list[Exclusions]",
        vm_exclusions: "list[Exclusions]",
        report_list: "list[Report]",
        all_report: "list[Report]",
    ):
        self.devops_platform_gateway = devops_platform_gateway
        self.printer_table_gateway = printer_table_gateway
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.vm_exclusions = vm_exclusions
        self.report_list = report_list
        self.all_report = all_report
        self.break_build = False
        self.warning_build = False
        self.report_breaker = []
        self.remediation_rate = 0
        self.blacklisted = 0
        self.max_risk_score = 0
        self.status = "succeeded"
        self.scan_result = {
            "findings_excluded": [],
            "vulnerabilities": {},
            "compliances": {},
            "risk": {},
        }

    def process(self):
        self._remediation_rate_control(self.all_report)
        new_report_list, applied_exclusions = self._apply_exclusions(self.report_list)
        if self.break_build:
            self.report_breaker.extend(copy.deepcopy(new_report_list))
        self._tag_blacklist_control(new_report_list)
        self._risk_score_control(new_report_list)
        all_exclusions = list(self.vm_exclusions) + list(applied_exclusions)
        self._print_exclusions(self._map_applied_exclusion(all_exclusions))

        self.max_risk_score = (
            max(report.risk_score for report in new_report_list)
            if new_report_list
            else 0
        )

        self._breaker()

        self.scan_result["findings_excluded"] = list(
            map(
                lambda item: {
                    "severity": item.severity,
                    "id": item.id,
                    "category": item.reason,
                },
                all_exclusions,
            )
        )

        self.scan_result["risk"] = {
            "risk_control": {
                "remediation_rate": self.remediation_rate,
                "blacklisted": self.blacklisted,
                "max_risk_score": self.max_risk_score,
            },
            "status": self.status,
            "found": list(
                map(
                    lambda item: {
                        "id": (
                            item.vuln_id_from_tool
                            if item.vuln_id_from_tool
                            else item.id
                        ),
                        "severity": item.severity,
                        "risk_score": item.risk_score,
                        "reason": item.reason,
                    },
                    self.report_breaker,
                )
            ),
        }

        print(
            self.devops_platform_gateway.message(
                "info",
                self.remote_config["MESSAGE_INFO"],
            )
        )

        return self.scan_result

    def _breaker(self):
        if self.break_build:
            print(self.devops_platform_gateway.result_pipeline("failed"))
            self.status = "failed"
        else:
            print(self.devops_platform_gateway.result_pipeline("succeeded"))

    def _remediation_rate_control(self, all_report: "list[Report]"):
        remote_config = self.remote_config
        remediation_rate_value = self._get_percentage(
            (sum(1 for report in all_report if report.mitigated)) / len(all_report)
        )
        risk_threshold = remote_config["THRESHOLD"]["REMEDIATION_RATE"]
        self.remediation_rate = remediation_rate_value

        if remediation_rate_value >= (risk_threshold + 5):
            print(
                self.devops_platform_gateway.message(
                    "succeeded",
                    f"Remediation Rate {remediation_rate_value}% is greater than {risk_threshold}%",
                )
            )
        elif remediation_rate_value >= risk_threshold:
            print(
                self.devops_platform_gateway.message(
                    "warning",
                    f"Remediation Rate {remediation_rate_value}% is close to {risk_threshold}%",
                )
            )
            self.warning_build = True
        else:
            print(
                self.devops_platform_gateway.message(
                    "error",
                    f"Remediation Rate {remediation_rate_value}% is less than {risk_threshold}%",
                )
            )
            self.break_build = True

    def _get_percentage(self, decimal):
        return round(decimal * 100, 3)

    def _get_applied_exclusion(self, report: Report):
        for exclusion in self.exclusions:
            if exclusion.id and (report.id == exclusion.id):
                return exclusion
            elif exclusion.id and (report.vuln_id_from_tool == exclusion.id):
                return exclusion
        return None

    def _map_applied_exclusion(self, exclusions: "list[Exclusions]"):
        return [
            {
                "severity": exclusion.severity,
                "id": exclusion.id,
                "where": exclusion.where,
                "create_date": exclusion.create_date,
                "expired_date": exclusion.expired_date,
                "reason": exclusion.reason,
            }
            for exclusion in exclusions
        ]

    def _apply_exclusions(self, report_list: "list[Report]"):
        new_report_list = []
        applied_exclusions = []
        exclusions_ids = {exclusion.id for exclusion in self.exclusions if exclusion.id}

        for report in report_list:
            if report.vuln_id_from_tool and (
                report.vuln_id_from_tool in exclusions_ids
            ):
                applied_exclusions.append(self._get_applied_exclusion(report))
            elif report.id and (report.id in exclusions_ids):
                applied_exclusions.append(self._get_applied_exclusion(report))
            else:
                report.reason = "Remediation Rate"
                new_report_list.append(report)

        return new_report_list, applied_exclusions

    def _tag_blacklist_control(self, report_list: "list[Report]"):
        remote_config = self.remote_config
        if report_list:
            tag_blacklist = set(remote_config["THRESHOLD"]["TAG_BLACKLIST"])
            tag_age_threshold = remote_config["THRESHOLD"]["TAG_MAX_AGE"]

            filtered_reports_above_threshold = [
                (report, tag)
                for report in report_list
                for tag in report.tags
                if tag in tag_blacklist and report.age >= tag_age_threshold
            ]

            filtered_reports_below_threshold = [
                (report, tag)
                for report in report_list
                for tag in report.tags
                if tag in tag_blacklist and report.age < tag_age_threshold
            ]

            for report, tag in filtered_reports_above_threshold:
                report.reason = "Blacklisted"
                print(
                    self.devops_platform_gateway.message(
                        "error",
                        f"Report {report.vuln_id_from_tool if report.vuln_id_from_tool else report.id} with tag {tag} is blacklisted and age {report.age} is above threshold {tag_age_threshold}",
                    )
                )

            for report, tag in filtered_reports_below_threshold:
                print(
                    self.devops_platform_gateway.message(
                        "warning",
                        f"Report {report.vuln_id_from_tool if report.vuln_id_from_tool else report.id} with tag {tag} is blacklisted but age {report.age} is below threshold {tag_age_threshold}",
                    )
                )

            if filtered_reports_above_threshold:
                self.break_build = True
                self.blacklisted = len(filtered_reports_above_threshold)
                self.report_breaker.extend(
                    copy.deepcopy(
                        [report for report, _ in filtered_reports_above_threshold]
                    )
                )

    def _risk_score_control(self, report_list: "list[Report]"):
        remote_config = self.remote_config
        risk_score_threshold = remote_config["THRESHOLD"]["RISK_SCORE"]
        break_build = False
        if report_list:
            for report in report_list:
                report.risk_score = round(
                    remote_config["WEIGHTS"]["severity"].get(report.severity.lower(), 0)
                    + remote_config["WEIGHTS"]["epss_score"] * report.epss_score
                    + remote_config["WEIGHTS"]["age"] * report.age
                    + sum(
                        remote_config["WEIGHTS"]["tags"].get(tag, 0)
                        for tag in report.tags
                    ),
                    4,
                )
                if report.risk_score >= risk_score_threshold:
                    break_build = True
                    report.reason = "Risk Score"
                    self.report_breaker.append(copy.deepcopy(report))
            print(
                "Below are open vulnerabilities from Vulnerability Management Platform"
            )
            self.printer_table_gateway.print_table_report(
                report_list,
            )
            if break_build:
                self.break_build = True
                print(
                    self.devops_platform_gateway.message(
                        "error",
                        f"There are findings with risk score greater than {risk_score_threshold}",
                    )
                )
            else:
                print(
                    self.devops_platform_gateway.message(
                        "succeeded",
                        f"There are no findings with risk score greater than {risk_score_threshold}",
                    )
                )
            print(f"Findings count: {len(report_list)}")

        else:
            print(
                self.devops_platform_gateway.message(
                    "succeeded", "There are no vulnerabilities"
                )
            )

    def _print_exclusions(self, applied_exclusions: "list[Exclusions]"):
        if applied_exclusions:
            print(
                self.devops_platform_gateway.message(
                    "warning", "Bellow are all findings that were excepted"
                )
            )
            self.printer_table_gateway.print_table_exclusions(applied_exclusions)
            for reason, total in Counter(
                map(lambda x: x["reason"], applied_exclusions)
            ).items():
                print("{0} findings count: {1}".format(reason, total))
