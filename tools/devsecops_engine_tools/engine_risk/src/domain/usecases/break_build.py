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
import sympy as sp
import math
from datetime import datetime, timedelta
import holidays


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
        threshold: any,
        policy_excluded: int,
    ):
        self.devops_platform_gateway = devops_platform_gateway
        self.printer_table_gateway = printer_table_gateway
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.vm_exclusions = vm_exclusions
        self.report_list = report_list
        self.all_report = all_report
        self.threshold = threshold
        self.policy_excluded = policy_excluded
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
        new_report_list, applied_exclusions = self._apply_exclusions(self.report_list)
        self._blacklist_control(new_report_list)
        self._remediation_rate_control(self.all_report, new_report_list)
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

    def _remediation_rate_control(
        self, all_report: "list[Report]", new_report_list: "list[Report]"
    ):
        sp.init_printing(use_unicode=True, num_columns=100)
        (
            remediation_rate_name,
            mitigated_name,
            all_findings_name,
            new_findings,
            white_list_name,
            transferred_name,
            base_image_name,
        ) = sp.symbols(
            "RemediationRate Mitigated AllFindings NewFindings WhiteList Transferred BaseImage"
        )
        formula = sp.Eq(
            remediation_rate_name,
            100
            * (
                mitigated_name
                / (
                    all_findings_name
                    - new_findings
                    - white_list_name
                    - transferred_name
                    - base_image_name
                )
            ),
        )
        print("\n")
        sp.pretty_print(formula)
        print("\n")

        mitigated_count = sum(1 for report in all_report if report.mitigated)
        white_list_count = sum(
            1
            for report in all_report
            if "On Whitelist" in report.risk_status and not report.mitigated
        )
        transferred_list_count = sum(
            1
            for report in all_report
            if "Transfer Accepted" in report.risk_status and not report.mitigated
        )
        base_image_count = sum(
            1
            for report in all_report
            if "Image Base" in report.vul_description
            and "On Whitelist" not in report.risk_status
            and "Transfer Accepted" not in report.risk_status
            and not report.mitigated
        )
        all_findings_count = len(all_report)
        print(
            f"Mitigated: {mitigated_count}   AllFindings: {all_findings_count}   BaseImage: {base_image_count}   NewFindings: {self.policy_excluded}   Transferred: {transferred_list_count}   WhiteList: {white_list_count}\n\n"
        )
        total = (
            all_findings_count
            - self.policy_excluded
            - white_list_count
            - base_image_count
            - transferred_list_count
        )

        if total == 0:
            print(
                self.devops_platform_gateway.message(
                    "succeeded",
                    "No findings to mitigate",
                )
            )
            return

        remediation_rate_value = self._get_percentage(mitigated_count / total)
        risk_threshold = self._get_remediation_rate_threshold(total)
        self.remediation_rate = remediation_rate_value

        if remediation_rate_value >= (risk_threshold + 5):
            print(
                self.devops_platform_gateway.message(
                    "succeeded",
                    f"Remediation rate {remediation_rate_value}% is greater than {risk_threshold}%",
                )
            )
        elif remediation_rate_value >= risk_threshold:
            print(
                self.devops_platform_gateway.message(
                    "warning",
                    f"Remediation rate {remediation_rate_value}% is close to {risk_threshold}%",
                )
            )
            self.warning_build = True
        else:
            missing_findings = math.ceil(
                (risk_threshold / 100 * total) - mitigated_count
            )
            print(
                self.devops_platform_gateway.message(
                    "error",
                    f"Remediation rate {remediation_rate_value}% is less than {risk_threshold}%. Minimum findings to mitigate: {missing_findings}.",
                )
            )
            self.break_build = True
            [
                setattr(report, "reason", "Remediation Rate")
                for report in new_report_list
            ]
            self.report_breaker.extend(copy.deepcopy(new_report_list))

    def _get_remediation_rate_threshold(self, total):
        remediation_rate = self.threshold["REMEDIATION_RATE"]
        for key in sorted(
            remediation_rate.keys(),
            key=lambda x: int(x) if x.isdigit() else float("inf"),
        ):
            if key.isdigit() and total <= int(key):
                return remediation_rate[key]
        return remediation_rate["other"]

    def _get_percentage(self, decimal):
        return round(decimal * 100, 3)

    def _map_applied_exclusion(self, exclusions: "list[Exclusions]"):
        return [
            {
                "severity": exclusion.severity,
                "id": exclusion.id,
                "where": exclusion.where,
                "create_date": exclusion.create_date,
                "expired_date": exclusion.expired_date,
                "reason": exclusion.reason,
                "vm_id": exclusion.vm_id,
                "vm_id_url": exclusion.vm_id_url,
                "service": exclusion.service,
                "tags": exclusion.tags,
            }
            for exclusion in exclusions
        ]

    def _apply_exclusions(self, report_list: "list[Report]"):
        filtered_reports = []
        applied_exclusions = []

        for report in report_list:
            exclude = False
            for exclusion in self.exclusions:
                if (
                    (
                        report.vuln_id_from_tool
                        and report.vuln_id_from_tool == exclusion.id
                    )
                    or (report.id and report.id == exclusion.id)
                    or (report.vm_id and exclusion.id in report.vm_id)
                ) and ((exclusion.where in report.where) or (exclusion.where == "all")):
                    if not exclusion.check_in_desc:
                        exclude = True
                    else:
                        for item in exclusion.check_in_desc:
                            if item in report.vul_description:
                                exclude = True
                                break
                    if exclude:
                        exclusion_copy = copy.deepcopy(exclusion)
                        exclusion_copy.vm_id = report.vm_id
                        exclusion_copy.vm_id_url = report.vm_id_url
                        exclusion_copy.service = report.service
                        exclusion_copy.tags = report.tags
                        applied_exclusions.append(exclusion_copy)
                        break
            if not exclude:
                filtered_reports.append(report)

        return filtered_reports, applied_exclusions

    def _blacklist_control(self, report_list: "list[Report]"):
        remote_config = self.remote_config
        if report_list:
            tag_blacklist = set(remote_config["TAG_BLACKLIST_EXCLUSION_DAYS"].keys())
            colombian_holidays = holidays.Colombia()

        def calculate_working_days(start_date, days):
            current_date = start_date
            working_days = 0
            while working_days < days:
                current_date += timedelta(days=1)
                if (
                    current_date.weekday() < 5
                    and current_date not in colombian_holidays
                ):
                    working_days += 1
            return current_date

        filtered_reports_above_threshold = []
        filtered_reports_below_threshold = []

        for report in report_list:
            for tag in report.tags:
                if tag in tag_blacklist:
                    exclusion_value = remote_config["TAG_BLACKLIST_EXCLUSION_DAYS"][tag]
                    if isinstance(exclusion_value, str) and "WD" in exclusion_value:
                        working_days_threshold = int(exclusion_value.replace("WD", ""))
                        report_created_date = datetime.strptime(
                            report.created.split("T")[0], "%Y-%m-%d"
                        )
                        threshold_date = calculate_working_days(
                            report_created_date, working_days_threshold
                        )
                        if datetime.now() >= threshold_date:
                            filtered_reports_above_threshold.append((report, tag))
                        else:
                            filtered_reports_below_threshold.append((report, tag))
                    else:
                        numeric_threshold = int(exclusion_value)
                        if report.age >= numeric_threshold:
                            filtered_reports_above_threshold.append((report, tag))
                        else:
                            filtered_reports_below_threshold.append((report, tag))

        for report, tag in filtered_reports_above_threshold:
            report.reason = "Blacklisted"
            print(
                self.devops_platform_gateway.message(
                    "error",
                    f"Report {report.vm_id} with tag '{tag}' is blacklisted and age {report.age} is above threshold {remote_config['TAG_BLACKLIST_EXCLUSION_DAYS'][tag]}",
                )
            )

        for report, tag in filtered_reports_below_threshold:
            print(
                self.devops_platform_gateway.message(
                    "warning",
                    f"Report {report.vm_id} with tag '{tag}' is blacklisted but age {report.age} is below threshold {remote_config['TAG_BLACKLIST_EXCLUSION_DAYS'][tag]}",
                )
            )
            self.policy_excluded += 1

        if filtered_reports_above_threshold:
            self.break_build = True
            self.blacklisted += len(filtered_reports_above_threshold)
            self.report_breaker.extend(
                copy.deepcopy(
                    [report for report, _ in filtered_reports_above_threshold]
                )
            )

        for report in report_list:
            if "On Blacklist" in report.risk_status:
                self.break_build = True
                report.reason = "Blacklisted"
                self.blacklisted += 1
                self.report_breaker.append(copy.deepcopy(report))
                print(
                    self.devops_platform_gateway.message(
                        "error",
                        f"Report {report.vm_id} is blacklisted.",
                    )
                )

    def _risk_score_control(self, report_list: "list[Report]"):
        remote_config = self.remote_config
        risk_score_threshold = self.threshold["RISK_SCORE"]
        break_build = False
        if report_list:
            for report in report_list:
                report.risk_score = round(
                    remote_config["WEIGHTS"]["severity"].get(report.severity.lower(), 0)
                    + remote_config["WEIGHTS"]["epss_score"] * report.epss_score
                    + min(
                        remote_config["WEIGHTS"]["age"] * report.age,
                        remote_config["WEIGHTS"]["max_age"],
                    )
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
            print("Below are open findings from Vulnerability Management Platform")
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
                    "succeeded",
                    "There are no open findings from Vulnerability Management Platform",
                )
            )

    def _print_exclusions(self, applied_exclusions: "list[Exclusions]"):
        if applied_exclusions:
            print(
                self.devops_platform_gateway.message(
                    "warning", "Bellow are all findings that were excepted"
                )
            )
            self.printer_table_gateway.print_table_report_exlusions(applied_exclusions)
            for reason, total in Counter(
                map(lambda x: x["reason"], applied_exclusions)
            ).items():
                print("{0} findings count: {1}".format(reason, total))
