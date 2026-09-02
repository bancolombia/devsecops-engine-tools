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
        self.max_priority_score = 0
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
        finding_score_model = self.remote_config.get("FINDING_SCORE", {}).get("MODEL")
        if finding_score_model == "PRIORITY":
            self._priority_control(new_report_list)
        else:
            self._risk_score_control(new_report_list)
        all_exclusions = list(self.vm_exclusions) + list(applied_exclusions)
        self._print_exclusions(self._map_applied_exclusion(all_exclusions))

        self._breaker()

        self.scan_result["findings_excluded"] = [
            {
                "severity": item.severity,
                "id": item.id,
                "category": item.reason,
            }
            for item in all_exclusions
        ]

        self.scan_result["risk"] = {
            "risk_control": {
                "remediation_rate": self.remediation_rate,
                "blacklisted": self.blacklisted,
                "max_risk_score": self.max_risk_score,
                "max_priority_score": self.max_priority_score,
            },
            "status": self.status,
            "found": self.report_breaker,
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
        self._print_remediation_rate_formula()

        counts = self._compute_remediation_rate_counts(all_report)
        print(
            f"Mitigated: {counts['mitigated']}   AllFindings: {counts['all_findings']}   BaseImage: {counts['base_image']}   NewFindings: {self.policy_excluded}   Transferred: {counts['transferred']}   WhiteList: {counts['white_list']}\n\n"
        )
        total = (
            counts["all_findings"]
            - self.policy_excluded
            - counts["white_list"]
            - counts["base_image"]
            - counts["transferred"]
        )

        if total == 0:
            print(
                self.devops_platform_gateway.message(
                    "succeeded",
                    "No findings to mitigate",
                )
            )
            return

        remediation_rate_value = self._get_percentage(counts["mitigated"] / total)
        risk_threshold = self._get_remediation_rate_threshold(total)
        self.remediation_rate = remediation_rate_value

        self._evaluate_remediation_rate(
            remediation_rate_value,
            risk_threshold,
            total,
            counts["mitigated"],
            new_report_list,
        )

    def _print_remediation_rate_formula(self):
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

    def _compute_remediation_rate_counts(self, all_report):
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
        return {
            "mitigated": mitigated_count,
            "white_list": white_list_count,
            "transferred": transferred_list_count,
            "base_image": base_image_count,
            "all_findings": len(all_report),
        }

    def _evaluate_remediation_rate(
        self, remediation_rate_value, risk_threshold, total, mitigated_count, new_report_list
    ):
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
            for report in new_report_list:
                self._append_report_breaker(report, "Remediation Rate")

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
            applied_exclusion = self._find_matching_exclusion(report)
            if applied_exclusion is not None:
                applied_exclusions.append(applied_exclusion)
            else:
                filtered_reports.append(report)

        return filtered_reports, applied_exclusions

    def _find_matching_exclusion(self, report):
        for exclusion in self.exclusions:
            if not self._exclusion_matches_report(report, exclusion):
                continue
            if self._exclusion_matches_description(report, exclusion):
                exclusion_copy = copy.deepcopy(exclusion)
                exclusion_copy.vm_id = report.vm_id
                exclusion_copy.vm_id_url = report.vm_id_url
                exclusion_copy.service = report.service
                exclusion_copy.tags = report.tags
                return exclusion_copy
        return None

    def _exclusion_matches_report(self, report, exclusion):
        id_matches = (
            (report.vuln_id_from_tool and report.vuln_id_from_tool == exclusion.id)
            or (report.id and report.id == exclusion.id)
            or (report.vm_id and exclusion.id in report.vm_id)
        )
        where_matches = (exclusion.where in report.where) or (exclusion.where == "all")
        return id_matches and where_matches

    def _exclusion_matches_description(self, report, exclusion):
        if not exclusion.check_in_desc:
            return True
        return any(item in report.vul_description for item in exclusion.check_in_desc)

    def _blacklist_control(self, report_list: "list[Report]"):
        remote_config = self.remote_config
        tag_blacklist = set()
        country_holidays = None
        if report_list:
            tag_blacklist = set(remote_config["TAG_BLACKLIST_EXCLUSION_DAYS"].keys())
            country_holidays = holidays.country_holidays(
                remote_config.get("COUNTRY_HOLIDAYS")
            )

        above_threshold, below_threshold = self._classify_blacklisted_reports(
            report_list, tag_blacklist, country_holidays, remote_config
        )

        if above_threshold or below_threshold:
            print()

        self._report_blacklist_above_threshold(above_threshold, remote_config)
        self._report_blacklist_below_threshold(below_threshold, remote_config)

        if above_threshold:
            self.break_build = True
            self.blacklisted += len(above_threshold)
            for report, _ in above_threshold:
                self._append_report_breaker(report, "Blacklisted")

        self._check_blacklist_risk_status(report_list)

    def _classify_blacklisted_reports(self, report_list, tag_blacklist, country_holidays, remote_config):
        above_threshold = []
        below_threshold = []
        for report in report_list:
            for tag in report.tags:
                if tag not in tag_blacklist:
                    continue
                exclusion_value = remote_config["TAG_BLACKLIST_EXCLUSION_DAYS"][tag]
                if self._is_blacklist_threshold_exceeded(report, exclusion_value, country_holidays):
                    above_threshold.append((report, tag))
                else:
                    below_threshold.append((report, tag))
        return above_threshold, below_threshold

    def _is_blacklist_threshold_exceeded(self, report, exclusion_value, country_holidays):
        if isinstance(exclusion_value, str) and "WD" in exclusion_value:
            working_days_threshold = int(exclusion_value.replace("WD", ""))
            report_created_date = datetime.strptime(
                report.created.split("T")[0], "%Y-%m-%d"
            )
            threshold_date = self._calculate_working_days(
                report_created_date, working_days_threshold, country_holidays
            )
            return datetime.now() >= threshold_date

        numeric_threshold = int(exclusion_value)
        return report.age >= numeric_threshold

    def _calculate_working_days(self, start_date, days, country_holidays):
        current_date = start_date
        working_days = 0
        while working_days < days:
            current_date += timedelta(days=1)
            if current_date.weekday() < 5 and current_date not in country_holidays:
                working_days += 1
        return current_date

    def _report_blacklist_above_threshold(self, above_threshold, remote_config):
        for report, tag in above_threshold:
            report.reason = "Blacklisted"
            print(
                self.devops_platform_gateway.message(
                    "error",
                    f"Report {report.vm_id} with tag '{tag}' is blacklisted and age {report.age} is above threshold {remote_config['TAG_BLACKLIST_EXCLUSION_DAYS'][tag]}",
                )
            )

    def _report_blacklist_below_threshold(self, below_threshold, remote_config):
        for report, tag in below_threshold:
            print(
                self.devops_platform_gateway.message(
                    "warning",
                    f"Report {report.vm_id} with tag '{tag}' is blacklisted but age {report.age} is below threshold {remote_config['TAG_BLACKLIST_EXCLUSION_DAYS'][tag]}",
                )
            )
            self.policy_excluded += 1

    def _check_blacklist_risk_status(self, report_list):
        for report in report_list:
            if "On Blacklist" in report.risk_status:
                self.break_build = True
                self.blacklisted += 1
                self._append_report_breaker(report, "Blacklisted")
                print(
                    self.devops_platform_gateway.message(
                        "error",
                        f"Report {report.vm_id} is blacklisted.",
                    )
                )

    def _append_report_breaker(self, report, reason):
        self.report_breaker.append(
            {
                "id": (
                    report.vuln_id_from_tool
                    if report.vuln_id_from_tool
                    else report.id
                ),
                "severity": report.severity,
                "risk_score": (
                    str(report.risk_score) if report.risk_score else "0"
                ),
                "priority_score": (
                    str(report.priority) if report.priority else "0"
                ),
                "reason": reason,
            }
        )

    def _risk_score_control(self, report_list: "list[Report]"):
        remote_config = self.remote_config
        score_threshold = self.threshold["SCORE"]
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
                if report.risk_score > score_threshold:
                    break_build = True
                    self.report_breaker.append(
                        {
                            "id": (
                                report.vuln_id_from_tool
                                if report.vuln_id_from_tool
                                else report.id
                            ),
                            "severity": report.severity,
                            "risk_score": str(report.risk_score),
                            "priority_score": "0",
                            "reason": "Risk Score",
                        }
                    )
            print()
            print("Below are open findings from Vulnerability Management Platform")
            self.printer_table_gateway.print_table_report(
                report_list,
                self.remote_config.get("FINDING_SCORE", {}).get("MODEL"),
            )
            if break_build:
                self.break_build = True
                print(
                    self.devops_platform_gateway.message(
                        "error",
                        f"There are findings with risk score greater than {score_threshold}",
                    )
                )
            else:
                print(
                    self.devops_platform_gateway.message(
                        "succeeded",
                        f"There are no findings with risk score greater than {score_threshold}",
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

        self.max_risk_score = (
            max(report.risk_score for report in report_list) if report_list else 0
        )

    def _priority_control(self, report_list: "list[Report]"):
        score_threshold = self.threshold["SCORE"]
        model = self.remote_config.get("FINDING_SCORE", {}).get("MODEL")
        classification_threshold = self.threshold.get(model, {})

        service_reports = self._group_reports_by_service(report_list)

        max_priority_score = 0
        break_build = False
        for service, reports in service_reports.items():
            priority_score_sum = sum(report.priority for report in reports)

            print(
                f"\nBelow are open findings for '{service}' from Vulnerability Management Platform"
            )
            self.printer_table_gateway.print_table_report(
                reports,
                model,
            )

            if priority_score_sum > max_priority_score:
                max_priority_score = priority_score_sum

            if self._evaluate_priority_score_sum(priority_score_sum, score_threshold, reports):
                break_build = True

            if self._evaluate_priority_classification(reports, classification_threshold):
                break_build = True

        if break_build:
            self.break_build = True

        self.max_priority_score = max_priority_score

    def _group_reports_by_service(self, report_list):
        service_reports = {}
        for report in report_list:
            service_reports.setdefault(report.service, []).append(report)
        return service_reports

    def _evaluate_priority_score_sum(self, priority_score_sum, score_threshold, reports):
        if priority_score_sum > score_threshold:
            for report in reports:
                self._append_priority_report_breaker(report, "Priority Score")
            print(
                self.devops_platform_gateway.message(
                    "error",
                    f"The sum of priorities {priority_score_sum} is greater than the threshold {score_threshold}",
                )
            )
            return True

        print(
            self.devops_platform_gateway.message(
                "succeeded",
                f"The sum of priorities {priority_score_sum} is less than the threshold {score_threshold}",
            )
        )
        return False

    def _evaluate_priority_classification(self, reports, classification_threshold):
        classification_reports = self._group_reports_by_classification(reports)
        classification_counts, has_threshold_violation = self._compute_classification_counts(
            classification_reports, classification_threshold
        )

        counts_str = ", ".join(
            [f"{k}: {v['count']}" for k, v in classification_counts.items()]
        )
        criteria_str = ", ".join(
            [f"{k}: {v['limit']}" for k, v in classification_counts.items()]
        )

        if not has_threshold_violation:
            print(
                self.devops_platform_gateway.message(
                    "succeeded",
                    f"Count of priority classes ({counts_str}) is not greater than or equal to failure criteria ({criteria_str}, operator: or)",
                )
            )
            return False

        print(
            self.devops_platform_gateway.message(
                "error",
                f"Count of priority classes ({counts_str}) is greater than or equal to failure criteria ({criteria_str}, operator: or)",
            )
        )
        for classification, values in classification_counts.items():
            if not values["violated"]:
                continue
            for report in classification_reports.get(classification, []):
                self._append_priority_report_breaker(report, "Priority Threshold")

        return True

    def _group_reports_by_classification(self, reports):
        classification_reports = {}
        for report in reports:
            classification_reports.setdefault(report.priority_classification, []).append(report)
        return classification_reports

    def _compute_classification_counts(self, classification_reports, classification_threshold):
        classification_counts = {}
        has_threshold_violation = False
        for classification in classification_threshold.keys():
            count = len(classification_reports.get(classification, []))
            limit = classification_threshold.get(classification, 999)
            classification_counts[classification] = {
                "count": count,
                "limit": limit,
                "violated": count >= limit,
            }
            if count >= limit:
                has_threshold_violation = True
        return classification_counts, has_threshold_violation

    def _append_priority_report_breaker(self, report, reason):
        self.report_breaker.append(
            {
                "id": (
                    report.vuln_id_from_tool
                    if report.vuln_id_from_tool
                    else report.id
                ),
                "severity": report.severity,
                "risk_score": "0",
                "priority_score": str(report.priority),
                "reason": reason,
            }
        )

    def _print_exclusions(self, applied_exclusions: "list[Exclusions]"):
        if applied_exclusions:
            print()
            print(
                self.devops_platform_gateway.message(
                    "warning", "Bellow are all findings that were excepted"
                )
            )
            self.printer_table_gateway.print_table_report_exclusions(applied_exclusions)
            for reason, total in Counter(
                x["reason"] for x in applied_exclusions
            ).items():
                print("{0} findings count: {1}".format(reason, total))
