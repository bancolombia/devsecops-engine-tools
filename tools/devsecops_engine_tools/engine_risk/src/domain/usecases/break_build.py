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


class BreakBuild:
    def __init__(
        self,
        devops_platform_gateway: DevopsPlatformGateway,
        printer_table_gateway: PrinterTableGateway,
        remote_config: any,
        exclusions: "list[Exclusions]",
    ):
        self.devops_platform_gateway = devops_platform_gateway
        self.printer_table_gateway = printer_table_gateway
        self.remote_config = remote_config
        self.exclusions = exclusions
        self.break_build = False

    def process(self, all_report: "list[Report]", report_list: "list[Report]"):
        self._risk_management_control(all_report)
        new_report_list, applied_exclusions = self._apply_exclusions(report_list)
        self._tag_blacklist_control(new_report_list)
        self._risk_score_control(new_report_list)
        self._print_exclusions(applied_exclusions)

        if self.break_build:
            print(self.devops_platform_gateway.result_pipeline("failed"))
        else:
            print(self.devops_platform_gateway.result_pipeline("succeeded"))

    def _risk_management_control(self, all_report: "list[Report]"):
        remote_config = self.remote_config
        risk_management_value = (
            sum(1 for report in all_report if report.mitigated)
        ) / len(all_report)

        if risk_management_value >= remote_config["THRESHOLD"]["RISK_MANAGEMENT"]:
            print(
                self.devops_platform_gateway.message(
                    "succeeded",
                    f"Risk Management {risk_management_value*100}% is greater than {remote_config['THRESHOLD']['RISK_MANAGEMENT']*100}%.",
                )
            )
        else:
            print(
                self.devops_platform_gateway.message(
                    "error",
                    f"Risk Management {risk_management_value*100}% is less than {remote_config['THRESHOLD']['RISK_MANAGEMENT']*100}%.",
                )
            )
            self.break_build = True

    def _get_applied_exclusion(self, report: Report):
        for exclusion in self.exclusions:
            if exclusion.id and (report.id == exclusion.id):
                return exclusion
            elif exclusion.id and (report.vul_id_tool == exclusion.id):
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
            if report.vul_id_tool and (report.vul_id_tool in exclusions_ids):
                applied_exclusions.append(self._get_applied_exclusion(report))
            elif report.id and (report.id in exclusions_ids):
                applied_exclusions.append(self._get_applied_exclusion(report))
            else:
                new_report_list.append(report)

        return new_report_list, self._map_applied_exclusion(applied_exclusions)

    def _tag_blacklist_control(self, report_list: "list[Report]"):
        remote_config = self.remote_config
        if report_list:
            tag_blacklist = set(remote_config["THRESHOLD"]["TAG_BLACKLIST"])
            tag_age_threshold = remote_config["THRESHOLD"]["TAG_AGE"]

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
                print(
                    self.devops_platform_gateway.message(
                        "error",
                        f"Report {report.vul_id_tool if report.vul_id_tool else report.id} with tag {tag} is blacklisted and age {report.age} is above threshold {tag_age_threshold}",
                    )
                )

            for report, tag in filtered_reports_below_threshold:
                print(
                    self.devops_platform_gateway.message(
                        "warning",
                        f"Report {report.vul_id_tool if report.vul_id_tool else report.id} with tag {tag} is blacklisted but age {report.age} is below threshold {tag_age_threshold}",
                    )
                )

            if filtered_reports_above_threshold:
                self.break_build = True

    def _risk_score_control(self, report_list: "list[Report]"):
        remote_config = self.remote_config
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
            print(
                "Below are all vulnerabilities from Vulnerability Management Platform"
            )
            self.printer_table_gateway.print_table_report(
                report_list,
            )
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
                    "warning", "Bellow are all findings that were excepted."
                )
            )
            self.printer_table_gateway.print_table_exclusions(applied_exclusions)
            for reason, total in Counter(
                map(lambda x: x["reason"], applied_exclusions)
            ).items():
                print("{0} findings count: {1}".format(reason, total))
