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

    def _risk_management_control(self, all_report: "list[Report]"):
        devops_platform_gateway = self.devops_platform_gateway
        remote_config = self.remote_config
        risk_management_value = (
            sum(1 for report in all_report if report.mitigated)
        ) / len(all_report)

        if risk_management_value >= remote_config["THRESHOLDS"]["RISK_MANAGEMENT"]:
            print(
                devops_platform_gateway.message(
                    "succeeded",
                    f"Risk Management {risk_management_value*100}% is greater than {remote_config['THRESHOLDS']['RISK_MANAGEMENT']*100}%.",
                )
            )
        else:
            print(
                devops_platform_gateway.message(
                    "error",
                    f"Risk Management {risk_management_value*100}% is less than {remote_config['THRESHOLDS']['RISK_MANAGEMENT']*100}%.",
                )
            )
            print(devops_platform_gateway.result_pipeline("failed"))

    def _apply_exclusions(self, report_list: "list[Report]"):
        applied_exclusions = []
        exclusions_ids = {exclusion.id for exclusion in self.exclusions if exclusion.id}

        for report in report_list[:]:
            if report.id and (report.id in exclusions_ids):
                applied_exclusions.append(report)
                report_list.remove(report)
            elif report.vul_id_tool and (report.vul_id_tool in exclusions_ids):
                applied_exclusions.append(report)
                report_list.remove(report)

        return applied_exclusions

    def _risk_score_control(self, report_list: "list[Report]"):
        devops_platform_gateway = self.devops_platform_gateway
        printer_table_gateway = self.printer_table_gateway
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
            printer_table_gateway.print_table_report(
                report_list,
            )
        else:
            print(
                devops_platform_gateway.message(
                    "succeeded", "There are no vulnerabilities"
                )
            )

    def process(self, all_report: "list[Report]", report_list: "list[Report]"):

        self._risk_management_control(all_report)

        applied_exclusions = self._apply_exclusions(report_list)

        self._risk_score_control(report_list)
