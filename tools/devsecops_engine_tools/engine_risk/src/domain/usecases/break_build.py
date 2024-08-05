from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.printer_table_gateway import (
    PrinterTableGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.report import (
    Report,
)


class BreakBuild:
    def __init__(
        self,
        devops_platform_gateway: DevopsPlatformGateway,
        printer_table_gateway: PrinterTableGateway,
        remote_config: any,
    ):
        self.devops_platform_gateway = devops_platform_gateway
        self.printer_table_gateway = printer_table_gateway
        self.remote_config = remote_config

    def process(self, report_list: "list[Report]"):
        devops_platform_gateway = self.devops_platform_gateway
        printer_table_gateway = self.printer_table_gateway
        remote_config = self.remote_config
        if len(report_list):
            for report in report_list:
                report.risk_score = remote_config["WEIGHTS"]["severity"].get(report.severity.lower(), 1) + \
                                    remote_config["WEIGHTS"]["epss_score"] * report.epss_score + \
                                    remote_config["WEIGHTS"]["age"] * report.age + \
                                    sum(remote_config["WEIGHTS"]["tags"].get(tag, 0) for tag in report.tags)
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
