from dataclasses import dataclass
from functools import reduce

from devsecops_engine_tools.engine_core.src.domain.model.input_core import InputCore
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability import (
    Vulnerability,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.print_table_gateway import (
    PrintTableGateway,
)


@dataclass
class BreakBuild:
    devops_platform_gateway: DevopsPlatformGateway
    print_table_gateway: PrintTableGateway
    vulnerabilities_list: "list[Vulnerability]"
    input_core: InputCore

    def __post_init__(self):
        devops_platform_gateway = self.devops_platform_gateway
        print_table_gateway = self.print_table_gateway
        level_compliance = self.input_core.level_compliance_defined
        exclusions = self.input_core.totalized_exclusions

        if len(self.vulnerabilities_list) != 0:
            vulnerabilities_list = self.vulnerabilities_list

            # Esta lista de excluidas no se imprimira para dejar un resultado más limpio
            vulnerabilities_excluded_list = list(
                filter(
                    lambda item: any(
                        exclusion["Id"] == item.id
                        and (
                            exclusion["Where"] in item.where_vulnerability
                            or "all" in exclusion["Where"]
                        )
                        for exclusion in exclusions
                    ),
                    vulnerabilities_list,
                )
            )

            vulnerabilities_without_exclusions_list = list(
                filter(
                    lambda v: v not in vulnerabilities_excluded_list,
                    vulnerabilities_list,
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

            if (
                vulnerabilities_critical >= level_compliance.critical
                or vulnerabilities_high >= level_compliance.high
                or vulnerabilities_medium >= level_compliance.medium
                or vulnerabilities_low >= level_compliance.low
            ):
                print_table_gateway.print_table(vulnerabilities_without_exclusions_list)
                print(
                    devops_platform_gateway.logging(
                        "error",
                        "Security count issues (critical: {0}, high: {1}, medium: {2}, low: {3}) is greater than or equal to failure criteria (critical: {4}, high: {5}, medium: {6}, low:{7}, operator: or)".format(
                            vulnerabilities_critical,
                            vulnerabilities_high,
                            vulnerabilities_medium,
                            vulnerabilities_low,
                            level_compliance.critical,
                            level_compliance.high,
                            level_compliance.medium,
                            level_compliance.low,
                        ),
                    )
                )
                print(devops_platform_gateway.result_pipeline("failed"))
            else:
                print_table_gateway.print_table(vulnerabilities_without_exclusions_list)
                print(
                    devops_platform_gateway.logging(
                        "warning",
                        "Security count issues (critical: {0}, high: {1}, medium: {2}, low: {3}) is not greater than or equal to failure criteria (critical: {4}, high: {5}, medium: {6}, low:{7}, operator: or)".format(
                            vulnerabilities_critical,
                            vulnerabilities_high,
                            vulnerabilities_medium,
                            vulnerabilities_low,
                            level_compliance.critical,
                            level_compliance.high,
                            level_compliance.medium,
                            level_compliance.low,
                        ),
                    )
                )
                print(devops_platform_gateway.result_pipeline("succeeded"))
        else:
            print(
                devops_platform_gateway.logging(
                    "succeeded", "There are no vulnerabilities"
                )
            )
            print(devops_platform_gateway.result_pipeline("succeeded"))

        print(
            devops_platform_gateway.logging(
                "info",
                "If you have doubts, visit https://discuss.apps.bancolombia.com/t/lanzamiento-csa-analisis-de-seguridad-en-contenedores/6199",
            )
        )
