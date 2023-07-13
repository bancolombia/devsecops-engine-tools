from dataclasses import dataclass, replace
from engine_core.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from engine_core.src.domain.model.InputCore import InputCore


@dataclass
class BreakBuild:
    deserializer_gateway : DeseralizatorGateway
    input_core : InputCore

    def __post_init__(self):
        vulnerabilities_list = self.deserializer_gateway.get_list_vulnerability()
        level_compliance = self.input_core.level_compliance_defined
        exclusions = self.input_core.totalized_exclusions
        rules_scaned = self.input_core.rules_scaned
        checkSeverity = { "critical": 0, "high": 0, "medium": 0, "low": 0 }

        if len(vulnerabilities_list) != 0:
            vulnerabilities_list_with_severity = list(map(lambda vulnerability: replace(vulnerability, severity= rules_scaned[vulnerability.id].get("severity")), vulnerabilities_list))
            vulnerabilities_excluded_list = list(filter(lambda item: exclusions.get(item.id) != None, vulnerabilities_list_with_severity))
            vulnerabilities_without_exclusions_list = list(filter(lambda item: exclusions.get(item.id) == None, vulnerabilities_list_with_severity))

            for vulnerability in vulnerabilities_without_exclusions_list:
                if vulnerability.severity.lower() in checkSeverity:
                    checkSeverity[vulnerability.severity.lower()] += 1

            # vulnerabilities_critical_list = list(filter(lambda item: item.severity.lower() == "critical", vulnerabilities_without_exclusions_list))
            # vulnerabilities_high = len(list(filter(lambda item: item.severity.lower() == "high", vulnerabilities_without_exclusions_list)))
            # # vulnerabilities_medium_list = list(filter(lambda item: item.severity.lower() == "medium", vulnerabilities_without_exclusions_list))
            # count = 0
            # vulnerabilities_high_reduce = reduce(lambda count, vulnerability: count + 1 if vulnerability.severity == "high" else count, vulnerabilities_without_exclusions_list)

            # # vulnerabilities_medium = reduce(lambda count, vulnerability: count + 1 if vulnerability.severity == 'medium' else count, vulnerabilities_without_exclusions_list, 0)
            # vulnerabilities_low_list = list(filter(lambda item: item.severity.lower() == "low", vulnerabilities_without_exclusions_list))
            # vulnerabilities_unknown_list = list(filter(lambda item: exclusions.get(item.severity.lower()) == "unknown", vulnerabilities_without_exclusions_list))
            
            print()
        else:
            return len(vulnerabilities_list)
