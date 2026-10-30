import sys
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings
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

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


@dataclass
class BreakBuild:
    def __init__(
        self,
        devops_platform_gateway: DevopsPlatformGateway,
        printer_table_gateway: PrinterTableGateway,
    ):
        self.devops_platform_gateway = devops_platform_gateway
        self.printer_table_gateway = printer_table_gateway

    def process(self, findings_list: "list[Finding]", input_core: InputCore, args: any, warning_release: bool, manager: any):
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

            findings_excluded, findings_without_exclusions = self._filter_findings(
                findings_list,
                exclusions,
                args,
                debug=input_core.debug_exclusion_diagnostics,
                pipeline_name=input_core.scope_pipeline,
                base_image_names=input_core.base_image_names,
            )
            scan_result["findings_excluded"] = [self._map_finding_excluded(item) for item in findings_excluded]
            
            vulnerabilities = [v for v in findings_without_exclusions if v.category == Category.VULNERABILITY]
            compliances = [v for v in findings_without_exclusions if v.category == Category.COMPLIANCE]

            vulnerability_counts = self._count_severities(vulnerabilities, manager)
            compliance_counts = self._count_severities_compliance(compliances)

            self._handle_vulnerabilities(vulnerability_counts, vulnerabilities, threshold, warning_release, scan_result, args, manager)
            self._handle_cve_policy(vulnerabilities, threshold)
            self._handle_compliances(compliance_counts, compliances, threshold, warning_release, scan_result, args, manager)
            self._handle_exclusions(
                findings_excluded,
                exclusions,
                manager,
                args,
                input_core.base_image_names,
            )
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
                                    "severity": item.severity,
                                    "create_date": date_initial.strftime("%d%m%Y"),
                                    "expired_date": date_final.strftime("%d%m%Y"),
                                    "reason": "New vulnerability in the industry",
                                    "priority": item.priority.scale
                                }
                            )
                        )

    def _filter_findings(
        self,
        findings_list,
        exclusions,
        args,
        debug=False,
        pipeline_name="",
        base_image_names=None,
    ):
        findings_excluded_list = []
        findings_without_exclusions_list = []
        image_to_scan = args.get("image_to_scan", "")

        for item in findings_list:
            checks = [
                (
                    exclusion,
                    self._exclusion_match_details(
                        item, exclusion, args, base_image_names
                    ),
                )
                for exclusion in exclusions
            ]
            if debug:
                candidates = [
                    {
                        "exclusion_id": exclusion.id,
                        "exclusion_images": exclusion.check_in_desc,
                        **details,
                    }
                    for exclusion, details in checks
                    if details["id_match"]
                    or (details["image_check_required"] and details["image_match"])
                ]
                logger.info(
                    "Cross-approval exclusion diagnostics for pipeline %s: "
                    "finding=%s checked=%s candidates=%s",
                    pipeline_name,
                    {
                        "id": item.id,
                        "where": item.where,
                        "severity": item.severity,
                        "priority": item.priority.scale if item.priority else None,
                        "module": args.get("module"),
                        "image_to_scan": image_to_scan,
                        "base_image_names": base_image_names or [],
                    },
                    len(exclusions),
                    candidates,
                )

            if any(details["matched"] for _, details in checks):
                findings_excluded_list.append(item)
            else:
                findings_without_exclusions_list.append(item)

        return findings_excluded_list, findings_without_exclusions_list

    @staticmethod
    def _matches_exclusion(item, exclusion, args, base_image_names=None):
        return BreakBuild._exclusion_match_details(
            item, exclusion, args, base_image_names
        )["matched"]

    @staticmethod
    def _exclusion_match_details(item, exclusion, args, base_image_names=None):
        id_match = exclusion.id == item.id
        where_match = exclusion.where in item.where or "all" in exclusion.where
        finding_priority = item.priority.scale if item.priority else None
        severity_match = BreakBuild._value_in_exclusion_list(
            exclusion.severity, item.severity
        )
        priority_match = BreakBuild._value_in_exclusion_list(
            exclusion.priority, finding_priority
        )
        image_check_required = (
            args.get("module") == "engine_container" and bool(exclusion.check_in_desc)
        )
        image_to_scan = args.get("image_to_scan", "")
        image_names = [image_to_scan] if image_to_scan else []
        image_names.extend(base_image_names or [])
        image_match = not image_check_required or (
            any(
                image_name in excluded_image
                for image_name in image_names
                for excluded_image in exclusion.check_in_desc
            )
        )
        matched = (
            id_match
            and where_match
            and (severity_match or priority_match)
            and image_match
        )
        return {
            "id_match": id_match,
            "where_match": where_match,
            "severity_match": severity_match,
            "priority_match": priority_match,
            "image_check_required": image_check_required,
            "image_match": image_match,
            "matched": matched,
        }

    @staticmethod
    def _value_in_exclusion_list(exclusion_value, finding_value):
        if not exclusion_value or finding_value is None:
            return False
        values = [value.strip() for value in exclusion_value.split(",")]
        return finding_value in values

    def _map_finding_excluded(self, item):
        return {
            "id": item.id,
            "severity": item.severity,
            "priority": str(item.priority.scale).replace(" ", "_"),
            "category": item.category.value,
        }

    def _count_severities(self, findings_list, manager):
        counts = {
            manager["CLASSIFICATION"][0]: 0,
            manager["CLASSIFICATION"][1]: 0,
            manager["CLASSIFICATION"][2]: 0,
            manager["CLASSIFICATION"][3]: 0
        }
        model = manager.get("MODEL", "severity")
        
        for finding in findings_list:
            if model == "priority":
                if finding.priority and finding.priority.scale:
                    severity = finding.priority.scale.lower()
                else:
                    continue
            else:
                severity = finding.severity.lower()
            
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _count_severities_compliance(self, findings_list):
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

    def _handle_vulnerabilities(self, counts, vulnerabilities_list, threshold, warning_release, scan_result, args, manager):
        devops_platform_gateway = self.devops_platform_gateway
        printer_table_gateway = self.printer_table_gateway
        print()

        classifications = manager["CLASSIFICATION"]
        total = sum(counts[severity] for severity in classifications)
        if total == 0:
            print(devops_platform_gateway.message("succeeded", "There are no vulnerabilities"))
            print(devops_platform_gateway.result_pipeline("succeeded"))
            return

        model = manager.get("MODEL", "severity")

        def get_threshold_value(idx):
            if model == "severity":
                return getattr(threshold.vulnerability, classifications[idx], 0)
            else:
                priority_map = {
                    0: "very_critical_priority",
                    1: "critical_priority",
                    2: "high_priority",
                    3: "medium_low_priority"
                }
                return getattr(threshold.priority, priority_map.get(idx, ""), 0)

        threshold_exceeded = any(
            counts.get(classifications[idx], 0) >= get_threshold_value(idx)
            for idx in range(min(4, len(classifications)))
        )

        threshold_values = [get_threshold_value(idx) for idx in range(min(4, len(classifications)))]

        if threshold_exceeded:
            print("Below are all vulnerabilities detected.")
            if vulnerabilities_list and args.get("tool", None) == "kiuwan":
                print(f"Analysis url: {vulnerabilities_list[0].analysis_url}")
            printer_table_gateway.print_table_findings(vulnerabilities_list, manager)
            print(devops_platform_gateway.message(
                "error",
                "Security count issues ({0}: {1}, {2}: {3}, {4}: {5}, {6}: {7}) is greater than or equal to failure criteria ({0}: {8}, {2}: {9}, {4}: {10}, {6}: {11}, operator: or)".format(
                    classifications[0], counts.get(classifications[0], 0),
                    classifications[1], counts.get(classifications[1], 0),
                    classifications[2], counts.get(classifications[2], 0),
                    classifications[3], counts.get(classifications[3], 0),
                    *threshold_values
                )
            ))
            print(devops_platform_gateway.result_pipeline("failed"))
            scan_result["vulnerabilities"] = {
                "model_break_build": model,
                "threshold": {k.replace(" ", "_"): v for k, v in counts.items()},
                "status": "failed",
                "found": [{"id": item.id, "severity": item.severity, "priority": str(item.priority.scale).replace(" ", "_")} for item in vulnerabilities_list],
            }
        else:
            print("Below are all vulnerabilities detected.")
            printer_table_gateway.print_table_findings(vulnerabilities_list, manager)
            print(devops_platform_gateway.message(
                "warning",
                "Security count issues ({0}: {1}, {2}: {3}, {4}: {5}, {6}: {7}) is not greater than or equal to failure criteria ({0}: {8}, {2}: {9}, {4}: {10}, {6}: {11}, operator: or)".format(
                    classifications[0], counts.get(classifications[0], 0),
                    classifications[1], counts.get(classifications[1], 0),
                    classifications[2], counts.get(classifications[2], 0),
                    classifications[3], counts.get(classifications[3], 0),
                    *threshold_values
                )
            ))
            result = "succeeded_with_issues" if warning_release or devops_platform_gateway.get_variable("stage") == "build" else "succeeded"
            print(devops_platform_gateway.result_pipeline(result))
            scan_result["vulnerabilities"] = {
                "model_break_build": model,
                "threshold": {k.replace(" ", "_"): v for k, v in counts.items()},
                "status": "succeeded",
                "found": [{"id": item.id, "severity": item.severity, "priority": str(item.priority.scale).replace(" ", "_")} for item in vulnerabilities_list],
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

    def _handle_compliances(self, counts, compliances_list, threshold, warning_release, scan_result, args, manager):
        devops_platform_gateway = self.devops_platform_gateway
        printer_table_gateway = self.printer_table_gateway
        print()

        if compliances_list:
            print("Below are all compliances issues detected.")
            if compliances_list and args.get("tool", None) == "kiuwan":
                print(f"Analysis url: {compliances_list[0].analysis_url}")
            printer_table_gateway.print_table_findings(compliances_list, manager)
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
                "found": [{"id": item.id, "severity": item.severity, "priority": str(item.priority.scale).replace(" ", "_")} for item in compliances_list],
            }
        else:
            print(devops_platform_gateway.message("succeeded", "There are no compliances issues"))
            print(devops_platform_gateway.result_pipeline("succeeded"))

    def _handle_exclusions(
        self,
        findings_excluded_list,
        exclusions,
        break_build_manager,
        args,
        base_image_names=None,
    ):
        devops_platform_gateway = self.devops_platform_gateway
        printer_table_gateway = self.printer_table_gateway
        print()

        model = break_build_manager.get("MODEL", "severity")
        if findings_excluded_list:
            exclusions_list = []
            for item in findings_excluded_list:
                matching_exclusions = [
                    exclusion
                    for exclusion in exclusions
                    if self._matches_exclusion(
                        item, exclusion, args, base_image_names
                    )
                ]
                image_exclusions = [
                    exclusion
                    for exclusion in matching_exclusions
                    if exclusion.check_in_desc
                ]
                matching = max(
                    image_exclusions or matching_exclusions,
                    key=lambda exclusion: (
                        datetime.strptime(exclusion.expired_date, "%d%m%Y")
                        if exclusion.expired_date
                        else datetime.min
                    ),
                    default=None,
                )
                if matching:
                    exclusions_list.append({
                        "severity": item.severity if model == "severity" else item.priority.scale,
                        "id": item.id,
                        "where": item.where,
                        "create_date": matching.create_date,
                        "expired_date": matching.expired_date,
                        "reason": matching.reason,
                        "module": item.module,
                        "fixed in": item.requirements,
                    })
            
            print(devops_platform_gateway.message("warning", "Below are all findings that were excepted."))
            printer_table_gateway.print_table_exclusions(exclusions_list, break_build_manager)
            
            for reason, total in Counter(x["reason"] for x in exclusions_list).items():
                print("{0} findings count: {1}".format(reason, total))