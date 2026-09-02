import copy
import os
import json


class HandleFilters:
    def filter(self, findings):
        active_findings = self._get_active_findings(findings)
        self._get_priority_vulnerability(active_findings)
        return active_findings

    def filter_tags_days(self, devops_platform_gateway, remote_config, findings):
        tag_exclusion_days = remote_config["TAG_EXCLUSION_DAYS"]
        runtime_tag_exclusion_days = remote_config["RUNTIME_TAG_EXCLUSION_DAYS"]

        if runtime_tag_exclusion_days["ENABLED"]:
            tag_exclusion_days = self._resolve_runtime_tag_exclusion_days(
                devops_platform_gateway, runtime_tag_exclusion_days, tag_exclusion_days
            )

        filtered_findings = []
        filtered = 0
        for finding in findings:
            if self._is_finding_excluded_by_tag(
                finding, tag_exclusion_days, devops_platform_gateway
            ):
                filtered += 1
            else:
                filtered_findings.append(finding)

        return filtered_findings, filtered

    def _resolve_runtime_tag_exclusion_days(
        self, devops_platform_gateway, runtime_tag_exclusion_days, default_tag_exclusion_days
    ):
        tag_exclusion_days_str = os.environ.get("TAG_EXCLUSION_DAYS")
        if tag_exclusion_days_str and tag_exclusion_days_str.strip():
            try:
                return json.loads(tag_exclusion_days_str)
            except:
                self._print_runtime_tag_exclusion_error(
                    devops_platform_gateway,
                    runtime_tag_exclusion_days,
                    tag_exclusion_days_str,
                    "Parse Error",
                )
        else:
            self._print_runtime_tag_exclusion_error(
                devops_platform_gateway,
                runtime_tag_exclusion_days,
                tag_exclusion_days_str,
                "Invalid Env Var",
            )
        return default_tag_exclusion_days

    def _print_runtime_tag_exclusion_error(
        self, devops_platform_gateway, runtime_tag_exclusion_days, tag_exclusion_days_str, message
    ):
        runtime_message_set = f'Runtime Tag Exclusions days set "{tag_exclusion_days_str}". {message}'
        if runtime_tag_exclusion_days["ERROR_ON_FAILED"]:
            print(devops_platform_gateway.message("error", runtime_message_set))
        else:
            print(
                devops_platform_gateway.message(
                    "info",
                    f"{runtime_message_set}. Using default TAG_EXCLUSION_DAYS",
                )
            )

    def _is_finding_excluded_by_tag(self, finding, tag_exclusion_days, devops_platform_gateway):
        for tag in finding.tags:
            if tag in tag_exclusion_days and finding.age < tag_exclusion_days[tag]:
                print(
                    devops_platform_gateway.message(
                        "warning",
                        f"Report {finding.vm_id} with tag '{tag}' and age {finding.age} days is being excluded. It will be considered in {tag_exclusion_days[tag] - finding.age} days.",
                    )
                )
                return True
        return False

    def _get_active_findings(self, findings):
        return list(
            filter(
                lambda finding: finding.active,
                findings,
            )
        )

    def _get_priority_vulnerability(self, findings):
        for finding in findings:
            found_cve = False
            for vul in finding.id:
                if vul["vulnerability_id"].startswith("CVE"):
                    finding.id = vul["vulnerability_id"]
                    found_cve = True
                    break
            if not found_cve and finding.id:
                finding.id = finding.id[0]["vulnerability_id"]
