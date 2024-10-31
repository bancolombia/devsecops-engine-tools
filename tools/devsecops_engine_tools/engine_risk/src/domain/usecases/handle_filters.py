import copy

class HandleFilters:
    def filter(self, findings):
        active_findings = self._get_active_findings(findings)
        self._get_priority_vulnerability(active_findings)
        return active_findings

    def filter_duplicated(self, findings):
        unique_findings = []
        findings_map = {}

        for finding in findings:
            key = (finding.where, tuple(finding.id), finding.vuln_id_from_tool)
            if key in findings_map:
                existing_finding = findings_map[key]
                combined_services = set(existing_finding.service.split() + finding.service.split())
                if finding.active or not existing_finding.active:
                    new_finding = copy.deepcopy(finding)
                    new_finding.service = " ".join(combined_services)
                    findings_map[key] = new_finding
                else:
                    existing_finding.service = " ".join(combined_services)
            else:
                findings_map[key] = copy.deepcopy(finding)

        unique_findings = list(findings_map.values())
        return unique_findings

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
