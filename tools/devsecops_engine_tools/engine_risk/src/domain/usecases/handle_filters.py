class HandleFilters:
    def filter(self, findings):
        active_findings = self._get_active_findings(findings)
        self._get_priority_vulnerability(active_findings)
        return active_findings

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
