import copy
from rich.console import Console


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
                combined_services = existing_finding.service.split() + [
                    s
                    for s in finding.service.split()
                    if s not in existing_finding.service.split()
                ]
                combined_services_url = existing_finding.service_url.split() + [
                    s_url
                    for s_url in finding.service_url.split()
                    if s_url not in existing_finding.service_url.split()
                ]
                combined_vm_ids = existing_finding.vm_id.split() + [
                    vm
                    for vm in finding.vm_id.split()
                    if vm not in existing_finding.vm_id.split()
                ]
                combined_vm_id_urls = existing_finding.vm_id_url.split() + [
                    vm_url
                    for vm_url in finding.vm_id_url.split()
                    if vm_url not in existing_finding.vm_id_url.split()
                ]
                if finding.age >= existing_finding.age:
                    new_finding = copy.deepcopy(finding)
                    new_finding.service = " ".join(combined_services)
                    new_finding.service_url = " ".join(combined_services_url)
                    new_finding.vm_id = " ".join(combined_vm_ids)
                    new_finding.vm_id_url = " ".join(combined_vm_id_urls)
                    findings_map[key] = new_finding
                else:
                    existing_finding.service = " ".join(combined_services)
                    existing_finding.service_url = " ".join(combined_services_url)
                    new_finding.vm_id = " ".join(combined_vm_ids)
                    new_finding.vm_id_url = " ".join(combined_vm_id_urls)
            else:
                findings_map[key] = copy.deepcopy(finding)

        unique_findings = list(findings_map.values())
        return unique_findings

    def filter_tags_days(self, remote_config, findings):
        tag_exclusion_days = remote_config["TAG_EXCLUSION_DAYS"]
        filtered_findings = []
        console = Console()

        for finding in findings:
            exclude = False
            for tag in finding.tags:
                if tag in tag_exclusion_days and finding.age < tag_exclusion_days[tag]:
                    exclude = True
                    console.print(
                        f"[yellow]Report [link={finding.vm_id_url}]{finding.vm_id}[/link] with tag '{tag}' and age {finding.age} days is being excluded. It will be considered in {tag_exclusion_days[tag] - finding.age} days.[/yellow]"
                    )
                    break
            if not exclude:
                filtered_findings.append(finding)

        return filtered_findings

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
