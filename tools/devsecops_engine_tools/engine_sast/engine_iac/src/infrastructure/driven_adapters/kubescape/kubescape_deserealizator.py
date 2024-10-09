from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
from datetime import datetime
from dataclasses import dataclass


@dataclass
class KubescapeDeserealizator:
    def get_list_finding(self, results_scan_list: list) -> "list[Finding]":
        list_open_findings = []

        for result in results_scan_list:
            finding_open = Finding(
                id=result.get("id"),
                cvss=None,
                where=result.get("where"),
                description=result.get("description"),
                severity=result.get("severity").lower(),
                identification_date=datetime.now().strftime("%d%m%Y"),
                published_date_cve=None,
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="kubescape"
            )
            list_open_findings.append(finding_open)

        return list_open_findings

    def extract_failed_controls(self, data):
        result_extracted_data = []
        results = data.get("results", [])
        resources = {resource.get("resourceID"): resource for resource in data.get("resources", [])}
        frameworks = data.get("summaryDetails", {}).get("frameworks", [])

        for result in results:
            resource_id = result.get("resourceID")
            controls = result.get("controls", [])

            for control in controls:
                if control.get("status", {}).get("status") == "failed":
                    control_id = control.get("controlID")
                    name = control.get("name")
                    resource = resources.get(resource_id)

                    if resource:
                        relative_path = resource.get("source", {}).get("relativePath", "").replace("\\", "/")
                        severity_score = self.get_severity_score(frameworks, control_id)

                        result_extracted_data.append({
                            "id": control_id,
                            "description": name,
                            "where": relative_path,
                            "severity": severity_score
                        })

        return result_extracted_data

    def get_severity_score(self, frameworks, control_id):
        classifications = {
            (0.0, 0.0): "none",
            (0.1, 3.9): "low",
            (4.0, 6.9): "medium",
            (7.0, 8.9): "high",
            (9.0, 10.0): "critical"
        }
        for framework in frameworks:
            control_object = framework.get("controls", {}).get(control_id, {})
            if control_object:
                for range_tuple, classification in classifications.items():
                    if range_tuple[0] <= control_object.get("scoreFactor", 0.0) <= range_tuple[1]:
                        return classification
        return None
