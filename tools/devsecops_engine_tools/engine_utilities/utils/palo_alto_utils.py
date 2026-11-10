import json
from datetime import datetime

from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding, Category


SEVERITY_MAP = {
    "unimportant": "low",
    "unassigned": "low",
    "negligible": "low",
    "not yet assigned": "low",
    "low": "low",
    "medium": "medium",
    "moderate": "medium",
    "high": "high",
    "important": "high",
    "critical": "critical",
}


def extract_fixed_version(status):
    prefix = "fixed in "
    if isinstance(status, str) and status.lower().startswith(prefix):
        return status[len(prefix):].strip()
    return "unknown"


def get_palo_alto_findings(image_scanned, module, tool):
    with open(image_scanned, "rb") as file:
        data = json.load(file)
    return get_palo_alto_findings_from_data(data, module, tool)


def get_palo_alto_findings_from_data(data, module, tool):
    if data.get("consoleURL"):
        print(f"Console URL: {data['consoleURL']}")
    findings = []
    for result in data.get("results", []):
        for vulnerability in result.get("vulnerabilities", []):
            discovered = vulnerability.get("discoveredDate")
            findings.append(Finding(
                id=vulnerability.get("id", ""),
                cvss=float(vulnerability.get("cvss") or 0.0),
                where=f"{vulnerability.get('packageName', '')}:{vulnerability.get('packageVersion', '')}",
                description=vulnerability.get("description", "")[:150],
                severity=SEVERITY_MAP.get(vulnerability.get("severity", "").lower(), ""),
                identification_date=datetime.fromisoformat(discovered.replace("Z", "+00:00")) if discovered else None,
                published_date_cve=vulnerability.get("publishedDate", "").replace("Z", "+00:00"),
                module=module,
                category=Category.VULNERABILITY,
                requirements=vulnerability.get("status", ""),
                tool=tool,
            ))
    return findings


def get_palo_alto_context(path_file_results, tool):
    with open(path_file_results, "rb") as file:
        data = json.load(file)
    return get_palo_alto_context_from_data(data, tool)


def get_palo_alto_context_from_data(data, tool):
    from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.context_container import ContextContainer

    contexts = []
    for result in data.get("results", []):
        for vulnerability in result.get("vulnerabilities", []):
            status = vulnerability.get("status", "unknown")
            link = vulnerability.get("link")
            contexts.append(ContextContainer(
                cve_id=vulnerability.get("id", "unknown"),
                cwe_id=vulnerability.get("cwe", "unknown"),
                vendor_id=vulnerability.get("vendorId", "unknown"),
                severity=SEVERITY_MAP.get(vulnerability.get("severity", "").lower(), vulnerability.get("severity", "unknown")),
                vulnerability_status=status,
                target_image=result.get("name") or result.get("id", "unknown"),
                package_name=vulnerability.get("packageName", "unknown"),
                installed_version=vulnerability.get("packageVersion", "unknown"),
                fixed_version=extract_fixed_version(status),
                cvss_score=vulnerability.get("cvss"),
                cvss_vector=vulnerability.get("vector", "unknown"),
                description=vulnerability.get("description", "unknown").replace("\n", ""),
                os_type=result.get("distro", "unknown"),
                layer_digest=result.get("id", "unknown"),
                published_date=vulnerability.get("publishedDate"),
                last_modified_date=vulnerability.get("discoveredDate", "unknown"),
                references=[link] if link else "unknown",
                source_tool=tool,
            ))
    return contexts