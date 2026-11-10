import json

from devsecops_engine_tools.engine_sca.engine_container.src.domain.model.context_container import (
    ContextContainer,
)
from devsecops_engine_tools.engine_utilities.utils.palo_alto_utils import (
    get_palo_alto_context_from_data,
    get_palo_alto_findings_from_data,
)


def _normalize_vulnerability(vulnerability):
    fix_versions = vulnerability.get("fixVersions") or vulnerability.get("fixedVersions") or []
    if isinstance(fix_versions, str):
        fix_versions = [fix_versions]
    fixed_version = ", ".join(str(version) for version in fix_versions) or "unknown"
    status = vulnerability.get("status") or vulnerability.get("vulnerabilityStatus")
    if not status and fixed_version != "unknown":
        status = f"fixed in {fixed_version}"

    return {
        "id": vulnerability.get("cveId") or vulnerability.get("vulnerabilityId") or vulnerability.get("id", "unknown"),
        "cwe": vulnerability.get("cweId") or vulnerability.get("cwe", "unknown"),
        "vendorId": vulnerability.get("vendorId", "unknown"),
        "severity": vulnerability.get("severity", "unknown"),
        "status": status or "unknown",
        "link": vulnerability.get("link") or vulnerability.get("url"),
        "cvss": vulnerability.get("cvss") or vulnerability.get("cvssScore"),
        "vector": vulnerability.get("vector") or vulnerability.get("cvssVector", "unknown"),
        "description": vulnerability.get("description", "unknown"),
        "packageName": vulnerability.get("packageName") or vulnerability.get("package", "unknown"),
        "packageVersion": vulnerability.get("packageVersion") or vulnerability.get("installedVersion", "unknown"),
        "publishedDate": vulnerability.get("publishedDate") or "",
        "discoveredDate": vulnerability.get("discoveredDate") or vulnerability.get("lastModifiedDate"),
    }


def _is_vulnerability(value):
    has_identifier = any(key in value for key in ("cveId", "vulnerabilityId", "id"))
    has_package = any(key in value for key in ("packageName", "package", "packageVersion"))
    return has_identifier and has_package


def _find_vulnerabilities(value, found):
    if isinstance(value, dict):
        if _is_vulnerability(value):
            found.append(value)
            return
        for nested in value.values():
            _find_vulnerabilities(nested, found)
    elif isinstance(value, list):
        for nested in value:
            _find_vulnerabilities(nested, found)


def _normalize_cortex_output(path_file_results):
    with open(path_file_results, "r", encoding="utf-8") as result_file:
        data = json.load(result_file)
    if not isinstance(data, dict) or not any(
        key in data for key in ("scannersResults", "results", "vulnerabilities", "findings")
    ):
        raise ValueError("Unsupported Cortex Cloud scan result format")

    vulnerabilities = []
    _find_vulnerabilities(data, vulnerabilities)
    target_image = data.get("imageName") or data.get("image") or data.get("target", "unknown")
    distro = data.get("distro") or data.get("os", "unknown")
    return {
        "results": [
            {
                "name": target_image,
                "distro": distro,
                "vulnerabilities": [_normalize_vulnerability(item) for item in vulnerabilities],
            }
        ]
    }


class CortexDeserealizator:
    def get_list_findings(self, image_scanned, module="engine_container"):
        data = _normalize_cortex_output(image_scanned)
        return get_palo_alto_findings_from_data(data, module, "CortexCloud")

    def get_container_context_from_results(self, path_file_results: str) -> list[ContextContainer]:
        data = _normalize_cortex_output(path_file_results)
        return get_palo_alto_context_from_data(data, "CortexCloud")