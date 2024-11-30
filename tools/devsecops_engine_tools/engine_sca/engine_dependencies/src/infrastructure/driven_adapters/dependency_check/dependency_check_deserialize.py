from devsecops_engine_tools.engine_sca.engine_dependencies.src.domain.model.gateways.deserializator_gateway import (
    DeserializatorGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Finding,
    Category,
)
from dataclasses import dataclass
from datetime import datetime
import xml.etree.ElementTree as ET
from devsecops_engine_tools.engine_utilities.utils.logger_info import MyLogger
from devsecops_engine_tools.engine_utilities import settings

logger = MyLogger.__call__(**settings.SETTING_LOGGER).get_logger()


@dataclass
class DependencyCheckDeserialize(DeserializatorGateway):
    TOOL = "DEPENDENCY_CHECK"

    def get_list_findings(self, dependencies_scanned_file, remote_config) -> "list[Finding]":
        dependencies, namespace = self.filter_vulnerabilities_by_confidence(dependencies_scanned_file, remote_config)

        list_open_vulnerabilities = []

        for dependency in dependencies:
            vulnerabilities_node = dependency.find('ns:vulnerabilities', namespace)
            if vulnerabilities_node:
                vulnerabilities = vulnerabilities_node.findall('ns:vulnerability', namespace)
                for vulnerability in vulnerabilities:
                    fix = "Not found"
                    vulnerable_software = vulnerability.find('ns:vulnerableSoftware', namespace)
                    if vulnerable_software:
                        software = vulnerable_software.findall('ns:software', namespace)
                        if len(software) > 0:
                            fix = software[0].get("versionEndExcluding", "Not found").lower()
                    
                    id = vulnerability.find('ns:name', namespace).text[:20]
                    cvss = ", ".join(f"{child.tag.split('}')[-1]}: {child.text}" for child in vulnerability.find('ns:cvssV3', namespace)) if vulnerability.find('ns:cvssV3', namespace) else ""
                    fileName = dependency.find('ns:fileName', namespace).text.split(":")[-1].strip()
                    description = vulnerability.find('ns:description', namespace).text if vulnerability.find('ns:description', namespace).text else ""
                    severity = vulnerability.find('ns:severity', namespace).text.lower()
                    cvss
                    finding_open = Finding(
                        id=id,
                        cvss=cvss,
                        where=fileName,
                        description=description[:120].replace("\n\n", " ").replace("\n", " ").strip() if len(description) > 0 else "No description available",
                        severity=severity,
                        identification_date=datetime.now().strftime("%d%m%Y"),
                        published_date_cve=None,
                        module="engine_dependencies",
                        category=Category.VULNERABILITY,
                        requirements=fix,
                        tool="DEPENDENCY_CHECK",
                    )
                    list_open_vulnerabilities.append(finding_open)

        return list_open_vulnerabilities

    def filter_vulnerabilities_by_confidence(self, dependencies_scanned_file, remote_config):
        data_result = ET.parse(dependencies_scanned_file)
        root = data_result.getroot()

        namespace_uri = root.tag.split('}')[0].strip('{')
        namespace = {'ns': namespace_uri}
        ET.register_namespace('', namespace_uri)

        confidence_levels = ["low", "medium", "high", "highest"]
        confidences = remote_config[self.TOOL]["VULNERABILITY_CONFIDENCE"]

        dependencies = root.find('ns:dependencies', namespace)
        if dependencies:
            to_remove = []
            for dep in dependencies.findall('ns:dependency', namespace):
                identifiers = dep.find('ns:identifiers', namespace)
                if identifiers:
                    vulnerability_ids = identifiers.findall('ns:vulnerabilityIds', namespace)
                    if vulnerability_ids:
                        vul_ids_confidences = [conf.get("confidence", "").lower() for conf in vulnerability_ids]
                        if len(vul_ids_confidences) > 0:
                            if not max(vul_ids_confidences, key=lambda c: confidence_levels.index(c)) in confidences: 
                                to_remove.append(dep)
                    elif not "no_confidence" in confidences:
                        to_remove.append(dep)
            for dep in to_remove: dependencies.remove(dep)
            data_result.write(dependencies_scanned_file, encoding="utf-8", xml_declaration=True)
        
        return dependencies, namespace