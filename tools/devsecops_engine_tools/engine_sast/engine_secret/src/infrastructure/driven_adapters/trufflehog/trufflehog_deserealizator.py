import os
import re
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding, Category
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway
)

@dataclass
class SecretScanDeserealizator(DeseralizatorGateway):

    def get_list_vulnerability(self, results_scan_list: List[dict], devops_gateway: DevopsPlatformGateway) -> List[Finding]:
        list_open_vulnerabilities = []
        for result in results_scan_list:
            where_text, line = self.get_where_correctly(result, devops_gateway)
            vulnerability_open = Finding(
                id="SECRET_SCANNING",
                cvss=None,
                where=f"{where_text}, Line: {line}",
                description="Sensitive information in source code",
                severity="critical",
                identification_date=datetime.now().strftime("%d%m%Y"),
                published_date_cve=None,
                module="engine_secret",
                category=Category.VULNERABILITY,
                requirements=result.get("DetectorName"),
                tool="Trufflehog",
            )
            list_open_vulnerabilities.append(vulnerability_open)
        return list_open_vulnerabilities
    
    def get_where_correctly(self, result: dict, devops_gateway: DevopsPlatformGateway):
        line = str(result.get("SourceMetadata").get("Data").get("Filesystem").get("line") or "Multiline")
        original_where = str(result.get("SourceMetadata").get("Data").get("Filesystem").get("file"))
        operative_system = os.environ.get('AGENT_OS')
        if re.search(r'Linux', operative_system):
            original_where = original_where.replace("\\", "/")
        
        directory = devops_gateway.get_variable("WORK_FOLDER")
        path_remove = directory or ""
        where_text = original_where.replace(path_remove, "")
        return where_text, line
