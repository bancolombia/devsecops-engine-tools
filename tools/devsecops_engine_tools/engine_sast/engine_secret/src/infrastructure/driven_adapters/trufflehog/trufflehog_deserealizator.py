import re
from datetime import datetime
from dataclasses import dataclass
from typing import List
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding, Category
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway

@dataclass
class SecretScanDeserealizator(DeseralizatorGateway):

    def get_list_vulnerability(self, results_scan_list: List[dict], os, path_directory) -> List[Finding]:
        list_open_vulnerabilities = []
        for result in results_scan_list:
            where_text, raw = self.get_where_correctly(result, os, path_directory)
            vulnerability_open = Finding(
                id="SECRET_SCANNING",
                cvss=None,
                where=f"{where_text}, Secret: {raw}",
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
    
    def get_where_correctly(self, result: dict, os, path_directory):
        original_where = str(result.get("SourceMetadata").get("Data").get("Filesystem").get("file"))
        initial_raw = str(result.get("Raw"))[:3]
        final_raw = str(result.get("Raw"))[-3:]
        hidden_raw = '*' * 9
        raw = initial_raw + hidden_raw + final_raw
        if re.search(r'Linux', os):
            original_where = original_where.replace("\\", "/")
        
        path_remove = path_directory or ""
        where_text = original_where.replace(path_remove, "")
        return where_text, raw