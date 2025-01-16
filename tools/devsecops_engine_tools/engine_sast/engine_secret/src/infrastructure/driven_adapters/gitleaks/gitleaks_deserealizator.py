from datetime import datetime
from dataclasses import dataclass
from typing import List
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding, Category
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import (
    DeseralizatorGateway
)

@dataclass
class GitleaksDeserealizator(DeseralizatorGateway):

    def get_list_vulnerability(self, results_scan_list: List[dict], path_directory: str, os: str) -> List[Finding]:
        list_open_vulnerabilities = []
        current_date=datetime.now().strftime("%d%m%Y")

        for result in results_scan_list:            
            vulnerability_open = Finding(
                id=result.get("RuleID", "SECRET_SCANNING"),
                cvss=None,
                where=self.get_where_correctly(result, path_directory),
                description=result.get("Description", "No description available"),
                severity="critical",
                identification_date=current_date,
                published_date_cve=None,
                module="engine_secret",
                category=Category.VULNERABILITY,
                requirements="",
                tool="Gitleaks",
            )
            list_open_vulnerabilities.append(vulnerability_open)
        return list_open_vulnerabilities
    
    def get_where_correctly(self, result: dict, path_directory=""):
        path = result.get("File", "").replace(path_directory, "")
        hidden_secret = str(result.get("Secret"))[:3] + '*' * 9 + str(result.get("Secret"))[-3:]
        return f"{path}, Secret: {hidden_secret}"