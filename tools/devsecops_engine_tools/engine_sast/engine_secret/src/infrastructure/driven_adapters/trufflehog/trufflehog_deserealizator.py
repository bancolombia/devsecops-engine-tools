import os
import re
from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import (
    DeseralizatorGateway
    )
from devsecops_engine_tools.engine_core.src.domain.model.finding import Finding, Category
from datetime import datetime
from dataclasses import dataclass


@dataclass
class SecretScanDeserealizator(DeseralizatorGateway):

    def get_list_vulnerability(self, results_scan_list: list) -> "list[Finding]":
        list_open_vulnerbailities = []
        for result in results_scan_list:
            where_text, line = self.get_where_correctly(result)
            vulnerability_open = Finding(
                        id="SECRET_SCANNING",
                        cvss=None,
                        where= where_text + ", Line: " + line,
                        description= "Sensitive information in source code",
                        severity="critical",
                        identification_date=datetime.now().strftime("%d%m%Y"),
                        module="Sast-secrets manager",
                        category=Category.VULNERABILITY,
                        requirements=result.get("DetectorName"),
                        tool="Trufflehog",
                    )
            list_open_vulnerbailities.append(vulnerability_open)
        return list_open_vulnerbailities
    
    def get_where_correctly(self, result: any):
        line = str(result.get("SourceMetadata").get("Data").get("Filesystem").get("line"))
        original_where = str(result.get("SourceMetadata").get("Data").get("Filesystem").get("file"))
        operative_system = os.environ.get('AGENT_OS')
        reg_exp_os = r'Linux'
        check_os = re.search(reg_exp_os, operative_system)
        if check_os:
            original_where = original_where.replace("\\", "/")
        path_remove = os.environ.get('SYSTEM_DEFAULTWORKINGDIRECTORY')
        where_text = original_where.replace(path_remove, "")

        if str(result.get("SourceMetadata").get("Data").get("Filesystem").get("line")) == "None":
            line = "Multiline"
        return where_text, line
