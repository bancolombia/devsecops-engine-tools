from tools.devsecops_engine_tools.engine_core.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from tools.devsecops_engine_tools.engine_core.src.domain.model.Vulnerability import Vulnerability
from datetime import datetime
from dataclasses import dataclass


@dataclass
class CheckovDeserealizator(DeseralizatorGateway):
    results_scan_list: list

    def get_list_vulnerability(self) -> 'list[Vulnerability]':
        list_open_vulnerbailities = []
        #TODO OCVELEZ: Mirar si es posible hacer uso de la librería https://pypi.org/project/attrdict/ para mejorar
        # la forma de mapear de json a objetos

        for result in self.results_scan_list:
            if "failed_checks" in str(result):
                for scan in result["results"]["failed_checks"]:
                    vulnerability_open = Vulnerability( 
                            id = scan.get("check_id"),
                            cvss = None,
                            where_vulnerability = scan.get("repo_file_path"),
                            description = scan.get("check_name"),
                            severity = scan.get("severity"),
                            identification_date = datetime.now().strftime('%d%m%Y'),
                            type_vulnerability = "IaaC",
                            requirements = scan.get("guideline"),
                            tool = "Checkov",
                            is_excluded = False
                        )
                    list_open_vulnerbailities.append(vulnerability_open)
                
        return list_open_vulnerbailities
