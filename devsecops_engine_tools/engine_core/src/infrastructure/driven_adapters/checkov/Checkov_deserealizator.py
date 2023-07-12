from engine_core.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from engine_core.src.domain.model.Vulnerability import Vulnerability
from datetime import datetime


class CheckovDeserealizator(DeseralizatorGateway):
    @staticmethod
    def get_list_vulnerability(results_list) -> list[Vulnerability]:
        list_open_vulnerbailities = []
        #TODO OCVELEZ: Mirar si es posible hacer uso de la librería https://pypi.org/project/attrdict/ para mejorar
        # la forma de mapear de json a objetos
        for scan in results_list:
            vulnerability_open = Vulnerability( 
                    id = scan.check_id,
                    cvss = None,
                    where_vulnerability = scan.repo_file_path,
                    description = scan.check_name,
                    severity = scan.severity,
                    identification_date = datetime.now().strftime('%d%m%Y'),
                    type_vulnerability = "IaaC",
                    requirements = scan.guideline,
                    tool = "Checkov",
                    is_excluded = False
                )
            list_open_vulnerbailities.append(vulnerability_open)
            
        print(list_open_vulnerbailities)
        return list_open_vulnerbailities
