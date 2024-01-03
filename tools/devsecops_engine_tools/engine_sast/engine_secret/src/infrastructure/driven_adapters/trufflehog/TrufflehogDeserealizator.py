from devsecops_engine_tools.engine_sast.engine_secret.src.domain.model.gateway.gateway_deserealizator import DeseralizatorGateway
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability import Vulnerability
from datetime import datetime
from dataclasses import dataclass


@dataclass
class TrufflehogDeserealizator(DeseralizatorGateway):

    def get_list_vulnerability(self, results_scan_list: list) -> "list[Vulnerability]":
        list_open_vulnerbailities = []
        # TODO OCVELEZ: Mirar si es posible hacer uso de la librería https://pypi.org/project/attrdict/ para mejorar
        # la forma de mapear de json a objetos

        for result in results_scan_list:
            vulnerability_open = Vulnerability(
                        id=result.get("SourceID"),
                        cvss=None,
                        where_vulnerability=result.get("SourceMetadata").get("Data").get("Filesystem").get("file"),
                        description="Secret Scan Desc",
                        severity="critical",
                        identification_date=datetime.now().strftime("%d%m%Y"),
                        type_vulnerability="Sast-secrets manager",
                        requirements=result.get("DetectorName"),
                        tool="Trufflehog",
                        is_excluded=False,
                    )
            list_open_vulnerbailities.append(vulnerability_open)
                

        return list_open_vulnerbailities
