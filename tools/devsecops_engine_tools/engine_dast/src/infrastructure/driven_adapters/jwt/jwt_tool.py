from typing import (
    List
)
from datetime import (
    datetime,
)
import jwt
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
)
from devsecops_engine_tools.engine_dast.src.domain.model.api_operation import (
    ApiOperation
)
from devsecops_engine_tools.engine_dast.src.infrastructure.helpers.file_generator_tool import (
    generate_file_from_tool,
)

class JwtTool(ToolGateway):

    def __init__(self, target_config):
        self.TOOL = "JWT"
        self.BAD_JWT_ALG = ["none", "ES256", "ES384", "ES512"]
        self.BAD_JWS_ALG = ["none", "ES256", "ES384", "ES512"]
        self.GOOD_JWE_ALG = ["dir", "RSA-OAEP", "RSA-OAEP-256"]
        self.GOOD_JWE_ENC = ["A256GCM"]
        self.target_config = target_config

    def verify_jwt_alg(self, token):
        "Evaluate JSON Web token's algorithm"

        map_id = "JWT_ALGORITHM"
        alg = jwt.get_unverified_header(token)["alg"]

        if alg in self.BAD_JWT_ALG: #Is vulnerable
            return {
                "map_id": map_id,
                "description": "msg"
                }

    def verify_jws_alg(self, token):
        """Evaluate JSON Web signature's algorithm"""

        map_id = "JWS_ALGORITHM"
        alg = jwt.get_unverified_header(token)["alg"]

        if alg in self.BAD_JWS_ALG:#Is vulnerable
            return {
                "map_id": map_id,
                "description": "msg"
                }

    def verify_jwe(self, token):
        """Evaluate JSON Web encryption's algorithm"""

        map_id = "JWE_ALGORITHM"
        msg = ""
        enc = jwt.get_unverified_header(token)["enc"]
        alg = jwt.get_unverified_header(token)["alg"]

        if enc in self.GOOD_JWE_ENC:
            if alg in self.GOOD_JWE_ALG:# Is not vulnerable
                return
            else:
                msg = "Algorithm: " + alg
        else:
            msg = "Encryption: " + enc

        return {
            "map_id": map_id,
            "description": msg
            }

    def check_token(self, token, jwt_details, config_tool):
        "Validates JWT, JWS or JWE"

        hed = jwt.get_unverified_header(token)

        if "enc" in hed.keys():
            result = self.verify_jwe(token)
        elif "typ" in hed.keys():
            result = self.verify_jwt_alg(token)
        else:
            result = self.verify_jws_alg(token)

        if result:
            mapped_result = {
                "check_id": config_tool["RULES"][result["map_id"]]["checkID"],
                "cvss": config_tool["RULES"][result["map_id"]]["cvss"],
                "matched-at": jwt_details["path"],
                "description": result["msg"],
                "severity": config_tool["RULES"][result["map_id"]]["severity"],
                "remediation": result["remediation"]
            }
            return mapped_result
        return None
    
    def configure_tool(self, target_data):
        """Method for group all operations that uses JWT"""
        jwt_list: List[ApiOperation] = []
        for operation in target_data.operations:
            if operation.authentication_gateway.type.lower() == "jwt":
                jwt_list.append(operation)
        return jwt_list

    def execute(self, jwt_config: List[ApiOperation], config_tool):
        result_scans = []
        if len(jwt_config) > 0:
            for jwt_operation in jwt_config:
                jwt_operation.authenticate()
                result = self.check_token(token=jwt_operation.credentials[1],
                                        jwt_details=jwt_operation.data["operation"],
                                        config_tool=config_tool)
                if result:
                    result_scans.append(result)
        return result_scans

    def get_list_finding(
        self,
        result_scan_list: "List[dict]"
    ) -> "List[Finding]":
        list_open_findings = []
        if len(result_scan_list) > 0:
            for scan in result_scan_list:
                finding_open = Finding(
                    id=scan.get("check-id"),
                    cvss=scan.get("cvss"),
                    where=scan.get("matched-at"),
                    description=scan.get("description"),
                    severity=scan.get("severity").lower(),
                    identification_date=datetime.now().strftime("%d%m%Y"),
                    module="engine_dast",
                    category=Category("vulnerability"),
                    requirements=scan.get("remediation"),
                    tool="jwt",
                    published_date_cve=scan.get("published-cve")
                )
                list_open_findings.append(finding_open)
        return list_open_findings

    def run_tool(self, target_data, config_tool):
        jwt_config = self.configure_tool(target_data)
        result_scans = self.execute(jwt_config, config_tool)
        if result_scans:
            finding_list = self.get_list_finding(result_scans)
            path_file_results = generate_file_from_tool(
                self.TOOL, result_scans, config_tool
            )
            return finding_list, path_file_results
        return []