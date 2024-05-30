from typing import (
    List
)
from datetime import (
    datetime,
)
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
import jwt
from devsecops_engine_tools.engine_dast.src.domain.model.gateways.tool_gateway import (
    ToolGateway,
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

        check_id = "ENGINE_JWT_001"
        is_vulnerable = False
        alg = jwt.get_unverified_header(token)["alg"]

        if alg in self.BAD_JWT_ALG:
            is_vulnerable = True

        return {
            "check-id": check_id,
            "cvss": "",
            "matched-at": "",
            "description": "msg",
            "severity": "",
            "remediation": ""
            }

    def verify_jws_alg(self, token):
        """Evaluate JSON Web signature's algorithm"""

        check_id = "ENGINE_JWT_002"
        is_vulnerable = False
        alg = jwt.get_unverified_header(token)["alg"]

        if alg in self.BAD_JWS_ALG:
            is_vulnerable = True

        return {
            "check-id": check_id,
            "cvss": "",
            "matched-at": "",
            "description": "msg",
            "severity": "",
            "remediation": ""
            }

    def verify_jwe(self, token):
        """Evaluate JSON Web encryption's algorithm"""

        check_id = "ENGINE_JWT_003"
        msg = ""
        is_vulnerable = True
        enc = jwt.get_unverified_header(token)["enc"]
        alg = jwt.get_unverified_header(token)["alg"]

        if enc in self.GOOD_JWE_ENC:
            if alg in self.GOOD_JWE_ALG:
                is_vulnerable = False
                msg = "Algoritmo: " + alg + " | Cifrado: " + enc
            else:
                msg = "Algoritmo: " + alg
        else:
            msg = "Cifrado: " + enc

        return {
            "check-id": check_id,
            "cvss": "",
            "matched-at": "",
            "description": msg,
            "severity": "",
            "remediation": ""
            }
   
    def check_token(self, token):
        "Verify if token is JWT, JWS or JWE"

        hed = jwt.get_unverified_header()

        if "enc" in hed.keys():
            result = self.verify_jwe(token)
        elif "typ" in hed.keys():
            result = self.verify_jwt_alg(token)
        else:
            result = self.verify_jws_alg(token)

        return result

    def configure_tool(self, target_data):
        """Method for create all tokens"""
        jwt_list = []
        for operation in target_data.operations:
            if operation.authentication_gateway["type"].lower() == "jwt":
                jwt_list.append(operation)
        return jwt_list

    def execute(self, jwt_config):
        result_scans = []
        if len(jwt_config) > 0:
            for jwt_operation in jwt_config:
                token = jwt_operation.authenticate()
                result = self.check_token(token)
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
                    description=scan["info"].get("description"),
                    severity=scan["info"].get("severity").lower(),
                    identification_date=datetime.now().strftime("%d%m%Y"),
                    module="engine_dast",
                    category=Category("vulnerability"),
                    requirements=scan["info"].get("remediation"),
                    tool="Jwt",
                )
                list_open_findings.append(finding_open)
        return list_open_findings

    def run_tool(self, target_data, config_tool):
        jwt_config = self.configure_tool(target_data)
        result_scans = self.execute(jwt_config)
        finding_list = self.deserialize_results(result_scans)
        path_file_results = generate_file_from_tool(
            self.TOOL, result_scans, config_tool
        )
        return finding_list, path_file_results


