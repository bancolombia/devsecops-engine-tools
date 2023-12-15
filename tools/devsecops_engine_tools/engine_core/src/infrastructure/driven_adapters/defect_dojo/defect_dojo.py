from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway,
)
from devsecops_engine_tools.engine_core.src.domain.model.vulnerability_management import (
    VulnerabilityManagement,
)
from devsecops_engine_utilities.defect_dojo import (
    DefectDojo,
    ImportScanRequest,
    Connect,
    Finding,
)
from devsecops_engine_utilities.utils.session_manager import SessionManager


@dataclass
class DefectDojoPlatform(VulnerabilityManagementGateway):
    def send_vulnerability_management(
        self, vulnerability_management: VulnerabilityManagement
    ):
        try:
            token_dd = (
                vulnerability_management.dict_args["token_vulnerability_management"]
                if vulnerability_management.dict_args["token_vulnerability_management"]
                is not None
                else vulnerability_management.secret_tool["token_defect_dojo"]
            )
            token_cmdb = (
                vulnerability_management.dict_args["token_cmdb"]
                if vulnerability_management.dict_args["token_cmdb"] is not None
                else vulnerability_management.secret_tool["token_cmdb"]
            )

            enviroment_mapping = {
                "dev": "Development",
                "qa": "Staging",
                "pdn": "Production",
            }
            scan_type_mapping = {
                "CHECKOV": "Checkov Scan",
            }

            if str(vulnerability_management.branch_name) in [
                "trunk",
                "develop",
                "master",
            ]:
                request: ImportScanRequest = Connect.cmdb(
                    cmdb_mapping={
                        "product_type_name": "nombreevc",
                        "product_name": "nombreapp",
                        "tag_product": "nombreentorno",
                        "product_description": "arearesponsableti",
                        "codigo_app": "CodigoApp",
                    },
                    compact_remote_config_url=f'{vulnerability_management.base_compact_remote_config_url}{vulnerability_management.config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["CMDB_MAPPING_PATH"]}',
                    personal_access_token=vulnerability_management.access_token,
                    token_cmdb=token_cmdb,
                    host_cmdb=vulnerability_management.config_tool[
                        "VULNERABILITY_MANAGER"
                    ]["DEFECT_DOJO"]["HOST_CMDB"],
                    expression=vulnerability_management.config_tool[
                        "VULNERABILITY_MANAGER"
                    ]["DEFECT_DOJO"]["REGEX_EXPRESSION_CMDB"],
                    token_defect_dojo=token_dd,
                    host_defect_dojo=vulnerability_management.config_tool[
                        "VULNERABILITY_MANAGER"
                    ]["DEFECT_DOJO"]["HOST_DEFECT_DOJO"],
                    scan_type=scan_type_mapping[vulnerability_management.scan_type],
                    engagement_name=vulnerability_management.input_core.scope_pipeline,
                    service=vulnerability_management.input_core.scope_pipeline,
                    file=vulnerability_management.input_core.path_file_results,
                    version=vulnerability_management.version,
                    build_id=vulnerability_management.build_id,
                    source_code_management_uri=vulnerability_management.source_code_management_uri,
                    branch_tag=vulnerability_management.branch_tag,
                    commit_hash=vulnerability_management.commit_hash,
                    environment=enviroment_mapping[
                        vulnerability_management.environment
                    ],
                    tags="evc",
                )

                response = DefectDojo.send_import_scan(request)
                if hasattr(response, "test_url"):
                    print(
                        "Report sent to vulnerability management: ", response.test_url
                    )
                else:
                    raise Exception(response)
        except Exception as ex:
            raise Exception(
                "Error sending report to vulnerability management with the following error: {0} ".format(
                    ex
                )
            )

    def get_findings_risk_acceptance(
        self, service, dict_args, secret_tool, config_tool
    ):
        try:
            token_dd = (
                dict_args["token_vulnerability_management"]
                if dict_args["token_vulnerability_management"] is not None
                else secret_tool["token_defect_dojo"]
            )

            session_manager = SessionManager(
                token_dd,
                config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["HOST_DEFECT_DOJO"],
            )

            findings_list = Finding.get_finding(
                session=session_manager, service=service, risk_accepted=True
            ).results
            return [
                {
                    "Id": finding.vuln_id_from_tool,
                    "Where": finding.file_path,
                    "Create_Date": finding.accepted_risks[-1]["created"],
                    "Expired_Date": finding.accepted_risks[-1]["expiration_date"],
                }
                for finding in findings_list
            ]
        except Exception as ex:
            raise Exception(
                "Error getting risk acceptance findings with the following error: {0} ".format(
                    ex
                )
            )
