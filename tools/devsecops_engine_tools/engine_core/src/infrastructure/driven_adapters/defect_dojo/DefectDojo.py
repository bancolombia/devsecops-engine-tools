from dataclasses import dataclass
from devsecops_engine_tools.engine_core.src.domain.model.gateway.vulnerability_management_gateway import (
    VulnerabilityManagementGateway,
)
from devsecops_engine_utilities.defect_dojo import (
    DefectDojo,
    ImportScanRequest,
    Connect,
    Finding,
)
from devsecops_engine_utilities.utils.session_manager import SessionManager
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    SystemVariables,
    BuildVariables,
    ReleaseVariables,
)
from devsecops_engine_utilities.azuredevops.models.AzureMessageLoggingPipeline import (
    AzureMessageLoggingPipeline,
)


@dataclass
class DefectDojoPlatform(VulnerabilityManagementGateway):
    def send_vulnerability_management(
        self, scan_type, file_path, dict_args, secret_tool, config_tool
    ):
        token_dd = (
            dict_args["token_vulnerability_management"]
            if dict_args["token_vulnerability_management"] is not None
            else secret_tool["token_defect_dojo"]
        )
        token_cmdb = (
            dict_args["token_cmdb"]
            if dict_args["token_cmdb"] is not None
            else secret_tool["token_cmdb"]
        )

        try:
            enviroment_mapping = {
                "dev": "Development",
                "qa": "Staging",
                "pdn": "Production",
            }
            source_code_management_uri = (
                f"{SystemVariables.System_TeamFoundationCollectionUri.value()}"
                f"{BuildVariables.Build_Project_Name.value()}/_git/{BuildVariables.Build_Repository_Name.value()}"
            )
            source_code_management_uri = source_code_management_uri.replace(" ", "%20")
            branch_name = BuildVariables.Build_SourceBranchName.value()
            base_compact_remote_config_url = (
                f"https://{SystemVariables.System_TeamFoundationCollectionUri.value().rstrip('/').split('/')[-1].replace('.visualstudio.com','')}"
                f".visualstudio.com/{SystemVariables.System_TeamProject.value()}/_git/"
                f"{dict_args['remote_config_repo']}?path=/"
            )
            if (
                (str(branch_name) == "trunk")
                or (str(branch_name) == "develop")
                or (str(branch_name) == "master")
            ):
                request: ImportScanRequest = Connect.cmdb(
                    cmdb_mapping={
                        "product_type_name": "nombreevc",
                        "product_name": "nombreapp",
                        "tag_product": "nombreentorno",
                        "product_description": "arearesponsableti",
                        "codigo_app": "CodigoApp",
                    },
                    compact_remote_config_url=f'{base_compact_remote_config_url}{config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["CMDB_MAPPING_PATH"]}',
                    personal_access_token=SystemVariables.System_AccessToken.value(),
                    token_cmdb=token_cmdb,
                    host_cmdb=config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                        "HOST_CMDB"
                    ],
                    expression=config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"][
                        "REGEX_EXPRESSION_CMDB"
                    ],
                    token_defect_dojo=token_dd,
                    host_defect_dojo=config_tool["VULNERABILITY_MANAGER"][
                        "DEFECT_DOJO"
                    ]["HOST_DEFECT_DOJO"],
                    scan_type=scan_type,
                    engagement_name=BuildVariables.Build_DefinitionName.value(),
                    service=BuildVariables.Build_DefinitionName.value(),
                    file=file_path,
                    version=BuildVariables.Build_BuildId.value(),
                    build_id=BuildVariables.Build_BuildNumber.value(),
                    source_code_management_uri=source_code_management_uri,
                    branch_tag=BuildVariables.Build_SourceBranch.value(),
                    commit_hash=BuildVariables.Build_SourceVersion.value(),
                    environment=enviroment_mapping[
                        ReleaseVariables.Environment.value()
                    ],
                    tags="evc",
                )

                response = DefectDojo.send_import_scan(request)
                if hasattr(response, "test_url"):
                    print("Report sent to defect dojo: ", response.test_url)
                else:
                    print(
                        AzureMessageLoggingPipeline.WarningLogging.get_message(
                            "Error sending report to defect dojo with the following error: {0} ".format(
                                response
                            )
                        )
                    )
        except Exception as ex:
            print(
                AzureMessageLoggingPipeline.WarningLogging.get_message(
                    "Error sending report to defect dojo with the following error: {0} ".format(
                        ex
                    )
                )
            )

    def get_findings_risk_acceptance(
        self, service, dict_args, secret_tool, config_tool
    ):
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
