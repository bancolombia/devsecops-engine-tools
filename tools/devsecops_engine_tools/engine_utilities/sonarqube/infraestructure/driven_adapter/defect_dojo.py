from engine_utilities.defect_dojo.applications.defect_dojo import(
    DefectDojo,
    ImportScanRequest
)
from engine_utilities.defect_dojo.applications.connect import (
    Connect
)
from engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    SystemVariables,
    BuildVariables
)
from engine_core.src.domain.model.gateway.vulnerability_management_gateway import(
    VulnerabilityManagementGateway
)

class DefectDojoAdapter(VulnerabilityManagementGateway):
    @staticmethod
    def send_report(
        compact_remote_config_url: str,
        source_code_management_uri: str,
        environment: str,
        token_defect_dojo: str,
        token_cmdb: str,
        config_tool: any
    ):
        request: ImportScanRequest = Connect.cmdb(
            cmdb_mapping={
                "product_type_name": "nombreevc",
                "product_name": "nombreapp",
                "tag_product": "nombreentorno",
                "product_description": "arearesponsableti",
                "codigo_app": "CodigoApp",
            },
            compact_remote_config_url=compact_remote_config_url,
            personal_access_token=SystemVariables.System_AccessToken.value(),
            token_cmdb=token_cmdb,
            host_cmdb=config_tool['VULNERABILITY_MANAGER']['DEFECT_DOJO']['HOST_CMDB'],
            expression=config_tool['VULNERABILITY_MANAGER']['DEFECT_DOJO']['REGEX_EXPRESSION_CMDB'],
            token_defect_dojo=token_defect_dojo,
            host_defect_dojo=config_tool['VULNERABILITY_MANAGER']['DEFECT_DOJO']['HOST_DEFECT_DOJO'],
            scan_type="SonarQube API Import",
            source_code_management_uri=source_code_management_uri,
            tags="evc",
            build_id=BuildVariables.Build_BuildId.value(),
            engagement_name=BuildVariables.Build_DefinitionName.value(),
            environment=environment,
            service=BuildVariables.Build_DefinitionName.value()
        )
        response = DefectDojo.send_import_scan(request)
        if hasattr(response, "url"):
            url_test = response.url.split("/")
            test_string = ""
            for i, elem in enumerate(url_test):
                if i == 0:
                    test_string = test_string + elem + "//"
                elif i == 6:
                    test_string = test_string + elem
                else:
                    test_string = test_string + elem + "/"
            print("Report sent to Vultracker: ",test_string)
        else:
            print(response)