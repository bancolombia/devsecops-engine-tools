from devsecops_engine_tools.engine_utilities.defect_dojo.applications.defect_dojo import (
    DefectDojo
)
from devsecops_engine_tools.engine_utilities.defect_dojo.domain.request_objects.import_scan import (
    ImportScanRequest
)
from devsecops_engine_tools.engine_utilities.defect_dojo.applications.connect import (
    Connect
)
from devsecops_engine_tools.engine_utilities.sonarqube.domain.model.gateways.vulnerability_management_gateway import (
    VulnerabilityManagementGateway
)
from devsecops_engine_tools.engine_core.src.domain.model.gateway.devops_platform_gateway import (
    DevopsPlatformGateway,
)

class DefectDojoAdapter(VulnerabilityManagementGateway):
    @staticmethod
    def send_report(
        compact_remote_config_url: str,
        source_code_management_uri: str,
        environment: str,
        secret_tool: dict,
        config_tool: any,
        devops_platform_gateway: DevopsPlatformGateway,
        project_key: str
    ):
        
        token_defect_dojo = secret_tool.get(
            "token_defect_dojo", 
            secret_tool.get("token_vulnerability_management")
        )
        token_cmdb = secret_tool["token_cmdb"]

        request: ImportScanRequest = Connect.cmdb(
            cmdb_mapping={
                "product_type_name": "nombreevc",
                "product_name": "nombreapp",
                "tag_product": "nombreentorno",
                "product_description": "arearesponsableti",
                "codigo_app": "CodigoApp",
            },
            compact_remote_config_url=f'{compact_remote_config_url.rstrip("/")}{config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["CMDB_MAPPING_PATH"]}',
            personal_access_token=devops_platform_gateway.get_variable("access_token"),
            token_cmdb=token_cmdb,
            host_cmdb=config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["HOST_CMDB"],
            expression=config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["REGEX_EXPRESSION_CMDB"],
            token_defect_dojo=token_defect_dojo,
            host_defect_dojo=config_tool["VULNERABILITY_MANAGER"]["DEFECT_DOJO"]["HOST_DEFECT_DOJO"],
            scan_type="SonarQube API Import",
            tags="sonarqube",
            engagement_name=project_key,
            version=devops_platform_gateway.get_variable("build_execution_id"),
            build_id=devops_platform_gateway.get_variable("build_id"),
            source_code_management_uri=source_code_management_uri,
            commit_hash=devops_platform_gateway.get_variable("commit_hash"),
            environment=environment,
            branch_tag=devops_platform_gateway.get_variable("branch_name"),
            service=project_key
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
            print("Report sent to Vulnerability Manager:", f"{test_string}?tags=sonarqube")
        else:
            print(response)