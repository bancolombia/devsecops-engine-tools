from devsecops_engine_utilities.defect_dojo import (
    DefectDojo,
    ImportScanRequest,
    Connect,
)
from devsecops_engine_utilities.azuredevops.models.AzurePredefinedVariables import (
    SystemVariables,
    BuildVariables,
    ReleaseVariables,
)
from devsecops_engine_utilities.azuredevops.infrastructure.azure_devops_api import (
    AzureDevopsApi,
)
from devsecops_engine_tools.engine_core.src.infrastructure.helpers.file_generator_tool import (
    generate_file_from_tool,
)


def send_defect_dojo(scan_type, result_list, dict_args):
    file_path = generate_file_from_tool(scan_type, result_list)
    try:
        enviroment_mapping = {
            "dev": "Development",
            "qa": "Staging",
            "pdn": "Production",
        }
        source_code_management_uri = f"{SystemVariables.System_TeamFoundationCollectionUri.value()}{BuildVariables.Build_Project_Name.value()}/_git/{BuildVariables.Build_Repository_Name.value()}"
        source_code_management_uri = source_code_management_uri.replace(" ", "%20")
        branch_name = BuildVariables.Build_SourceBranchName.value()
        base_compact_remote_config_url = f'https://{SystemVariables.System_TeamFoundationCollectionUri.value().rstrip("/").split("/")[-1]}.visualstudio.com/{SystemVariables.System_TeamProject.value()}/_git/{dict_args["azure_remote_config_repo"]}?path=/'
        utils_azure = AzureDevopsApi(
            personal_access_token=SystemVariables.System_AccessToken.value(),
            compact_remote_config_url=f'{base_compact_remote_config_url}{dict_args["defect_dojo_mapping_path"]}',
        )
        connection = utils_azure.get_azure_connection()
        config_tool = utils_azure.get_remote_json_config(connection=connection)
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
                compact_remote_config_url=f'{base_compact_remote_config_url}{config_tool["CMDB_MAPPING_PATH"]}',
                personal_access_token=SystemVariables.System_AccessToken.value(),
                token_cmdb=dict_args["token_cmdb"],
                host_cmdb=config_tool["HOST_CMDB"],
                expression=config_tool["REGEX_EXPRESSION_CMDB"],
                token_defect_dojo=dict_args["token_defect_dojo"],
                host_defect_dojo=config_tool["HOST_DEFECT_DOJO"],
                scan_type=scan_type,
                engagement_name=BuildVariables.Build_DefinitionName.value(),
                service=BuildVariables.Build_DefinitionName.value(),
                file=file_path,
                version=BuildVariables.Build_BuildId.value(),
                build_id=BuildVariables.Build_BuildNumber.value(),
                source_code_management_uri=source_code_management_uri,
                branch_tag=BuildVariables.Build_SourceBranch.value(),
                commit_hash=BuildVariables.Build_SourceVersion.value(),
                environment=enviroment_mapping[ReleaseVariables.Environment.value()],
                tags="evc",
            )

            response = DefectDojo.send_import_scan(request)
            if hasattr(response, "test_url"):
                print("Report sent to defect dojo: ", response.test_url)
            else:
                print(response)
                print('"##vso[task.complete result=SucceededWithIssues;]DONE"')
    except Exception as ex:
        print("Handling run-time error send_defect_dojo info:")
        print(ex)
        print('"##vso[task.complete result=SucceededWithIssues;]DONE"')
