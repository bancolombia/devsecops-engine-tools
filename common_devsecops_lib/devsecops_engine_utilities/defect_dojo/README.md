# Example of use of defect-dojo module

import os
from devsecops_engine_utilities.defect_dojo import DefectDojo,\
    ImportScanRequest, Connect

path_file = os.path.dirname(os.path.realpath(__file__))
if __name__ == "__main__":
    # Example Checkov Scan file

     request: ImportScanRequest = Connect.cmdb(
        cmdb_mapping=settings.CMDB_MAPPING
        compact_remote_config_url=settings.COMPACT_REMOTE_CONFIG_URL,
        personal_access_token=settings.PERSONAL_ACCESS_TOKEN,
        token_cmdb=settings.TOKEN_CMDB,
        host_cmdb=settings.HOST_CMDB,
        expression=settings.EXPRESSION,
        token_defect_dojo=settings.TOKEN_DEFECT_DOJO,
        host_defect_dojo=settings.HOST_DEFECT_DOJO,
        scan_type=scan_type, # checkov Scan file
        engagement_name=settings.ENGAGEMENT_NAME,
        tags=settings.TAGS,
        branch_tag=settings.BRANCH_TAG,
    )

    response = DefectDojo.send_import_scan(request)

    # # Example api Scan sonnar

       request: ImportScanRequest = Connect.cmdb(
        cmdb_mapping=settings.CMDB_MAPPING
        compact_remote_config_url=settings.COMPACT_REMOTE_CONFIG_URL,
        personal_access_token=settings.PERSONAL_ACCESS_TOKEN,
        token_cmdb=settings.TOKEN_CMDB,
        host_cmdb=settings.HOST_CMDB,
        expression=settings.EXPRESSION,
        token_defect_dojo=settings.TOKEN_DEFECT_DOJO,
        host_defect_dojo=settings.HOST_DEFECT_DOJO,
        scan_type=scan_type, # SonarQube API Import
        engagement_name=settings.ENGAGEMENT_NAME,
        tags=settings.TAGS,
        branch_tag=settings.BRANCH_TAG, # example main or master
    )


    response = DefectDojo.send_import_scan(request)


https://dev.azure.com/{organization}/{project}/_git/{repository}

## run Integration test

In this module you will find the integration tests of the methods implemented in the library and it can also serve as documentation.

be located in the directory common_devsecops_lib and execute command

    python -m integrations_test.defect_dojo


## Config lauch.json of vscode

    {
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Integration test",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/common_devsecops_lib/test_integrations_defect_dojo.py",
            "console": "integratedTerminal",
            "justMyCode": true
        }
    ]
}
