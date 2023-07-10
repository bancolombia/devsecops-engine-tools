# Introduction

DevSecOps Security Tools

# Objective

# Project layout

```
NU0429001_devsecops_engine
├───.github
│   └───workflows
│           engine_core.yaml         -> CD pipeline for the engine core.
│           engine_sast.yaml         -> CD pipeline for the engine sast.
│           engine_dast.yaml         -> CD pipeline for the engine dast.
│           engine_sca.yaml         -> CD pipeline for the engine sca.
│           engine_utilities.yaml         -> CD pipeline for the engine utilities.
|
├───engine_core -> Code and Docker file for the engine_core.
|           test
|           src 
|               applications
|               deploment
|               domain
|                   model
|                   usecases
|               infraestructure
|                   driven_adapters
|                   entry_points
|                   utils
```
# Example of use of defect-dojo module
import os
from devsecops_engine_utilities.defect_dojo import DefectDojo,\
    ImportScanRequest, Connect

path_file = os.path.dirname(os.path.realpath(__file__))
if __name__ == "__main__":
    # Example Checkov Scan file

    
    request: ImportScanRequest = Connect.cmdb(
        cmdb_mapping={
            "product_type_name": "nombreevc",
            "product_name": "nombreapp",
            "tag_product": "nombreentorno",
            "product_description": "arearesponsableti",
            "codigo_app": "CodigoApp",
        },
        organization_url="https://test.test.com/",
        personal_access_token="28394tokenk-test",
        repository_id="name_engagemeent or id repositoroy",
        remote_config_path="paht of file .json",
        project_remote_config="project name",
        token_cmdb="token1293983",
        host_cmdb="https://test.test.com",
        token_defect_dojo="tokentest1312342",
        expression=r"((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS)\d+)_",
        host_defect_dojo="http://localhost:8000",
        scan_type="Checkov Scan",
        engagement_name="",
        file=f"{path_file}/sheckov_scan.json",
        tags="evc",
    )

    response = DefectDojo.send_import_scan(request)

    # # Example api Scan sonnar

       request: ImportScanRequest = Connect.cmdb(
        cmdb_mapping={
            "product_type_name": "nombreevc",
            "product_name": "nombreapp",
            "tag_product": "nombreentorno",
            "product_description": "arearesponsableti",
            "codigo_app": "CodigoApp",
        },
        organization_url="https://test.test.com/",
        personal_access_token="28394tokenk-test",
        repository_id="name_engagemeent or id repositoroy",
        remote_config_path="paht of file .json",
        project_remote_config="project name",
        token_cmdb="token1293983",
        host_cmdb="https://test.test.com",
        expression=r"((AUD|AP|CLD|USR|OPS|ASN|AW|NU|EUC|IS)\d+)_",
        token_defect_dojo="tokentest1312342",
        host_defect_dojo="http://localhost:8000",
        scan_type="SonarQube API Import",
        engagement_name="",
        file=f"{path_file}/sheckov_scan.json",
        tags="evc",
    )


    response = DefectDojo.send_import_scan(request)


https://dev.azure.com/{organization}/{project}/_git/{repository}

# How can I help?

