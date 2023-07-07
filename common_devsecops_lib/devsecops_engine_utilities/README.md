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
        token_cmdb="4n9bde64nd07ebcu86shbco7m39n0",
        host="host cmdb",
        token_cmdb_defect_dojo="test56de11694e2fe83238235db9b007bb8736beae349011ec",
        host_defect_dojo="http://localhost:8000",
        scan_type="Checkov Scan",
        engagement_name="Engagement_Services_xxxxxxx",
        file=f"{path_file}/sheckov_scan.json",
        tags="evc",
    )

    response = DefectDojo.send_import_scan(request)

    # # Example api Scan sonnar

    request: ImportScanRequest = Connect.cmdb(
        token_cmdb="4n9bde64nd07ebcu86shbco7m39n0",
        host="https://cmdb.amazonaws.com",
        token_cmdb_defect_dojo="test56de11694e2fe8238949845db9b007bb8736beae349011ec",
        host_defect_dojo="http://localhost:8000",
        scan_type="SonarQube API Import",
        engagement_name="Engagement_Services_xxxxxx",
        tags="evc",
    )

    response = DefectDojo.send_import_scan(request)

# How can I help?

