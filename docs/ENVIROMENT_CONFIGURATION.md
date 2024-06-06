# How to setup your enviroment

1. In the root of the project execute the following commands:
 
```bash
python -m pip install
```
```bash
python -m pip install setuptools virtualenv wheel
```
* Create a virtual environment and activate it:
```bash
virtualenv .venv
source .venv/bin/activate
```
```bash
python -m pip install -r tools/requirements.txt
```
```bash
python -m pip install -r tools/requirements_test.txt     
```
 
2. In the root of the project create a file named ".env" and add:
```bash
PYTHONPATH=tools/
```

3. Inside the folder located in the root .vscode. Configure the launch.json file as follows:

```json
{
    "version": "0.2.0",
    "configurations": [
        
        {
            "name": "Python: Current File",
            "type": "python",
            "request": "launch",
            "program": "tools/devsecops_engine_tools/engine_core/src/applications/runner_engine_core.py",
            "console": "integratedTerminal",
            "args": [
                "--platform_devops",
                "local",
                "--remote_config_repo",
                "DevSecOps_Remote_Config",
                "--tool",
                "engine_iac",
                "--use_secrets_manager",
                "false",
                "--use_vulnerability_management",
                "false",
                "--send_metrics",
                "false",
            ],
            "env": {
                //platform azure
                "BUILD_BUILDID": "2688",
                "BUILD_DEFINITIONNAME": "[DEFINITIONNAME]",
                "BUILD_REPOSITORY_ID": "57a0ece4-aa98-4a6a-a1f3-a17b2207fb6f",
                "BUILD_REPOSITORY_NAME": "[REPOSITORY_NAME]",
                "BUILD_SOURCEBRANCH": "refs/heads/trunk",
                "BUILD_STAGINGDIRECTORY": "[/PATH_STAGINGDIRECTORY/]",
                "ARTIFACT_PATH": "[/ARTIFACT_PATH/]",
                "BUILD_SOURCEBRANCHMESSAGE": "",
                "BUILD_SOURCEBRANCHNAME": "trunk",
                "BUILD_SOURCEVERSION": "2d545969a76516156d76e1c88f8e699537e889bd",
                "BUILD_ARTIFACTSTAGINGDIRECTORY": "/tmp",
                "SYSTEM_ACCESSTOKEN": "",
                "SYSTEM_DEFAULTWORKINGDIRECTORY": "[/PATH_DEFAULTWORKINGDIRECTORY/]",
                "SYSTEM_DEFINITIONID": "1",
                "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI": "https://dev.azure.com/PNFEngineTest/",
                "SYSTEM_TEAMPROJECTID": "Pruebas_PNF_Engine",
                "SYSTEM_TEAMPROJECT": "Pruebas_PNF_Engine",
                "RELEASE_DEFINITIONNAME": "DEFINITION_NAME",
                "BUILD_PROJECTNAME" : "Pruebas_PNF_Engine",
                "BUILD_BUILDNUMBER" : "2688",
                "ENV": "dev",
                //platform local
                "DET_PIPELINE_NAME": "[DET_PIPELINE_NAME]",
                "DET_PATH_DIRECTORY": "[DET_PATH_DIRECTORY]",
                "DET_OS": "[DET_OS]",
                "DET_WORK_FOLDER": "[DET_WORK_FOLDER]",
                "DET_TEMP_DIRECTORY": "/tmp",
                "DET_BRANCH_NAME": "trunk",
                "DET_SOURCE_CODE_MANAGEMENT_URI": "[DET_SOURCE_CODE_MANAGEMENT_URI]",
                "DET_BASE_COMPACT_REMOTE_CONFIG_URL": "[DET_BASE_COMPACT_REMOTE_CONFIG_URL]",
                "DET_ACCESS_TOKEN": "[DET_ACCESS_TOKEN]",
                "DET_BUILD_EXECUTION_ID": "2688",
                "DET_BUILD_ID": "2688",
                "DET_BRANCH_TAG": "refs/heads/trunk",
                "DET_COMMIT_HASH": "2d545969a76516156d76e1c88f8e699537e889bd",
                "DET_ENVIRONMENT": "dev",
                "DET_STAGE": "Release",
                "DET_AGENT_DIRECTORY": "[DET_AGENT_DIRECTORY]",
                "DET_REPOSITORY_PROVIDER": "AzureDevOps",
                "DET_TARGET_BRANCH": "trunk",
                "DET_SOURCE_BRANCH": "feature/test",
                "DET_ORGANIZATION": "[DET_ORGANIZATION]",
                "DET_PROJECT_NAME": "[DET_PROJECT_NAME]",
                "DET_REPOSITORY": "[DET_REPOSITORY]",
                //platform github
                "GH_TEAMFOUNDATIONCOLLECTIONURI": "Organization_Name",
                "GH_ACCESSTOKEN" : "Token",
                "GH_HOSTTYPE": "Release",
                "GH_ENV": "dev",
                "GH_TEAMPROJECT": "[GH_TEAMPROJECT]",
                "GH_TARGETBRANCHNAME": "[GH_TARGETBRANCHNAME]",
                "GH_SOURCEBRANCH": "[GH_SOURCEBRANCH]",
                "GH_DEFAULTWORKINGDIRECTORY": "[GH_DEFAULTWORKINGDIRECTORY]",
                "GH_BUILD_BUILDID": "[GH_BUILD_BUILDID]",
                "GH_BUILD_BUILDNUMBER": "[GH_BUILD_BUILDNUMBER]",
                "GH_BUILD_DEFINITIONNAME": "[GH_BUILD_DEFINITIONNAME]",
                "GH_BUILD_REPOSITORY_NAME": "[GH_BUILD_REPOSITORY_NAME]",
                "GH_BUILD_SOURCEBRANCH": "[GH_BUILD_SOURCEBRANCH]",
                "GH_BUILD_SOURCEBRANCHNAME": "[GH_BUILD_SOURCEBRANCHNAME]",
                "GH_BUILD_SOURCEVERSION": "[GH_BUILD_SOURCEVERSION]",
                "GH_BUILD_REPOSITORY_PROVIDER": "[GH_BUILD_REPOSITORY_PROVIDER]", 
                "GH_RELEASE_DEFINITIONNAME": "[GH_RELEASE_DEFINITIONNAME]",
                "GH_RELEASE_RELEASEID": "[GH_RELEASE_RELEASEID]",
                "GH_AGENT_BUILDDIRECTORY": "[GH_AGENT_BUILDDIRECTORY]",
                "GH_AGENT_WORKFOLDER": "[GH_AGENT_WORKFOLDER]",
                "GH_AGENT_TEMPDIRECTORY": "[GH_AGENT_TEMPDIRECTORY]",
                "GH_AGENT_OS": "[GH_AGENT_OS]"
            },
            "justMyCode": true
        }
    ]
}
```

4. Go Run :arrow_forward: