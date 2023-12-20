# How to setup your enviroment

1. In the root of the project execute the following commands (Important to have the vpn active to be able to download from artifactory):
 
```bash
python -m pip install --upgrade pip -i https://artifactory.apps.bancolombia.com/api/pypi/python-org/simple --trusted-host artifactory.apps.bancolombia.com
```
```bash
python -m pip install setuptools virtualenv wheel -i https://artifactory.apps.bancolombia.com/api/pypi/python-org/simple --trusted-host artifactory.apps.bancolombia.com
```
* Create a virtual environment and activate it:
```bash
virtualenv .venv
source .venv/bin/activate
```
```bash
python -m pip install -r tools/requirements.txt -i https://artifactory.apps.bancolombia.com/api/pypi/python-org/simple --trusted-host artifactory.apps.bancolombia.com
```
```bash
python -m pip install -r tools/requirements_test.txt -i https://artifactory.apps.bancolombia.com/api/pypi/python-org/simple --trusted-host artifactory.apps.bancolombia.com     
```
```bash
python -m pip install -r common_devsecops_lib/requirements.txt -i https://artifactory.apps.bancolombia.com/api/pypi/python-org/simple --trusted-host artifactory.apps.bancolombia.com
```
```bash
python -m pip install -r common_devsecops_lib/requirements_test.txt -i https://artifactory.apps.bancolombia.com/api/pypi/python-org/simple --trusted-host artifactory.apps.bancolombia.com     
```
2. Then build the common_devsecops_lib library and Install the created library:
```bash
cd common_devsecops_lib/
python setup.py bdist_wheel
```
* Put the command bellow and press key tab after utilities word:
```bash
pip install 'dist/devsecops_engine_utilities<KEY-TAB>' -i https://artifactory.apps.bancolombia.com/api/pypi/python-org/simple --trusted-host artifactory.apps.bancolombia.com
```
 
3. In the root of the project create a file named ".env" and add:
```bash
PYTHONPATH=tools/
```

4. Inside the folder located in the root .vscode. Configure the launch.json file as follows:

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
                "--remote_config_repo",
                "NU0429001_DevSecOps_Remote_Config",
                "--tool",
                "engine_iac",
                "--environment",
                "dev",
                "--use_secrets_manager",
                "False",
                "--use_vulnerability_management",
                "False"
            ],
            "env": {
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
                "ENV": "dev"
            },
            "justMyCode": true
        }
    ]
}
```

5. Go Run :arrow_forward: