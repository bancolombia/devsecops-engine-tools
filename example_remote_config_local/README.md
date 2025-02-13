# Example use remote config for vulnerability management

Initially, we need to know that the DevSecOps engine tools include a module for connecting to a vulnerability centralizer (DefectDojo). As a primary requirement for using this module, it must be considered whether a CMDB will be used or not. This is configurable through the remote config located in the [engine_core](https://github.com/bancolombia/devsecops-engine-tools/blob/trunk/example_remote_config_local/engine_core/ConfigTool.json). Below, examples of the two possible cases will be provided:

### Using CMDB:
Let's suppose the CMDB response is as follows:
```json
{
    "count": 2,
    "value": [
        {
            "ApplicationCode": "code1-app",
            "ApplicationName": "Example Application Name 1",
            "ApplicationType": "Example Application type 1",
            "ApplicationTag": "Example Application tag 1",
            "ApplicationDescription": "Example Application description 1",
            "Env": "PDN"
        },
        {
            "ApplicationCode": "code1-app",
            "ApplicationName": "Example Application Name 1",
            "ApplicationType": "Example Application type 1",
            "ApplicationTag": "Example Application tag 1",
            "ApplicationDescription": "Example Application description 1",
            "Env": "DEV"
        }
    ]
}
```

Then, the remote config settings should look similar to this:
```json
"DEFECT_DOJO": {
    "HOST_DEFECT_DOJO": "http://localhost:8080",
    "LIMITS_QUERY": 100,
    "MAX_RETRIES_QUERY": 5,
    "REIMPORT_SCAN": false,
    "CMDB": {
        "USE_CMDB": true,
        "HOST_CMDB": "http://host_cmdb_example",
        "REGEX_EXPRESSION_CMDB": "^([^-]+)",
        "CMDB_MAPPING_PATH": "/path/mapping_cmdb.json",
        "CMDB_MAPPING": {
            "PRODUCT_TYPE_NAME": "ApplicationType",
            "PRODUCT_NAME": "ApplicationName",
            "TAG_PRODUCT": "ApplicationTag",
            "PRODUCT_DESCRIPTION": "ApplicationDescription",
            "CODIGO_APP": "ApplicationCode"
        },
        "CMDB_REQUEST_RESPONSE": {
            "HEADERS": {
                "Content-Type": "application/json",
                "Api-Key": "tokenvalue"
            },
            "METHOD": "GET",
            "PARAMS": {
                "appCode": "codappvalue"
            },
            "RESPONSE": ["value", 0]
        }
    }
}
```

**Let’s detail the description for the elements under the CMDB key:**

- *USE_CMDB:* The value is a boolean, indicating whether or not CMDB will be used.

- *HOST_CMDB:* The URL of the API for querying the CMDB.

- *REGEX_EXPRESSION_CMDB:* Regular expression.

- *CMDB_MAPPING_PATH:* Location of the mapping for possible product types.

- *CMDB_MAPPING:* Element containing the equivalent mappings between DefectDojo and the CMDB.

- *CMDB_REQUEST_RESPONSE:* Contains the necessary elements to make a request to the CMDB.

- *HEADERS:* Headers required to make the request. Note that the authentication type must be via Api-Key. The value "tokenvalue" should remain as is, as it is necessary for replacing the token.

- *METHOD:* Can be either POST or GET.

- *PARAMS:* Used if the selected METHOD is GET. The value "codappvalue" should remain as is, as it is necessary for replacement.

- *BODY:* Used if the selected METHOD is POST. The value "codappvalue" should remain as is, as it is necessary for replacement.

### Without Using CMDB:
For this case, three environment variables must be created according to the DevOps platform.
```bash
## Platform local
DET_VM_PRODUCT_TYPE_NAME="Example product type name"
DET_VM_PRODUCT_NAME="Example product type name"
DET_VM_PRODUCT_DESCRIPTION="Example product descrition"

## Platform azure
VM_PRODUCT_TYPE_NAME="Example product type name"
VM_PRODUCT_NAME="Example product type name"
VM_PRODUCT_DESCRIPTION="Example product descrition"

## Platform github
VM_PRODUCT_TYPE_NAME="Example product type name"
VM_PRODUCT_NAME="Example product type name"
VM_PRODUCT_DESCRIPTION="Example product descrition"
```

The remote config settings should look similar to this:
```json
    "DEFECT_DOJO": {
        "HOST_DEFECT_DOJO": "http://localhost:8080",
        "LIMITS_QUERY": 100,
        "MAX_RETRIES_QUERY": 5,
        "REIMPORT_SCAN": false,
        "CMDB": {
            "USE_CMDB": false,
            "REGEX_EXPRESSION_CMDB": "^([^-]+)",
        }
    }
```