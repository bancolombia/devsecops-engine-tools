---
sidebar_position: 1
---

# Module Engine Core

## Overview

The `engine_core` module is the central orchestrator of the DevSecOps Engine Tools platform. It coordinates the execution of security scans, manages configuration, integrates with external systems, and processes results for reporting and risk management. The module is designed following Clean Architecture principles, ensuring separation of concerns and extensibility.


## Configuration Structure

The module is configured through main JSON example files located in `example_remote_config_local/engine_core/`:

### ConfigTool.json

Configuration of the driven adapters in the main layer and management of on/off flags for the tools executed by engine tools.

```json
{
    "BANNER": "DevSecOps Engine Tools",
    "WARNING_RELEASE": false,
    "SECRET_MANAGER": {
        "AWS": {
            "SECRET_NAME": "",
            "USE_ROLE": false,
            "ROLE_ARN": "",
            "REGION_NAME": ""
        }
    },
    "VULNERABILITY_MANAGER": {
        "BRANCH_FILTER": [
            "trunk",
            "main"
        ],
        "DEFECT_DOJO": {
            "HOST_DEFECT_DOJO": "",
            "PRINT_DOMAIN": "",
            "LIMITS_QUERY": 100,
            "MAX_RETRIES_QUERY": 5,
            "TOOL_SCM_MAPPING": {
                "DEFAULT": 2,
                "TFSGIT": 2,
                "GITHUB": 3
            },
            "TOOL_SONAR_MAPPING": {
                "DEFAULT": 4,
                "SONAR_INSTANCE_ONE": 4,
                "SONAR_INSTANCE_TWO": 5
            },
            "TOOL_SLA_MAPPING": {
                "DEFAULT": 1,
                "ORPHAN": 4
            },
            "REIMPORT_SCAN": false,
            "CMDB": {
                "USE_CMDB": false,
                "HOST_CMDB": "",
                "GENERATE_AUTH_CMDB": false,
                "AUTH_CMDB_REQUEST_REPONSE": {
                    "URL": "",
                    "HEADERS": {
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                    "METHOD": "POST",
                    "PARAMS": "username=test&password=#{passwordvalue}#",
                    "RESPONSE": null
                },
                "REGEX_EXPRESSION_CMDB": "",
                "CMDB_MAPPING_PATH": "vulnerability_management/cmdb_mapping.json",
                "CMDB_MAPPING": {
                    "PRODUCT_TYPE_NAME": "",
                    "PRODUCT_NAME": "",
                    "TAG_PRODUCT": "",
                    "PRODUCT_DESCRIPTION": "",
                    "CODIGO_APP": ""
                },
                "CMDB_REQUEST_RESPONSE": {
                    "HEADERS": {
                        "Content-Type": "application/json",
                        "Api-Key": "tokenvalue"
                    },
                    "METHOD": "GET|POST",
                    "PARAMS": {
                        "appCode": "codappvalue"
                    },
                    "BODY": {
                        "appCode": "codappvalue"
                    },
                    "RESPONSE": [0],
                    "MAX_RETRIES": 3,
                    "RETRY_DELAY": 5
                }
            }
        }
    },
    "METRICS_MANAGER": {
        "AWS": {
            "BUCKET": "",
            "TYPE_FORMAT_BUCKET_FILE": "parquet|json",
            "PATH_BUCKET": "engine_tools",
            "USE_ROLE": false,
            "ROLE_ARN": "",
            "REGION_NAME": ""
        }
    },
    "SBOM_MANAGER": {
        "ENABLED": true,
        "TOOL": "SYFT|CDXGEN",
        "BRANCH_FILTER": [],
        "TOOL_OVERRIDE_PIPELINES": {
            "pipeline_exception_1": "SYFT",
            "pipeline_exception_2": "CDXGEN"
        },
        "SYFT": {
            "SYFT_VERSION": "1.17.0",
            "OUTPUT_FORMAT": "cyclonedx-json"
        },
        "CDXGEN": {
            "CDXGEN_VERSION": "11.7.0",
            "OUTPUT_FORMAT": "cyclonedx-json",
            "SLIM_BINARY": true,
            "EXCLUDE_TYPES": ["jar"],
            "EXCLUDE_PATHS": ["**/test/**"],
            "RECURSE": true,
            "DEBUG_PIPELINES": ["pipeline_name1", "pipeline_name2"],
            "LIFECYCLE_PIPELINES": {
                "pipeline_name1": "pre-build"
            }
        }
    },
    "ENGINE_IAC": {
        "ENABLED": true,
        "TOOL": "CHECKOV|KUBESCAPE|KICS"
    },
    "ENGINE_CONTAINER": {
        "ENABLED": true,
        "TOOL": "PRISMA|TRIVY"
    },
    "ENGINE_DAST": {
        "ENABLED": true,
        "TOOL": "NUCLEI",
        "EXTRA_TOOLS": ["JWT"]
    },
    "ENGINE_SECRET": {
        "ENABLED": true,
        "TOOL": "TRUFFLEHOG|GITLEAKS"
    },
    "ENGINE_DEPENDENCIES": {
        "ENABLED": true,
        "TOOL": "XRAY|DEPENDENCY_CHECK|TRIVY"
    },
    "ENGINE_CODE": {
        "ENABLED": true,
        "TOOL": "BEARER|KIUWAN"
    },
    "ENGINE_FUNCTION": {
        "ENABLED": true,
        "TOOL": "PRISMA"
    },
    "ENGINE_RISK": {
        "ENABLED": false
    },
    "REPORT_SONAR": {
        "ENABLED": true
    }
}
```

- **BANNER**: Application banner
- **WARNING_RELEASE**: warning in stage release break build
- **SECRET_MANAGER**: Driven adapter configuration for secrets manager
    - **AWS**
        - SECRET_NAME: secret name
        - USE_ROLE: use AWS role
        - ROLE_ARN: ARN of the assumed role with permissions over this resource
        - REGION_NAME: AWS region name

- **VULNERABILITY_MANAGER**: Driven adapter configuration for vulnerability manager
    - **BRANCH_FILTER**: Branch filter where the tool will send reports to the Vulnerability Manager.
        - feature/migration_open -> migration_open
        - PR -> [ID-PR]/merge
    - **DEFECT_DOJO**
        - HOST_DEFECT_DOJO: defect dojo host
        - PRINT_DOMAIN: Dominio to print
        - LIMITS_QUERY: Query limit for platform queries.
        - MAX_RETRIES_QUERY: Maximum number of retry attempts for queries to the platform
        - **TOOL_SCM_MAPPING**: Mapping between the source code management (SCM) tool and its corresponding identifier in DefectDojo.  
            - **DEFAULT**: Default SCM tool identifier.
            - **TFSGIT**: Identifier for Azure DevOps (TFS Git) repositories.
            - **GITHUB**: Identifier for GitHub repositories.

            Example:
            ```json
            "TOOL_SCM_MAPPING": {
                    "DEFAULT": 2,
                    "TFSGIT": 2,
                    "GITHUB": 3
            }
            ```
        - **TOOL_SONAR_MAPPING**: Mapping between SonarQube instances and their corresponding identifiers in DefectDojo.
            - **DEFAULT**: Default SonarQube instance identifier.
            - **SONAR_INSTANCE_ONE**: Identifier for the first SonarQube instance.
            - **SONAR_INSTANCE_TWO**: Identifier for the second SonarQube instance.

            Example:
            ```json
            "TOOL_SONAR_MAPPING": {
                "DEFAULT": 4,
                "SONAR_INSTANCE_ONE": 4,
                "SONAR_INSTANCE_TWO": 5
            }
            ```  
        - **TOOL_SLA_MAPPING**: Mapping between the SLA (Service Level Agreement) types and their corresponding identifiers in DefectDojo.
            - **DEFAULT**: Default SLA identifier.
            - **ORPHAN**: Identifier for orphaned findings or items without a specific SLA.

            Example:
            ```json
            "TOOL_SLA_MAPPING": {
                "DEFAULT": 1,
                "ORPHAN": 4
            }
            ```  
        - **REIMPORT_SCAN**: Boolean value that determines whether the scan results should be re-imported into DefectDojo. 
            - If set to `true`, the tool will attempt to re-import scan results, updating the same test.  
            - If set to `false`, each scan will be imported as a new test.  
        - **CMDB**: Configuration for the integration with the Configuration Management Database (CMDB).
            - **USE_CMDB**: Boolean value indicating whether to use CMDB integration (`true` or `false`).
            - **HOST_CMDB**: URL endpoint for the CMDB API.
            - **GENERATE_AUTH_CMDB**: Boolean value to enable or disable authentication request for the CMDB.
            - **AUTH_CMDB_REQUEST_REPONSE**: Object containing authentication request details if `GENERATE_AUTH_CMDB` is enabled.
                - **URL**: Authentication endpoint.
                - **HEADERS**: Headers required for the authentication request.
                - **METHOD**: HTTP method for the authentication request (e.g., `POST`).
                - **PARAMS**: Parameters for the authentication request.
                - **RESPONSE**: Expected response or token field.
            - **REGEX_EXPRESSION_CMDB**: Regular expression used to extract or filter data from the CMDB response.
            - **CMDB_MAPPING_PATH**: Path to the mapping file for product types or other mappings.
            - **CMDB_MAPPING**: Object mapping CMDB fields to DefectDojo fields.
                - **PRODUCT_TYPE_NAME**: Field name in CMDB for the product type.
                - **PRODUCT_NAME**: Field name in CMDB for the product name.
                - **TAG_PRODUCT**: Field name in CMDB for the product tag.
                - **PRODUCT_DESCRIPTION**: Field name in CMDB for the product description.
                - **CODIGO_APP**: Field name in CMDB for the application code.
            - **CMDB_REQUEST_RESPONSE**: Object containing the request and response configuration for querying the CMDB.
                - **HEADERS**: Headers required for the CMDB query.
                - **METHOD**: HTTP method for the CMDB query (`GET` or `POST`).
                - **PARAMS**: Parameters for the CMDB query (used for `GET`).
                - **BODY**: Body for the CMDB query (used for `POST`).
                - **RESPONSE**: Path or keys to extract the relevant data from the CMDB response.
                - **MAX_RETRIES**: Specifies the maximum number of retry attempts allowed for a given operation
                - **RETRY_DELAY**: Specifies the amount of time in seconds, to wait before retrying a failed operation

        This section allows you to configure how the vulnerability management module interacts with your organization's CMDB, including authentication, data extraction, and field mapping, to ensure seamless integration and accurate data synchronization.

- **METRICS_MANAGER**: Driven adapter configuration for metrics manager
    - **AWS**
        - BUCKET: bucket where the metrics JSON will be sent
        - USE_ROLE: use AWS role
        - ROLE_ARN: ARN of the assumed role with permissions over this resource
        - REGION_NAME: AWS region name

- **ENGINE_IAC**: Configuration for the engine_iac tool
    - ENABLED: true or false
    - TOOL: CHECKOV |KUBESCAPE | KICS

- **ENGINE_CONTAINER**: Configuration for the engine_container tool
    - ENABLED: true or false
    - TOOL: PRISMA | TRIVY

- **ENGINE_DAST**: Configuration for the engine_dast tool
    - ENABLED: true or false
    - TOOL: NUCLEI

- **ENGINE_SECRET**: Configuration for the engine_secret tool
    - ENABLED: true or false
    - TOOL: TRUFFLEHOG | GITLEAKS

- **ENGINE_CODE**: Configuration for the engine_code tool
    - ENABLED: true or false
    - TOOL: BEARER

- **ENGINE_DEPENDENCIES**: Configuration for the engine_dependencies tool
    - ENABLED: true or false
    - TOOL: XRAY | DEPENDENCY_CHECK | TRIVY

- **ENGINE_FUNCTION**: Configuration for the engine_function tool
    - ENABLED: true or false
    - TOOL: PRISMA

- **ENGINE_RISK**: Configuration for the engine_risk tool
    - ENABLED: true or false

- **REPORT_SONAR**: Configuration for the report_sonar tool
    - ENABLED: true or false

### Use Cases CMDB for vulnerability management

Initially, we need to know that the DevSecOps engine tools include a module for connecting to a vulnerability centralizer (DefectDojo). As a primary requirement for using this module, it must be considered whether a CMDB will be used or not. This is configurable through the remote config located in the [engine_core](https://github.com/bancolombia/devsecops-engine-tools/blob/trunk/example_remote_config_local/engine_core/ConfigTool.json). Below, examples of the two possible cases will be provided:

#### Using CMDB:
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

#### Without Using CMDB:
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
## Main Responsibilities

- **Orchestration:** Manages the workflow for running security tools (SAST, DAST, IaC, container, dependencies, secrets, risk).
- **Configuration Management:** Loads and applies configuration from remote repositories (Azure, GitHub, local).
- **Integration:** Connects with external platforms such as DefectDojo, cloud providers, artifact repositories, and CI/CD systems.
- **Result Processing:** Aggregates, normalizes, and processes scan results, including risk assessment and metrics reporting.
- **CLI Interface:** Provides a command-line interface for flexible execution and integration in pipelines.

## Key Components

- `runner_engine_core.py`: Main entry point for CLI execution and orchestration logic.
- `entry_point_core.py`: Initializes the engine, loads configuration, and triggers the appropriate use cases.
- **Use Cases:** Located in `src/domain/usecases/`, including:
	- `HandleScan`: Executes and processes security scans.
	- `HandleRisk`: Aggregates and evaluates risk based on findings.
	- `BreakBuild`: Determines if the build should fail based on policy.
	- `MetricsManager`: Handles metrics collection and reporting.

## Example CLI Usage

```sh
devsecops-engine-tools \
	--platform_devops github \
	--remote_config_source github \
	--remote_config_repo devsecops-config \
	--module engine_container \
	--tool trivy \
	--image_to_scan myimage:latest
```

## Extensibility

- New tools and modules can be added by extending the adapters and use cases.
- Integrations with new platforms or reporting systems can be implemented via the infrastructure layer.

## Testing

- Unit tests are provided in the `test/` directory, covering core logic and CLI argument parsing.


