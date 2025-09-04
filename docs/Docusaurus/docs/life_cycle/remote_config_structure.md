---
sidebar_position: 2
---

# Structure Remote Config

[example_remote_config_local](https://github.com/bancolombia/devsecops-engine-tools/blob/trunk/example_remote_config_local/)
```bash
📦Remote_Config
   ┣ 📂engine_core
   ┃ ┗ 📜ConfigTool.json
   ┣ 📂engine_dast
   ┃ ┗ 📜ConfigTool.json
   ┃ ┗ 📜Exclusions.json
   ┣ 📂engine_integrations
   ┃ ┗ 📂report_sonar
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┃ ┗ 📂copacetic
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┣ 📂engine_risk
   ┃ ┗ 📜ConfigTool.json
   ┃ ┗ 📜Exclusions.json
   ┣ 📂engine_sast
   ┃ ┗ 📂engine_iac
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┃ ┗ 📂engine_secret
   ┃   ┗ 📜ConfigTool.json
   ┃ ┗ 📂engine_code
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┣ 📂engine_sca
   ┃ ┗ 📂engine_container
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┃ ┗ 📂engine_dependencies
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
```

## **engine_core**

### Configuration

Configuration of the driven adapters in the main layer and management of on/off flags for the tools executed by engine tools.

> /engine_core/ConfigTool.json
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
                "CMDB_MAPPING_PATH": "",
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
                    "RESPONSE": [0]
                }
            }
        }
    },
    "METRICS_MANAGER": {
        "AWS": {
            "BUCKET": "",
            "USE_ROLE": false,
            "ROLE_ARN": "",
            "REGION_NAME": ""
        }
    },
    "SBOM_MANAGER": {
        "ENABLED": false,
        "TOOL": "SYFT|CDXGEN",
        "BRANCH_FILTER": [
            "trunk",
            "main"
        ],
        "SYFT": {
            "SYFT_VERSION": "1.17.0",
            "OUTPUT_FORMAT": "cyclonedx-json"
        },
        "CDXGEN": {
            "CDXGEN_VERSION": "11.6.0",
            "OUTPUT_FORMAT": "cyclonedx-json",
            "SLIM_BINARY": false
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
        "ENABLED": "true",
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

## **engine_dast**

Module is responsible for orchestrating Dynamic Application Security Testing (DAST) within the DevSecOps Engine Tools platform. It automates the execution of DAST tools, processes scan configurations, manages authentication flows, and integrates results for further risk analysis and reporting

### Configuration

> /engine_dast/ConfigTool.json
```json
{
    "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 1, 
            "High": 8, 
            "Medium": 10, 
            "Low": 15
        },
        "COMPLIANCE": {
            "Critical": 1
        }
    },
    "MESSAGE_INFO_DAST": "If you have doubts, visit https://forum.example",
    "IGNORE_ERRORS": false,
    "NUCLEI": {
        "VERSION": "3.3.5",
        "DOWNLOAD_URL": "https://github.com/projectdiscovery/nuclei/releases/download/",
        "CONCURRENCY": 1,
        "RESPONSE_SIZE": 256,
        "BULK_SIZE": 1,
        "TIMEOUT": 10,
        "BINARY_PATH": "/usr/local/bin",
        "USE_EXTERNAL_CHECKS_GIT": false,
        "USE_EXTERNAL_CHECKS_DIR": true,
        "EXTERNAL_DIR_OWNER": "dummie-username",
        "EXTERNAL_DIR_REPOSITORY": "example-repo-templates",
        "APP_ID_GITHUB": "00000000",
        "INSTALLATION_ID_GITHUB": "00000000",
        "ENABLE_CUSTOM_RULES": true
    },
    "JWT": {
        "RULES": {
                "JWT_ALGORITHM": {
                    "checkID": "ENGINE_JWT_001",
                    "environment": {"dev": "True", "pdn": "True", "qa": "True"},
                    "guideline": "https://example.com/",
                    "severity": "Low",
                    "cvss": "",
                    "category": "Vulnerability"
                }
        }
    }
}

```


### Exclusions

> /engine_dast/Exclusions.json
#### **By Component**

The key for each element in the JSON is the name of the release pipeline. It can be composed of the following properties:
 > TOOL:
  - id: Rule ID
  - where: all or file path to be excluded
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - severity: Severity of the finding
  - hu: User Story identifier supporting the configured exception.
 
 > SKIP_TOOL
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - hu: User Story identifier supporting the configured exception.

 > THRESHOLD
  - VULNERABILITY: new defined levels (Critical,High,Medium,Low)
  - Compliance: new defined levels (Critical)
  - CVE: List of CVEs
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - reason: reason for the threshold exclusion
  - hu: User Story identifier supporting the configured exception.



```json
{
    "NU0000_Build_Proof": {
      "SKIP_TOOL": {
        "create_date": "24012024",
        "expired_date": "30012024",
        "hu": "3423213"
      },
      "NUCLEI": [
        {
          "id": "strict-transport-security-header",
          "where": "gateway.yaml",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704"
        }
      ]
    },
    "NU0000_Build_Proof_MR_ms_proof": {
      "JWT": [
        {
          "id": "cache-control-header",
          "where": "app.yaml",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704"
        }
      ]
    },
    "NU0000_Build_Proof_Skip": {
      "SKIP_TOOL": {
        "create_date": "24012024",
        "expired_date": "30012024",
        "hu": "3423213"
      }
    },
    "NU0000_Build_Proof_THRESHOLD": {
      "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 50,
            "High": 50,
            "Medium": 8,
            "Low": 15
        },
        "COMPLIANCE": {
          "Critical": 99
        },
        "create_date": "26092024",
        "expired_date": "30062025",
        "hu": "123122"
      }
    }
}
```


#### **By All Policy**

The key of the element in the JSON is All. It can be composed of the following properties:

> TOOL:
  - id: Rule ID
  - where: all or file path to be excluded
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - severity: Severity of the finding
  - hu: User Story identifier supporting the configured exception.
  - reason: Reason for the exception (False Positive)



```json
{
    "All": {
      "JWT": [
        {
          "id": "strict-transport-security-header",
          "where": "all",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704",
          "reason": "False Positive"
        }
      ]
    }
}
```


#### **By BY_PATTERN_SEARCH Policy**

The key of the element in the JSON is the regex. It can be composed of the following properties:

> REGEX:
  - THRESHOLD: Rule ID
    - VULNERABILITY: new defined levels (Critical,High,Medium,Low)
    - Compliance: new defined levels (Critical)
    - CVE: List of CVEs
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - reason: reason for the threshold exclusion
    - hu: User Story identifier supporting the configured exception.



```json
{
    "BY_PATTERN_SEARCH": {
        "*_(?i:migration).*": {
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 99,
                    "High": 99,
                    "Medium": 99,
                    "Low": 99
                },
                "create_date": "10092024",
                "expired_date": "31122025",
                "reason": "Migration",
                "hu": "123123"
            }
        }
    }
}
```


## **engine_integrations**

The engine_integrations module enables the integration of DevSecOps Engine Tools with external systems and platforms, focusing on orchestrating and automating reporting and data exchange processes. It is designed to be extensible, allowing new integrations to be added as needed.

### **report_sonar**

#### Configuration

> /engine_integrations/report_sonar/ConfigTool.json
```json
{
    "IGNORE_SEARCH_PATTERN": ".*test.*",
    "TARGET_BRANCHES": ["trunk", "develop", "master"],
    "MAX_RETRIES_QUERY_SONAR": 5,
    "USE_BRANCH_PARAMETER": false,
    "USE_PULL_REQUEST_PARAMETER": ["proyect1", "proyect2"],
    "PIPELINE_COMPONENTS": {
        "EXAMPLE_MULTICOMPONENT_PIPELINE": [
            "component1",
            "component2",
            "component3",
            "component4",
            "component5"
        ]
    }
}

```

#### Exclusions

> /engine_integrations/report_sonar/Exclusions.json
##### **By Component**

The key of each element in the JSON is the name of the build pipeline. This can be composed of the following properties:
 > PIPELINE_BUILD:
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - hu: User Story identifier supporting the configured exception.
    - reason: reason for the exclusion



```json
{
    "PIPELINE_NAME": {
        "create_date": "18112023",
        "expired_date": "18032024",
        "hu": "0000000"
    }
}
```

##### **By BY_PATTERN_SEARCH Policy**

The key of the element in the JSON is the regex. It can be composed of the following properties:

 > REGEX:
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - hu: User Story identifier supporting the configured exception.
    - reason: reason for the exclusion


```json
{
    "BY_PATTERN_SEARCH": {
      ".*test.*": {
          "create_date": "24012025",
          "expired_date": "31032025",
          "hu": "6032053"
      }
    }
}
```

### **copacetic**

#### Configuration

> /engine_integrations/copacetic/ConfigTool.json
```json
{
    "VERSION": "0.11.1",
    "IGNORE_SEARCH_PATTERN": "(?i).*(?:test|demo|sample).*",
    "TARGET_BRANCHES": ["main", "master", "develop", "release"],
    "TIMEOUT": 1800,
    "DEFAULT_OUTPUT_SUFFIX": "-patched",
    "BUILDKIT_CONFIG": {
        "DEFAULT_ADDR": "docker-container://buildkit",
        "PROGRESS": "auto",
        "IGNORE_ERRORS": false
    }
}

```

#### Exclusions

> /engine_integrations/copacetic/Exclusions.json
##### **By Component**

The key of each element in the JSON is the name of the build pipeline. This can be composed of the following properties:
 > PIPELINE_BUILD:
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - hu: User Story identifier supporting the configured exception.
    - reason: reason for the exclusion



```json
{
    "PIPELINE_NAME": {
        "create_date": "18112023",
        "expired_date": "18032024",
        "hu": "0000000"
    }
}
```

##### **By BY_PATTERN_SEARCH Policy**

The key of the element in the JSON is the regex. It can be composed of the following properties:

 > REGEX:
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - hu: User Story identifier supporting the configured exception.
    - reason: reason for the exclusion


```json
{
    "BY_PATTERN_SEARCH": {
      ".*test.*": {
          "create_date": "24012025",
          "expired_date": "31032025",
          "hu": "6032053"
      }
    }
}
```

## **engine_risk**
Module for prioritizing the resolution of findings reported in Vulnerability Management.

### Configuration

> /engine_risk/ConfigTool.json

```json
{
    "MESSAGE_INFO": "Custom message",
    "IGNORE_ANALYSIS_PATTERN": "(.*_test|test_.*)",
    "COUNTRY_HOLIDAYS": "CO",
    "HANDLE_SERVICE_NAME": {
        "ENABLED": "false",
        "CHECK_ENDING": [
            "_ending1",
            "_ending2"
        ],
        "REGEX_GET_SERVICE_CODE": "[^_]+",
        "REGEX_GET_WORDS": "[_-]",
        "MIN_WORD_LENGTH": 3,
        "MIN_WORD_AMOUNT": 2,
        "REGEX_CHECK_WORDS": "(a^)",
        "ADD_SERVICES": [
            "{service_code}-custom_service",
            "custom_service"
        ]
    },
    "PARENT_ANALYSIS": {
        "ENABLED": "false",
        "REGEX_GET_PARENT": "^.*?_parent_id"
    },
    "EXCLUSIONS_PATHS": {
        "engine_code": "engine_sast/engine_code/Exclusions.json",
        "engine_iac": "engine_sast/engine_iac/Exclusions.json",
        "engine_secret": "engine_sast/engine_secret/Exclusions.json",
        "engine_container": "engine_sca/engine_container/Exclusions.json",
        "engine_dependencies": "engine_sca/engine_dependencies/Exclusions.json"
    },
    "WEIGHTS": {
        "severity": {
            "critical": 10,
            "high": 5,
            "medium": 3,
            "low": 1
        },
        "tags": {
            "engine_iac": 0,
            "engine_secret": 0,
            "engine_container": 0,
            "engine_dependencies": 0
        },
        "age": 0.0333,
        "max_age": 12,
        "epss_score": 100
    },
    "RUNTIME_TAG_EXCLUSION_DAYS": {
        "ENABLED": false,
        "ERROR_ON_FAILED": false
    },
    "TAG_EXCLUSION_DAYS": {
        "tag1": 10,
        "tag2": 20
    },
    "TAG_BLACKLIST_EXCLUSION_DAYS": {
        "tag3": 5,
        "tag4": 0
    },
    "THRESHOLD": {
        "REMEDIATION_RATE": {
            "1": 0,
            "5": 30,
            "10": 50,
            "other": 70
        },
        "RISK_SCORE": 10
    }
}
```

### Exclusions

> /engine_risk/Exclusions.json

It should be noted that engine_risk inherits the exclusions from all practices; however, it has the ability to configure exclusions in cases where the finding does not originate from one of our practices.

#### **By Component**

The key for each element in the JSON is the name of the release pipeline. It can be composed of the following properties:
 > RISK:
  - id: Rule ID
  - where: all or vulnerable file path
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - hu: User Story identifier supporting the configured exception.
 
 > SKIP_TOOL
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - hu: User Story identifier supporting the configured exception.

 > SKIP_SERVICE
  - services: list of services to exclude in the pipeline.
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - hu: User Story identifier supporting the configured exception.
 
 > THRESHOLD
  - REMEDIATION_RATE: new remediation rate threshold.
  - RISK_SCORE: new risk score threshold.
  - TAG_MAX_AGE: new threshold for days for blacklist tags.
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - reason: reason for the threshold exclusion
  - hu: User Story identifier supporting the configured exception.


```json
{
    "NU0000_Build_Proof": {
      "RISK": [
        {
          "id": "84771dba-5503-4201-83e0-23d962250f07",
          "where": "all",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704"
        },
        {
          "id": "AYElNS2oHPG9aMv2mrUC",
          "where": "vulnerable/file.txt",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704"
        }
      ]
    },
    "NU0000_Build_Proof_Skip": {
      "SKIP_TOOL": {
        "create_date": "24012024",
        "expired_date": "30012024",
        "hu": "3423213"
      }
    },
    "NU0000_Build_Proof_Skip_Services": {
      "SKIP_SERVICE": {
        "services": [
            "NU0000_Exclude_Service1",
            "NU0000_Exclude_Service2"
        ],
        "create_date": "24012024",
        "expired_date": "30012024",
        "hu": "3423213"
      }
    },
    "AW0000_Release_New_Threshold": {
        "THRESHOLD": {
            "REMEDIATION_RATE": {
                "other": 0
            },
            "RISK_SCORE": 999,
            "create_date": "24012024",
            "expired_date": "30012024",
            "hu": "3423213"
        }
    }
}
```

#### **By All Policy**

The key of the element in the JSON is All. It can be composed of the following properties:

> RISK:
  - id: Rule ID
  - where: all or vulnerable file path
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - hu: User Story identifier supporting the configured exception.
  - reason: Reason for the exception (False Positive)


```json
{
    "All": {
      "RISK": [
        {
          "id": "48428cdb-4da0-4440-878b-6ceced98c7bf",
          "where": "all",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704",
          "reason": "False Positive"
        }
      ]
    }
}
```


#### **By BY_PATTERN_SEARCH Policy**

The key of the element in the JSON is the regex. It can be composed of the following properties:

> REGEX:
  - THRESHOLD: Rule ID
    - REMEDIATION_RATE: new remediation rate threshold.
    - RISK_SCORE: new risk score threshold.
    - TAG_MAX_AGE: new threshold for days for blacklist tags.
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - reason: reason for the threshold exclusion
    - hu: User Story identifier supporting the configured exception.


```json
{
    "BY_PATTERN_SEARCH": {
        "*_(?i:migration).*": {
            "THRESHOLD": {
                "REMEDIATION_RATE": {
                    "other": 0
                },
                "RISK_SCORE": 999,
                "create_date": "10092024",
                "expired_date": "31122025",
                "reason": "Migration",
                "hu": "123123"
            }
        }
    }
}
```



## **engine_sast/engine_code**

The engine_code module is responsible for orchestrating Static Application Security Testing (SAST) within the DevSecOps Engine Tools platform. It automates the execution of SAST tools, processes code scan configurations, manages exclusions, and integrates results for further risk analysis and reporting.

### Configuration

> /engine_sast/engine_code/ConfigTool.json
```json
{
    "IGNORE_SEARCH_PATTERN": [
      ".git"
    ],
    "EXCLUDE_FOLDER": [],
    "MESSAGE_INFO_ENGINE_CODE": "engine_code run successfully",
    "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 999,
            "High": 999,
            "Medium": 999,
            "Low": 999
        },
        "COMPLIANCE": {
            "Critical": 0
        }
    },
    "BEARER": {
      "NUMBER_THREADS": 4
    },
    "TARGET_BRANCHES": ["trunk", "develop"]
}
```

### Exclusiones

> /engine_sast/engine_code/Exclusions.json

#### **By Component**

The key for each element in the JSON is the name of the release pipeline. It can be composed of the following properties:
 > TOOL:
    - id: Rule ID
    - where: all or file path to be excluded
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - severity: Severity of the finding
    - hu: User Story identifier supporting the configured exception.
 
 > SKIP_TOOL
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - hu: User Story identifier supporting the configured exception.

 > THRESHOLD
    - VULNERABILITY: new defined levels (Critical,High,Medium,Low)
    - Compliance: new defined levels (Critical)
    - CVE: List of CVEs
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - reason: reason for the threshold exclusion
    - hu: User Story identifier supporting the configured exception.

```json
{
	"Repository_Test": {
		"BEARER": [
			{
				"id": "javascript_lang_logger_leak",
				"where": "/repository_name/path/to/file.ts",
				"create_date": "18112023",
				"expired_date": "18032024",
				"severity": "Low",
				"hu": "0000000"
			}
		]
	}
}
```

#### **By All Policy**

The key of the element in the JSON is All. It can be composed of the following properties:

> TOOL:
    - id: Rule ID
    - where: all or file path to be excluded
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - severity: Severity of the finding
    - hu: User Story identifier supporting the configured exception.
    - reason: Reason for the exception (False Positive)



```json
{
	"All": {
		"BEARER": [
			{
				"id": "test_id",
				"where": "all",
				"create_date": "18112023",
				"expired_date": "18032024",
				"severity": "Low",
				"hu": "0000000"
			}
		]
	}
}
```

#### **By BY_PATTERN_SEARCH Policy**

The key of the element in the JSON is the regex. It can be composed of the following properties:

> REGEX:
    - THRESHOLD: Rule ID
        - VULNERABILITY: new defined levels (Critical, High, Medium, Low)
        - COMPLIANCE: new defined levels (Critical)
        - CVE: List of CVEs
        - create_date: creation date (daymonthyear)
        - expired_date: expiration date (daymonthyear)
        - reason: reason for the threshold exclusion
        - hu: User Story identifier supporting the configured exception.


```json
{
    "BY_PATTERN_SEARCH": {
        "*_(?i:migration).*": {
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 99,
                    "High": 99,
                    "Medium": 99,
                    "Low": 99
                },
                "create_date": "10092024",
                "expired_date": "31122025",
                "reason": "Migration",
                "hu": "123123"
            }
        }
    }
}
```


## **engine_sast/engine_iac**

Static infrastructure analysis (k8s, dockerfile, cft) is a process that detects vulnerabilities in an application's defined infrastructure. This automated process is part of Bancolombia's DevSecOps practices, which evaluate security, code quality, and compliance.

### Configuration

> /engine_sast/engine_iac/ConfigTool.json
```json
{
    "SEARCH_PATTERN": [
      "AW",
      "NU"
    ],
    "IGNORE_SEARCH_PATTERN": "(.*test.*|.*prueba.*|.*Borrar|.*eliminar.*|.*No_usar)",
    "UPDATE_SERVICE_WITH_FILE_NAME_CFT": "True",
    "MESSAGE_INFO_ENGINE_IAC": "message",
    "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 1,
            "High": 8,
            "Medium": 10,
            "Low": 15
        },
        "QUALITY_VULNERABILITY_MANAGEMENT": {
            "PTS": [
                {
                    "Product Type Name": {
                        "APPS": [
                            "CodeApp",
                            "CodeApp1",
                            "CodeApp12"
                        ],
                        "PROFILE": "STRONG"
                    }
                },
                {
                    "Product Type Name2": {
                        "APPS": "ALL",
                        "PROFILE": "MODERATE"
                    }
                }
            ],
            "STRONG": {
                "Critical": 0,
                "High": 0,
                "Medium": 5,
                "Low": 15
            },
            "MODERATE": {
                "Critical": 1,
                "High": 3,
                "Medium": 5,
                "Low": 15
            }
        },
        "COMPLIANCE": {
            "Critical": 1
        }
    },
    "CHECKOV": {
        "VERSION": "2.3.296",
        "USE_EXTERNAL_CHECKS_GIT": "False",
        "EXTERNAL_CHECKS_GIT": "external_repo",
        "EXTERNAL_GIT_SSH_HOST": "github.com",
        "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "",
        "USE_EXTERNAL_CHECKS_DIR": "True",
        "EXTERNAL_DIR_OWNER": "owner",
        "EXTERNAL_DIR_REPOSITORY": "repository",
        "RULES": {
            "RULES_DOCKER": {
                "CKV_DOCKER_1": {
                    "checkID": "IAC-CKV-DOCKER-1 Ensure port 22 is not exposed",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "guideline",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Vulnerability"
                }
            },
            "RULES_K8S": {
                "CKV_K8S_8": {
                    "checkID": "IAC-CKV_K8S_8 Liveness Probe Should be Configured",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "guideline",
                    "severity": "Critical",
                    "cvss": "",
                    "category": "Compliance"
                }
            }
        }
    }
}
```

### Exclusiones

> /engine_sast/engine_iac/Exclusions.json

#### **By Component**

The key for each element in the JSON is the name of the release pipeline. It can be composed of the following properties:
 > TOOL:
    - id: Rule ID
    - where: all or file path to be excluded
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - severity: Severity of the finding
    - hu: User Story identifier supporting the configured exception.
 
 > SKIP_TOOL
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - hu: User Story identifier supporting the configured exception.

 > THRESHOLD
    - VULNERABILITY: new defined levels (Critical,High,Medium,Low)
    - Compliance: new defined levels (Critical)
    - CVE: List of CVEs
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - reason: reason for the threshold exclusion
    - hu: User Story identifier supporting the configured exception.

```json
{
        "NU0000_Build_Proof": {
            "SKIP_TOOL": {
                "create_date": "24012024",
                "expired_date": "30012024",
                "hu": "3423213"
            },
            "CHECKOV": [
                {
                    "id": "CKV_K8S_40",
                    "where": "gateway.yaml",
                    "create_date": "18112023",
                    "expired_date": "18032024",
                    "hu": "4338704"
                }
            ]
        },
        "NU0000_Build_Proof_MR_ms_proof": {
            "CHECKOV": [
                {
                    "id": "CKV_K8S_9",
                    "where": "app.yaml",
                    "create_date": "18112023",
                    "expired_date": "18032024",
                    "hu": "4338704"
                }
            ]
        },
        "NU0000_Build_Proof_Skip": {
            "SKIP_TOOL": {
                "create_date": "24012024",
                "expired_date": "30012024",
                "hu": "3423213"
            }
        },
        "NU0000_Build_Proof_THRESHOLD": {
            "THRESHOLD": {
                "VULNERABILITY": {
                        "Critical": 50,
                        "High": 50,
                        "Medium": 8,
                        "Low": 15
                },
                "COMPLIANCE": {
                    "Critical": 99
                },
                "create_date": "26092024",
                "expired_date": "30062025",
                "hu": "123122"
            }
        }
}
```

#### **By All Policy**

The key of the element in the JSON is All. It can be composed of the following properties:

> TOOL:
    - id: Rule ID
    - where: all or file path to be excluded
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - severity: Severity of the finding
    - hu: User Story identifier supporting the configured exception.
    - reason: Reason for the exception (False Positive)



```json
{
    "All": {
      "CHECKOV": [
        {
          "id": "CKV_K8S_24",
          "where": "all",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704",
          "reason": "False Positive"
        }
      ]
    }
}
```

#### **By BY_PATTERN_SEARCH Policy**

The key of the element in the JSON is the regex. It can be composed of the following properties:

> REGEX:
    - THRESHOLD: Rule ID
        - VULNERABILITY: new defined levels (Critical, High, Medium, Low)
        - COMPLIANCE: new defined levels (Critical)
        - CVE: List of CVEs
        - create_date: creation date (daymonthyear)
        - expired_date: expiration date (daymonthyear)
        - reason: reason for the threshold exclusion
        - hu: User Story identifier supporting the configured exception.



```json
{
    "BY_PATTERN_SEARCH": {
        "*_(?i:migration).*": {
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 99,
                    "High": 99,
                    "Medium": 99,
                    "Low": 99
                },
                "create_date": "10092024",
                "expired_date": "31122025",
                "reason": "Migration",
                "hu": "123123"
            }
        }
    }
}
```

## **engine_sast/engine_secret**

Secret scanning is a process that detects vulnerabilities in the application's source code. This automated process is part of Bancolombia's DevSecOps practices, through which security, code quality, and compliance are evaluated.


### Configuration

> /engine_sast/engine_secret/ConfigTool.json
```json
{
    "IGNORE_SEARCH_PATTERN": "(.*test.*)",
    "MESSAGE_INFO_ENGINE_SECRET": "engine_secret run successfully",
    "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 99,
            "High": 99,
            "Medium": 99,
            "Low": 99
        },
        "COMPLIANCE": {
            "Critical": 0
        }
    },
    "TARGET_BRANCHES": ["trunk", "develop"],
    "trufflehog": {
        "VERSION": "3.88.31",
        "EXCLUDE_PATH": [".git", "_venv"],
        "NUMBER_THREADS": 4,
        "ENABLE_CUSTOM_RULES" : false,
        "EXTERNAL_DIR_OWNER": "ExternalOrg",
        "EXTERNAL_DIR_REPOSITORY": "DevSecOps_Checks",
        "APP_ID_GITHUB":"",
        "INSTALLATION_ID_GITHUB":"",
        "USE_EXTERNAL_CHECKS_GIT": false,
        "USE_EXTERNAL_CHECKS_DIR": false,
        "RULES": {
            "MISCONFIGURATION_SCANNING": {
                "References": "https://reference.url/",
                "Mitigation": "Make sure you only enable the Spring Boot Actuator endpoints that you really need and restrict access to these endpoints."
            }
        }
    },
    "gitleaks": {
        "VERSION": "8.21.1",
        "EXCLUDE_PATH": [".git"],
        "NUMBER_THREADS": 4,
        "ALLOW_IGNORE_LEAKS": false,
        "ENABLE_CUSTOM_RULES" : false,
        "EXTERNAL_DIR_OWNER": "ExternalOrg",
        "EXTERNAL_DIR_REPOSITORY": "DevSecOps_Checks",
        "APP_ID_GITHUB":"",
        "INSTALLATION_ID_GITHUB":"",
        "USE_EXTERNAL_CHECKS_GIT": false,
        "USE_EXTERNAL_CHECKS_DIR": false
    }
}
```


### Exclusions

> /engine_sast/engine_secret/Exclusions.json
#### **By Component**

The key for each element in the JSON is the name of the build pipeline. It can be composed of the following properties:
 > TOOL:
  - id: Rule ID
  - where: all or file path to be excluded
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - severity: Severity of the finding
  - hu: User Story identifier supporting the configured exception.
 
 > SKIP_TOOL
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - hu: User Story identifier supporting the configured exception.

 > THRESHOLD
  - VULNERABILITY: new defined levels (Critical,High,Medium,Low)
  - Compliance: new defined levels (Critical)
  - CVE: List of CVEs
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - reason: reason for the threshold exclusion
  - hu: User Story identifier supporting the configured exception.



```json
{
    "NU0000_Build_Proof": {
      "TRUFFLEHOG": [
        {
          "id": "SECRET_SCANNING",
          "where": "ruta-secreto",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704"
        }
      ]
    },
    "NU0000_Build_Proof_MR_ms_proof": {
      "TRUFFLEHOG": [
        {
          "id": "SECRET_SCANNING",
          "where": "azure_api/secretos_azure_api.txt",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704"
        }
      ]
    },
    "NU0000_Build_Proof_skip": {
      "SKIP_TOOL": {
          "create_date": "24012024",
          "expired_date": "30012024",
          "hu": "3423213"
        },
    },
    "NU0000_Build_Proof_THRESHOLD": {
      "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 50,
            "High": 50,
            "Medium": 8,
            "Low": 15
        },
        "CVE": [],
        "create_date": "26092024",
        "expired_date": "30062025",
        "hu": "123122"
      }
    }
}
```


#### **By All Policy**

The key of the element in the JSON is All. It can be composed of the following properties:

> TOOL:
  - id: Rule ID
  - where: all or file path to be excluded
  - create_date: creation date (daymonthyear)
  - expired_date: expiration date (daymonthyear)
  - severity: Severity of the finding
  - hu: User Story identifier supporting the configured exception.
  - reason: Reason for the exception (False Positive)



```json
{
    "All": {
      "TRUFFLEHOG": [
        {
          "id": "SECRET_SCANNING",
          "where": "keys_test.txt",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704",
          "reason": "False Positive"
        }
      ]
    }
}
```


#### **By BY_PATTERN_SEARCH Policy**

The key of the element in the JSON is the regex. It can be composed of the following properties:

> REGEX:
  - THRESHOLD: Rule ID
    - VULNERABILITY: new defined levels (Critical,High,Medium,Low)
    - Compliance: new defined levels (Critical)
    - CVE: List of CVEs
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - reason: reason for the threshold exclusion
    - hu: User Story identifier supporting the configured exception.



```json
{
    "BY_PATTERN_SEARCH": {
        "*_(?i:migration).*": {
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 99,
                    "High": 99,
                    "Medium": 99,
                    "Low": 99
                },
                "create_date": "10092024",
                "expired_date": "31122025",
                "reason": "Migration",
                "hu": "123123"
            }
        }
    }
}
```

## **engine_sca/engine_container**


Container Security Analysis (CSA) is a practice focused on ensuring the integrity, confidentiality, and availability of container-based applications, promoting a security culture from the early stages of development through deployment and production operations.

### Configuration

> /engine_sca/engine_container/ConfigTool.json
```json
{
    "PRISMA_CLOUD": {
        "TWISTCLI_PATH": "twistcli",
        "PRISMA_CONSOLE_URL": "",
        "PRISMA_API_VERSION": "",
        "SBOM_FORMAT": "cyclonedx_json"
    },
    "TRIVY": {
        "TRIVY_VERSION": "0.62.1",
        "SBOM_FORMAT": "cyclonedx"
    },
    "SBOM": {
        "ENABLED": false,
        "BRANCH_FILTER": [
            "trunk",
            "main"
        ]
    },
    "GET_IMAGE_BASE": {
        "ENABLED": false,
        "BASE_IMAGE_LABELS": [
            "com.example.label1",
            "com.example.label2"
        ],
        "LABEL_KEYS": {
            "baseline_date": "x86.baseline.date",
            "specific_use": "evc/uso_especifico",
            "key_image_exception": "x86.image.name"
        }
    },
    "VALIDATE_BASE_IMAGE_DATE": {
        "ENABLED": false,
        "REFERENCE_IMAGE_DATE": "20250206"
        
    },
    "BLACK_LIST_BASE_IMAGE": {
        "ENABLED": false,
        "BLACK_LIST": [
            "/test/"
        ]
    },
    "MESSAGE_INFO_ENGINE_CONTAINER": "engine_container run successfully",
    "IGNORE_SEARCH_PATTERN": "(.*_demo0|.*_cer)",
    "REGEX_CLEAN_END_PIPELINE_NAME": "",
    "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 99,
            "High": 99,
            "Medium": 99,
            "Low": 999
        },
        "QUALITY_VULNERABILITY_MANAGEMENT": {
            "PTS": [
                {
                    "Product Type Name": {
                        "APPS": [
                            "CodeApp",
                            "CodeApp1",
                            "CodeApp12"
                        ],
                        "PROFILE": "STRONG"
                    }
                },
                {
                    "Product Type Name2": {
                        "APPS": "ALL",
                        "PROFILE": "MODERATE"
                    }
                }
            ],
            "STRONG": {
                "Critical": 0,
                "High": 0,
                "Medium": 5,
                "Low": 15
            },
            "MODERATE": {
                "Critical": 1,
                "High": 3,
                "Medium": 5,
                "Low": 15
            }
        },
        "COMPLIANCE": {
            "Critical": 1
        }
    }
}
```

### Exclusions

> /engine_sca/engine_container/Exclusions.json
#### **By Component**

The key for each element in the JSON is the name of the release pipeline. This can include the following properties:
 > TOOL:
    - id: CVE
    - where: all or the dependency to be excluded
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - severity: Severity of the finding
    - hu: User Story identifier supporting the configured exception.
 
 > SKIP_TOOL
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - hu: User Story identifier supporting the configured exception.

 > THRESHOLD
    - VULNERABILITY: new defined levels (Critical, High, Medium, Low)
    - Compliance: new defined levels (Critical)
    - CVE: List of CVEs
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - reason: reason for the threshold exclusion
    - hu: User Story identifier supporting the configured exception.

 > VALIDATE_BASE_IMAGE_DATE
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - hu: User Story identifier supporting the configured exception.


```json
{
    "NU0000_Build_Proof": {
      "SKIP_TOOL": {
        "create_date": "24012024",
        "expired_date": "30012024",
        "hu": "3423213"
      },
      "PRISMA": [
        {
          "id": "CVE-2024-637",
          "where": "busy:2.1",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704"
        }
      ]
    },
    "NU0429001_Release_Date_Proof": {
    "VALIDATE_BASE_IMAGE_DATE": {
      "create_date": "21022024",
      "expired_date": "26052024",
      "hu": "2342342"
     }
     },
    "NU0000_Build_Proof_MR_ms_proof": {
      "PRISMA": [
        {
          "id": "CVE-2023-1221",
          "where": "all",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704"
        }
      ]
    },
    "NU0000_Build_Proof_Skip": {
      "SKIP_TOOL": {
        "create_date": "24012024",
        "expired_date": "30012024",
        "hu": "3423213"
      }
    },
    "NU0000_Build_Proof_THRESHOLD": {
      "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 50,
            "High": 50,
            "Medium": 8,
            "Low": 15
        },
        "CVE": [],
        "create_date": "26092024",
        "expired_date": "30062025",
        "hu": "123122"
      }
    }
}
```

#### **By All Policy**

The key of the element in the JSON is All. It can include the following properties:

> TOOL:
    - id: CVE
    - where: all or file path to be excluded
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - severity: Severity of the finding
    - hu: User Story identifier supporting the configured exception.
    - reason: Reason for the exception (False Positive)



```json
{
    "All": {
      "PRISMA": [
        {
          "id": "CVE-2023-6378",
          "where": "all",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704",
          "reason": "False Positive"
        }
      ]
    }
}
```

#### **By BY_PATTERN_SEARCH Policy**

The key of the element in the JSON is the regex. It can include the following properties:

> REGEX:
    - THRESHOLD: Rule ID
        - VULNERABILITY: new defined levels (Critical, High, Medium, Low)
        - COMPLIANCE: new defined levels (Critical)
        - CVE: List of CVEs
        - create_date: creation date (daymonthyear)
        - expired_date: expiration date (daymonthyear)
        - reason: reason for the threshold exclusion
        - hu: User Story identifier supporting the configured exception.



```json
{
    "BY_PATTERN_SEARCH": {
        "*_(?i:migration).*": {
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 99,
                    "High": 99,
                    "Medium": 99,
                    "Low": 99
                },
                "create_date": "10092024",
                "expired_date": "31122025",
                "reason": "Migration",
                "hu": "123123"
            }
        }
    }
}
```

## **engine_sca/engine_dependencies**

Software Composition Analysis (SCA) is a process that detects compromised or vulnerable open-source components used in an application's source code. This automated process is part of Bancolombia's DevSecOps practices, through which security, code quality, and compliance are evaluated.

### Configuration

> /engine_sca/engine_dependencies/ConfigTool.json
```json
{
    "XRAY": {
        "CLI_VERSION": "2.55.0",
        "REGEX_EXPRESSION_EXTENSIONS": "\\.(jar|ear|war)$",
        "PACKAGES_TO_SCAN": ["node_modules", "site-packages"],
        "STDERR_EXPECTED_WORDS": ["Technology", "WorkingDirectory", "Descriptors"],
        "STDERR_BREAK_ERRORS": ["NoSuchFileException"],
        "STDERR_ACCEPTED_ERRORS": ["What went wrong", "Caused by"]
    },
    "IGNORE_ANALYSIS_PATTERN": "(.*_test)",
    "MESSAGE_INFO_ENGINE_DEPENDENCIES": "message custom",
    "IGNORE_FILES": ["wrapper.jar"],
    "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 3,
            "High": 5,
            "Medium": 10,
            "Low": 15
        },
        "COMPLIANCE": {
            "Critical": 1
        },
        "CVE": ["CVE-123123"]
    },
    "DEPENDENCY_CHECK": {
        "CLI_VERSION": "11.1.0",
        "REGEX_EXPRESSION_EXTENSIONS": "\\.(jar|ear|war)$",
        "PACKAGES_TO_SCAN": ["node_modules", "site-packages"],
        "VULNERABILITY_CONFIDENCE" : ["highest"]
    },
    "TRIVY": {
        "CLI_VERSION": "0.65.0"
    }
}
```

### Exclusions

> /engine_sca/engine_dependencies/Exclusions.json
#### **By Component**

The key for each element in the JSON is the name of the build pipeline. This can include the following properties:
 > TOOL:
    - id: Xray_Id
    - cve_id: CVE
    - where: all or dependency to be excluded
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - severity: Severity of the finding
    - hu: User Story identifier supporting the configured exception.
 
 > SKIP_TOOL
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - hu: User Story identifier supporting the configured exception.

 > SKIP_FILES
    - files: Array of file extensions to exclude
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - hu: User Story identifier supporting the configured exception.

 > THRESHOLD
    - VULNERABILITY: new defined levels (Critical, High, Medium, Low)
    - Compliance: new defined levels (Critical)
    - CVE: List of CVEs
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - reason: reason for the threshold exclusion
    - hu: User Story identifier supporting the configured exception.



```json
{
    "NU0000_Build_Proof": {
      "SKIP_TOOL": {
        "create_date": "24012024",
        "expired_date": "30012024",
        "hu": "3423213"
      },
      "XRAY": [
        {
          "id": "XRAY-113434",
          "cve_id": "CVE-2024-6378",
          "where": "busy:2.1",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704"
        }
      ]
    },
    "NU0000_Build_Proof_MR_ms_proof": {
      "XRAY": [
        {
          "id": "XRAY-113121",
          "cve_id": "CVE-2023-1221",
          "where": "all",
          "create_date": "18112023",
          "expired_date": "18032024",
          "severity": "HIGH",
          "hu": "4338704"
        }
      ]
    },
    "NU0000_Build_Proof_Skip": {
      "SKIP_TOOL": {
        "create_date": "24012024",
        "expired_date": "30012024",
        "hu": "3423213"
      }
    },
    "NU0000_Build_Proof_Skip_files": {
      "SKIP_FILES": {
            "files": [
                "ear"
            ],
            "create_date": "19022024",
            "expired_date": "undefined",
            "hu": "34121"
        }
    },
    "NU0000_Build_Proof_THRESHOLD": {
      "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 50,
            "High": 50,
            "Medium": 8,
            "Low": 15
        },
        "CVE": [],
        "create_date": "26092024",
        "expired_date": "30062025",
        "hu": "123122"
      }
    }
}
```

#### **By All Policy**

The key of the element in the JSON is All. It can include the following properties:

> TOOL:
    - id: Rule ID
    - where: all or file path to be excluded
    - cve_id: CVE
    - create_date: creation date (daymonthyear)
    - expired_date: expiration date (daymonthyear)
    - severity: Severity of the finding
    - hu: User Story identifier supporting the configured exception.
    - reason: Reason for the exception (False Positive)



```json
{
    "All": {
      "XRAY": [
        {
          "id": "XRAY-533052",
          "cve_id": "CVE-2023-6378",
          "create_date": "18112023",
          "expired_date": "18032024",
          "hu": "4338704",
          "reason": "False Positive"
        }
      ]
    }
}
```

#### **By BY_PATTERN_SEARCH Policy**

The key of the element in the JSON is the regex. It can include the following properties:

> REGEX:
    - THRESHOLD: Rule ID
        - VULNERABILITY: new defined levels (Critical, High, Medium, Low)
        - COMPLIANCE: new defined levels (Critical)
        - CVE: List of CVEs
        - create_date: creation date (daymonthyear)
        - expired_date: expiration date (daymonthyear)
        - reason: reason for the threshold exclusion
        - hu: User Story identifier supporting the configured exception.



```json
{
    "BY_PATTERN_SEARCH": {
        "*_(?i:migration).*": {
            "THRESHOLD": {
                "VULNERABILITY": {
                    "Critical": 99,
                    "High": 99,
                    "Medium": 99,
                    "Low": 99
                },
                "COMPLIANCE": {
                    "Critical": 99
                },
                "CVE": [],
                "create_date": "10092024",
                "expired_date": "31122025",
                "reason": "Migration",
                "hu": "123123"
            }
        }
    }
}
```

## **vulnerability_management/cmdb_mapping**

Mapping configuration for the names of the evcs obtained from the cmdb, to centralize a single name and have unified product types in Vulnerability Management.

 > types_product:
  - "CMDB Name" : "Unique product type name for Vulnerability Management"

> Example vulnerability_management/cmdb_mapping.json
```json
{
  "types_product": {
    "IT ARCHITECTURE": "PT1 - ARCHITECTURE",
    "SOFTWARE ENGINEERING": "PT2 - IT ENGINEERING"
  }
}
```