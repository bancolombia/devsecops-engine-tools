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
    "TRACEBACK": false,
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
            "GET_EXACT_PRODUCT": false,
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
            "REGEX_EXPRESSION_CODE_APP": "",
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
    "LICENSE_ANALYZER": {
        "TOOL": "DEPENDENCY_TRACK",
        "DEPENDENCY_TRACK": {
            "HOST": "",
            "API_KEY_SECRET_KEY": "",
            "EXPORT_TASK_ID": false,
            "TASK_ID_VARIABLE_NAME": ""
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
            "OUTPUT_FORMAT": "cyclonedx-json",
            "EXCLUDE_PATHS": ["**/test/**", "**/node_modules/**"],
            "EXCLUDE_CATALOGERS": [],
            "DEBUG_PIPELINES": ["pipeline_name1", "pipeline_name2"]
        },
        "CDXGEN": {
            "CDXGEN_VERSION": "11.7.0",
            "OUTPUT_FORMAT": "cyclonedx-json",
            "SLIM_BINARY": true,
            "FETCH_LICENSE": false,
            "SPEC_VERSION": "1.6",
            "EXCLUDE_TYPES": ["jar"],
            "EXCLUDE_PATHS": ["**/test/**"],
            "RECURSE": true,
            "INSTALL_DEPENDENCIES": true,
            "DEBUG_PIPELINES": ["pipeline_name1", "pipeline_name2"],
            "REQUIRED_ONLY_PIPELINES": ["pipeline_name1", "pipeline_name2"],
            "BREAK_ON_BUILD_FAILURE": true,
            "BUILD_FAILURE_PATTERNS": ["BUILD FAILED", "BUILD FAILURE", "npm ERR!"],
            "OVERRIDE_REGISTRIES": false,
            "REGISTRIES": {
                "MAVEN_CENTRAL_URL": "",
                "NPM_URL": "",
                "PYPI_URL": "",
                "NUGET_URL": ""
            }
        }
    },
    "PRIORITY_MANAGER":{
        "USE_PRIORITY": true,
        "HOST_PRIORITY": "",
        "CVE_REGEX": "CVE-\\d{4}-\\d+",
        "MAX_RETRIES":3,
        "HOMOLOGATION_PRIORITY":{
            "STANDARD": {
                "critical":{
                    "SCORE": 1.00,
                    "CLASSIFICATION": "very critical"
                },
                "high":{
                    "SCORE": 0.74,
                    "CLASSIFICATION": "critical"
                },
                "medium":{
                    "SCORE": 0.46,
                    "CLASSIFICATION": "high"
                },
                "low":{
                    "SCORE": 0.01,
                    "CLASSIFICATION": "medium low"
                }
            },
            "DISCREET":{
                "critical":{
                    "SCORE": 0.74,
                    "CLASSIFICATION": "critical"
                },
                "high":{
                    "SCORE": 0.46,
                    "CLASSIFICATION": "high"
                },
                "medium":{
                    "SCORE": 0.01,
                    "CLASSIFICATION": "medium low"
                },
                "low":{
                    "SCORE": 0.01,
                    "CLASSIFICATION": "medium low"
                }
            }
        },
        "MAPPING_HOST":{
            "Muy Crítica": "very critical",
            "Crítica": "critical",
            "Alta": "high",
            "Baja y Media": "medium low"
        }
    },
    "BREAK_BUILD_MANAGER":{
        "MODEL": "severity|priority",
        "CLASSIFICATION": ["critical|very critical", "high|critical", "medium|high", "low|medium low"]
    },
    "ENGINE_IAC": {
        "ENABLED": true,
        "TOOL": "CHECKOV|KUBESCAPE|KICS|CONFTEST",
        "PRIORITY": "STANDARD|DISCREET"
    },
    "ENGINE_CONTAINER": {
        "ENABLED": true,
        "TOOL": "PRISMA|TRIVY",
        "PRIORITY": "STANDARD|DISCREET"
    },
    "ENGINE_DAST": {
        "ENABLED": true,
        "TOOL": "NUCLEI",
        "EXTRA_TOOLS": ["JWT"],
        "PRIORITY": "STANDARD|DISCREET"
    },
    "ENGINE_SECRET": {
        "ENABLED": true,
        "TOOL": "TRUFFLEHOG|GITLEAKS|ALL_TOOLS",
        "PRIORITY": "STANDARD|DISCREET"
    },
    "ENGINE_DEPENDENCIES": {
        "ENABLED": true,
        "TOOL": "XRAY|DEPENDENCY_CHECK|TRIVY",
        "PRIORITY": "STANDARD|DISCREET"
    },
    "ENGINE_CODE": {
        "ENABLED": true,
        "TOOL": "BEARER|KIUWAN",
        "PRIORITY": "STANDARD|DISCREET"
    },
    "ENGINE_FUNCTION": {
        "ENABLED": true,
        "TOOL": "PRISMA",
        "PRIORITY": "STANDARD|DISCREET"
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
- **TRACEBACK**: Show the traceback if there are any error in the execution
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
        - GET_EXACT_PRODUCT: optional flag. Ensure product get from defect dojo before request is exact match otherwise use default behavior include match
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
        - **REGEX_EXPRESSION_CODE_APP**: Regular expression used to extract code app from component
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

- **LICENSE_ANALYZER**: Configuration for the license analysis integration (beta). Uploads the generated SBOM to a license analyzer tool to inspect component licenses. Activated via the `--use_license_analyzer true` CLI flag. Only runs if `SBOM_MANAGER.ENABLED` is `true` for the current branch.
    - **TOOL**: License analyzer adapter to use. Currently supported: `DEPENDENCY_TRACK`.
    - **DEPENDENCY_TRACK**
        - **HOST**: Base URL of the Dependency-Track server (e.g., `https://dtrack.example.com`).
        - **API_KEY_SECRET_KEY**: Name of the secret key in the secrets manager that holds the Dependency-Track API key. If no secrets manager is used, pass the token via `--token_license_analyzer` CLI argument.
        - **EXPORT_TASK_ID**: `true` or `false`. When enabled, the upload task token returned by Dependency-Track is exported as a pipeline variable, allowing downstream jobs to poll for analysis results.
        - **TASK_ID_VARIABLE_NAME**: Name of the pipeline variable where the task token will be stored (only used when `EXPORT_TASK_ID` is `true`).

- **SBOM_MANAGER**: Configuration for SBOM generation. Requires `ENABLED: true` and the `--use_license_analyzer true` CLI flag for the license analyzer to run. Additionally, `CDXGEN.FETCH_LICENSE` should be set to `true` to enrich the SBOM with license metadata before uploading to the license analyzer.
    - **SYFT**
        - **SYFT_VERSION**: Version of Syft to download and use. Example: `"1.17.0"`.
        - **OUTPUT_FORMAT**: Output format for the SBOM. Default: `"cyclonedx-json"`. Other options include `"spdx-json"`, `"syft-json"`, `"table"`.
        - **EXCLUDE_PATHS**: Array of glob patterns to exclude directories/files from analysis. Example: `["**/test/**", "**/node_modules/**"]`. Useful for skipping test files, build artifacts, or vendor directories.
        - **EXCLUDE_CATALOGERS**: Array of cataloger names to exclude from the default set. Catalogers are specialized modules that detect specific package types (e.g., `"java-archive-cataloger"`, `"python-package-cataloger"`). When specified, Syft uses `--select-catalogers -NAME` to remove these catalogers from analysis. Example: `["java-archive-cataloger", "binary-cataloger"]`.
        - **DEBUG_PIPELINES**: Array of pipeline names where Syft should run in verbose mode (`-v` flag). Useful for troubleshooting SBOM generation issues in specific pipelines. Example: `["pipeline_name1", "pipeline_name2"]`.
                
    - **CDXGEN**
        - **FETCH_LICENSE**: `true` or `false`. When enabled, cdxgen fetches license information for each component from public registries and includes it in the generated SBOM. Recommended when `--use_license_analyzer true` is used.
        - **INSTALL_DEPENDENCIES**: `true` or `false`. When enabled, cdxgen installs project dependencies before generating the SBOM, improving component coverage.
        - **BREAK_ON_BUILD_FAILURE**: `true` or `false` (default `true`). cdxgen can exit with return code `0` even when the underlying build tool actually failed, silently producing an incomplete/empty SBOM. When enabled, the stdout/stderr of the cdxgen process is checked against `BUILD_FAILURE_PATTERNS` and, if any pattern matches, the SBOM generation is aborted and the error is logged so the affected pipeline is easy to spot.
        - **BUILD_FAILURE_PATTERNS**: Array of regular expressions (case-insensitive) used to detect build failures in the cdxgen output. There are no built-in defaults; patterns must be defined entirely via remote config for the languages/build tools relevant to your pipelines. Example: `["BUILD FAILED", "BUILD FAILURE", "npm ERR!"]`.
        - **OVERRIDE_REGISTRIES**: `true` or `false`. When enabled, the registry URLs defined in `REGISTRIES` are set as environment variables before cdxgen runs, redirecting dependency resolution to internal or private registries.
        - **REGISTRIES**: Map of environment variable names to registry URLs used when `OVERRIDE_REGISTRIES` is `true`.
            - **MAVEN_CENTRAL_URL**: Maven registry URL.
            - **NPM_URL**: npm registry URL.
            - **PYPI_URL**: PyPI registry URL.
            - **NUGET_URL**: NuGet registry URL.

- **PRIORITY_MANAGER**: Configuración para el manejo de prioridades basadas en scores de vulnerabilidades CVE
    - **USE_PRIORITY**: `true` o `false`. Habilita el uso del sistema de prioridades. Cuando está en `true`, el sistema consultará un API externo para obtener scores de prioridad de CVEs y aplicará homologación para findings sin formato CVE.
    - **HOST_PRIORITY**: URL del API externo que proporciona los scores de prioridad para CVEs. Ejemplo: `https://api.example.com/priorities`
    - **CVE_REGEX**: Expresión regular para identificar CVEs en los IDs de findings. Por defecto: `"CVE-\\d{4}-\\d+"`
    - **MAX_RETRIES**: Specifies the maximum number of retry attempts allowed for a given operation
    - **HOMOLOGATION_PRIORITY**: Mapeo de severidades tradicionales a prioridades con scores. Permite dos perfiles:
        - **STANDARD**: Perfil estándar con scores más altos
            - `critical`: score 1.00 → "very critical"
            - `high`: score 0.74 → "critical"
            - `medium`: score 0.46 → "high"
            - `low`: score 0.01 → "medium low"
        - **DISCREET**: Perfil discreto con scores más conservadores
            - `critical`: score 0.74 → "critical"
            - `high`: score 0.46 → "high"
            - `medium`: score 0.01 → "medium low"
            - `low`: score 0.01 → "medium low"
    - **MAPPING_HOST**: Mapeo de clasificaciones del API externo a escalas internas
        - `"Muy Crítica"` → `"very critical"`
        - `"Crítica"` → `"critical"`
        - `"Alta"` → `"high"`
        - `"Baja y Media"` → `"medium low"`

- **BREAK_BUILD_MANAGER**: Configuración para el sistema de ruptura de build basado en severidad o prioridad
    - **MODEL**: Define el modelo de evaluación a utilizar
        - `"severity"`: Usa el modelo tradicional basado en severidades (critical, high, medium, low)
        - `"priority"`: Usa el modelo basado en scores de prioridad (very critical, critical, high, medium low)
    - **CLASSIFICATION**: Array con las clasificaciones a evaluar, en orden de mayor a menor criticidad
        - Para `MODEL="severity"`: `["critical", "high", "medium", "low"]`
        - Para `MODEL="priority"`: `["very critical", "critical", "high", "medium low"]`
    
    **Nota**: El modelo seleccionado determina:
    - Qué campo del finding se usa para clasificación (`severity` vs `priority.scale`)
    - Qué atributos de threshold se consultan (`vulnerability.critical` vs `vulnerability.get_level("very critical", "priority")`)
    - Cómo se muestran los resultados en tablas y mensajes de error/warning

- **ENGINE_IAC**: Configuration for the engine_iac tool
    - ENABLED: true or false
    - TOOL: CHECKOV |KUBESCAPE | KICS
    - PRIORITY: STANDARD | DISCREET

- **ENGINE_CONTAINER**: Configuration for the engine_container tool
    - ENABLED: true or false
    - TOOL: PRISMA | TRIVY
    - PRIORITY: STANDARD | DISCREET

- **ENGINE_DAST**: Configuration for the engine_dast tool
    - ENABLED: true or false
    - TOOL: NUCLEI
    - PRIORITY: STANDARD | DISCREET

- **ENGINE_SECRET**: Configuration for the engine_secret tool
    - ENABLED: true or false
    - TOOL: TRUFFLEHOG | GITLEAKS
    - PRIORITY: STANDARD | DISCREET

- **ENGINE_CODE**: Configuration for the engine_code tool
    - ENABLED: true or false
    - TOOL: BEARER
    - PRIORITY: STANDARD | DISCREET

- **ENGINE_DEPENDENCIES**: Configuration for the engine_dependencies tool
    - ENABLED: true or false
    - TOOL: XRAY | DEPENDENCY_CHECK | TRIVY
    - PRIORITY: STANDARD | DISCREET

- **ENGINE_FUNCTION**: Configuration for the engine_function tool
    - ENABLED: true or false
    - TOOL: PRISMA
    - PRIORITY: STANDARD | DISCREET

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
    "REGEX_EXPRESSION_CODE_APP": "^([^-]+)",
    "REIMPORT_SCAN": false,
    "CMDB": {
        "USE_CMDB": true,
        "HOST_CMDB": "http://host_cmdb_example",
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
        "REGEX_EXPRESSION_CODE_APP": "^([^-]+)",
        "REIMPORT_SCAN": false,
        "CMDB": {
            "USE_CMDB": false
        }
    }
```

## Ejemplos de Configuración

### Ejemplo 1: Modelo Severity (Tradicional)

```json
{
    "BREAK_BUILD_MANAGER": {
        "MODEL": "severity",
        "CLASSIFICATION": ["critical", "high", "medium", "low"]
    },
    "PRIORITY_MANAGER": {
        "USE_PRIORITY": false
    },
    "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 5,
            "High": 10,
            "Medium": 20,
            "Low": 30
        }
    }
}
```

En este caso:
- El build se romperá si hay ≥5 vulnerabilidades críticas, ≥10 high, ≥20 medium o ≥30 low
- Se usa el campo `severity` de los findings
- No se consulta API externa de prioridades

### Ejemplo 2: Modelo Priority con API Externa

```json
{
    "BREAK_BUILD_MANAGER": {
        "MODEL": "priority",
        "CLASSIFICATION": ["very critical", "critical", "high", "medium low"]
    },
    "PRIORITY_MANAGER": {
        "USE_PRIORITY": true,
        "HOST_PRIORITY": "https://api.priorities.internal/v1",
        "CVE_REGEX": "CVE-\\d{4}-\\d+",
        "HOMOLOGATION_PRIORITY": {
            "STANDARD": {
                "critical": {
                    "SCORE": 1.00,
                    "CLASSIFICATION": "very critical"
                },
                "high": {
                    "SCORE": 0.74,
                    "CLASSIFICATION": "critical"
                },
                "medium": {
                    "SCORE": 0.46,
                    "CLASSIFICATION": "high"
                },
                "low": {
                    "SCORE": 0.01,
                    "CLASSIFICATION": "medium low"
                }
            }
        },
        "MAPPING_HOST": {
            "Muy Crítica": "very critical",
            "Crítica": "critical",
            "Alta": "high",
            "Baja y Media": "medium low"
        }
    },
    "THRESHOLD": {
        "VULNERABILITY": {
            "Critical": 5,
            "High": 10,
            "Medium": 20,
            "Low": 30
        },
        "VULNERABILITY_PRIORITY": {
            "Very Critical": 3,
            "Critical": 5,
            "High": 10,
            "Medium Low": 20
        }
    }
}
```

En este caso:
- Los CVEs se envían al API externa para obtener scores de prioridad
- Los findings sin formato CVE se homologan por severidad usando `HOMOLOGATION_PRIORITY`
- El build se romperá según los umbrales de `VULNERABILITY_PRIORITY`
- Se usa el campo `priority.scale` de los findings

### Ejemplo 3: Threshold con Exclusiones

```json
{
    "THRESHOLD": {
        "my-pipeline": {
            "VULNERABILITY": {
                "Critical": 0,
                "High": 2,
                "Medium": 10,
                "Low": 50
            },
            "VULNERABILITY_PRIORITY": {
                "Very Critical": 0,
                "Critical": 1,
                "High": 5,
                "Medium Low": 20
            },
            "reason": "Pipeline crítico con umbrales más estrictos"
        }
    }
}
```

Los umbrales se pueden personalizar por pipeline específico o por patrón regex.

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

## Remote Config Environment Variables

These variables are used to resolve authentication and repository context when loading remote configuration files.

```bash
DET_REMOTE_ORG="my-azure-organization"
DET_REMOTE_PROJ="my-azure-project"
DET_REMOTE_TOKEN="***"
DET_GITHUB_REPOSITORY="owner/repository"
```

- **DET_REMOTE_ORG**
    - **Use:** Azure DevOps organization used to build the remote config URL.
    - **Applies to:** `--remote_config_source azure`.
    - **Fallback if missing:** `System.TeamFoundationCollectionUri`.

- **DET_REMOTE_PROJ**
    - **Use:** Azure DevOps project used in the remote config URL path.
    - **Applies to:** `--remote_config_source azure`.
    - **Fallback if missing:** `System.TeamProject`.

- **DET_REMOTE_TOKEN**
    - **Use:** Token to authenticate against the remote config source.
    - **Applies to:** `--remote_config_source azure` and `--remote_config_source github`.
    - **Fallback if missing:**
        - Azure: `System.AccessToken`.
        - GitHub: `github.access.token`.

- **DET_GITHUB_REPOSITORY**
    - **Use:** GitHub repository context used to resolve owner/repository (accepts `owner/repo` or full GitHub URL).
    - **Applies to:** `--remote_config_source github`.
    - **Fallback if missing:** `github.repository`.

## Extensibility

- New tools and modules can be added by extending the adapters and use cases.
- Integrations with new platforms or reporting systems can be implemented via the infrastructure layer.

## Testing

- Unit tests are provided in the `test/` directory, covering core logic and CLI argument parsing.


