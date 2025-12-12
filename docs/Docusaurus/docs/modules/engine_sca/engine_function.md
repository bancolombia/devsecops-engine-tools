# Module Engine Function

## Overview

The `engine_function` module orchestrates Software Composition Analysis (SCA) for serverless functions packaged as .zip (e.g., AWS Lambda and Azure Functions) within the DevSecOps Engine Tools platform. It automates the execution of Prisma Cloud’s twistcli for serverless code, loads scan configuration, applies exclusions and thresholds, and normalizes results for risk analysis and reporting.

## Configuration Structure

The module is configured through two main JSON files located in `example_remote_config_local/engine_sca/engine_function/`:

### ConfigTool.json

Main configuration file that defines scanning behavior, tool versions, and security policies.

```json
{
  "PRISMA_CLOUD": {
    "PRISMA_CONSOLE_URL": "https://<tu-prisma-console>",
    "PRISMA_API_VERSION": "v1",
    "TWISTCLI_PATH": "twistcli.exe"
  },
  "IGNORE_SEARCH_PATTERN": "(.*_legacy|.*_skip)",     
  "MESSAGE_INFO_ENGINE_FUNCTION": "message custom",
  "THRESHOLD": {
    "VULNERABILITY": {
      "Critical": 1,
      "High": 3,
      "Medium": 10,
      "Low": 999
    },
    "COMPLIANCE": {
      "Critical": 1
    },
    "CVE": ["CVE-2024-0001"],
    "PRIORITY": {
        "Very Critical": 1,
        "Critical": 3,
        "High": 10,
        "Medium Low": 999
    }
  }
}
```

#### Configuration Parameters

**PRISMA_CLOUD**: Configuration for Prisma Cloud integration
- **PRISMA_CONSOLE_URL**: Prisma Cloud console URL (e.g., `"https://console.prismacloud.io"`)
- **PRISMA_API_VERSION**: Prisma Cloud API version to use (e.g., `"v1"`)
- **TWISTCLI_PATH**: Local path to twistcli executable (e.g., `"twistcli.exe"`)

**IGNORE_SEARCH_PATTERN**: Regex pattern to ignore specific functions during scanning
- Defines functions that should be excluded from analysis
- Example: `"(.*_legacy|.*_skip)"` will ignore functions ending with `_legacy` or `_skip`

**MESSAGE_INFO_ENGINE_FUNCTION**: Custom message for engine information
- Allows configuration of context-specific informational messages

**THRESHOLD**: Security threshold configuration
- **VULNERABILITY**: Limits by vulnerability severity
  - `Critical`: Maximum number of critical vulnerabilities allowed
  - `High`: Maximum number of high vulnerabilities allowed
  - `Medium`: Maximum number of medium vulnerabilities allowed
  - `Low`: Maximum number of low vulnerabilities allowed
- **COMPLIANCE**: Limits for compliance issues
  - `Critical`: Maximum number of critical compliance issues
- **CVE**: List of specific CVEs to ignore or prioritize
- **PRIORITY**: Limits by vulnerability priority
  - `Very Critical`: Maximum number of very critical vulnerabilities allowed
  - `Critical`: Maximum number of critical vulnerabilities allowed
  - `High`: Maximum number of hihg vulnerabilities allowed
  - `Medium Low`: Maximum number of medium low vulnerabilities allowed

### Exclusions.json

File that defines specific exclusions by tool and repository for function analysis.

```json
{
  "All": {
    "PRISMA": [
      {
        "id": "",
        "where": "all",
        "create_date": "24012023",
        "expired_date": "22092023",
        "hu": "345345",
        "reason": "False Positive"
      }
    ]
  },
  "Repository_Test": {
    "VALIDATE_BASE_IMAGE_DATE": {
      "create_date": "21022024",
      "expired_date": "26052024",
      "hu": "2342342"
    },
    "BLACK_LIST_BASE_IMAGE": {
      "create_date": "21022024",
      "expired_date": "26052024",
      "hu": "2342342"
    },
    "PRISMA": [
      {
        "id": "CVE-2023-6237",
        "cve_id": "CVE-2023-6237",
        "expired_date": "21092024",
        "create_date": "24012023",
        "hu": "345345"
      }
    ]
  }
}
```

#### Exclusion Structure

**Global Exclusions (`All`)**: Applicable to all repositories
- **PRISMA**: Prisma Cloud specific exclusions
  - `id`: Unique identifier for the exclusion
  - `where`: Scope of application (`"all"` for global)
  - `create_date`: Creation date of the exclusion
  - `expired_date`: Expiration date of the exclusion
  - `hu`: User story or reference ticket
  - `reason`: Justification for the exclusion

**Repository-specific Exclusions**: Specific to particular repositories
- **VALIDATE_BASE_IMAGE_DATE**: Temporary exclusion for base image date validation
- **BLACK_LIST_BASE_IMAGE**: Exclusion for blacklisted base images
- **PRISMA**: Prisma Cloud specific exclusions by CVE
  - `cve_id`: CVE identifier to exclude
  - Same metadata fields as global exclusions

## Main Responsibilities

- **Serverless SCA Orchestration:** Runs Prisma Cloud twistcli serverless scan over function ZIP artifacts.
- **Configuration Management:** Loads tool settings, thresholds, and policies from remote configuration (or local examples).
- **Artifact Discovery:** Finds *.zip function packages in the provided folder_path.
- **Exclusions & Thresholds:** Applies per-pipeline and global exclusions (Exclusions.json) and evaluates thresholds to support build-break decisions in the core.
- **Result Processing:** Parses twistcli output to extract vulnerability and compliance distributions and CVE tables.
- **CI/CD Integration:** Works with Azure DevOps/GitHub environments via predefined variables and messaging helpers.

## Key Components

- **src/applications/runner_function_scan.py**
Entry point used by the core to start the Function SCA workflow (parses args, delegates to the use case).

- **src/infrastructure/entry_points/entry_point_function.py**
Bootstraps the module and returns (findings, input_core) to the engine core.

- **src/domain/usecases/function_scan.py**
Core use case: loads config (ConfigTool.json), checks exclusions (Exclusions.json), prepares input, and dispatches the scan.

- **Adapters**

- **src/infrastructure/driven_adapters/prisma_cloud/prisma_cloud_manager_scan.py**
Wrapper around twistcli serverless scan (download, execution, stdout parsing).

## Supported Tools and Features

- **Prisma Cloud (twistcli):** Downloads twistcli from Prisma Console via API.
- **Scans function ZIP:** Detects Vulnerability distribution: total/critical/high/medium/low.
- **Configurable Exclusions:** Supports exclusion of vulnerabilities and custom ignore patterns.
- **Thresholds and Policies:** Handles custom thresholds and build-breaking policies.

## Example Usage

Typically invoked by the engine core in CI:

```sh
devsecops-engine-tools \
  --platform_devops azure \
  --remote_config_source azure \
  --remote_config_repo <your-remote-config-repo> \
  --module engine_function \
  --tool prisma \
  --folder_path path/to/functions_zip_dir \
  --use_secrets_manager false \
  --use_vulnerability_management false \
  --send_metrics false

```

## Extensibility

- Add new serverless scanners by implementing a new adapter under driven_adapters/tool/ and wiring it in function_scan.py.
- Extend result parsing (e.g., additional compliance frameworks) by enhancing the parser and mapping to the engine’s finding model.

## Testing

Unit tests are located under the `test/` directory, covering:

- Orchestration workflow validation.
- Configuration loading (`ConfigTool.json`).
- Exclusion and threshold handling.
- Result processing.

---
