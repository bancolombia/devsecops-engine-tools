---
sidebar_position: 2
---

# Module Engine DAST

## Overview

The `engine_dast` module is responsible for orchestrating Dynamic Application Security Testing (DAST) within the DevSecOps Engine Tools platform. It automates the execution of DAST tools, processes scan configurations, manages authentication flows, and integrates results for further risk analysis and reporting.

## Configuration Structure

The module is configured through two main JSON files located in `example_remote_config_local/engine_dast/`:

### ConfigTool.json

Main configuration file that defines scanning behavior, tool versions, and security policies.

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
    },
    "PRIORITY": {
        "Very Critical": 1,
        "Critical": 8,
        "High": 10,
        "Medium Low": 15
    }
  },
  "MESSAGE_INFO_DAST": "If you have doubts, visit https://forum.example",
  "IGNORE_ERRORS": false,
  "PRINT_API_CONFIG": true,
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
        "environment": {
          "dev": "True",
          "pdn": "True",
          "qa": "True"
        },
        "guideline": "https://example.com/",
        "severity": "Low",
        "cvss": "",
        "category": "Vulnerability"
      }
    }
  }
}
```

#### Configuration Parameters

##### Threshold Configuration
- **VULNERABILITY**: Maximum allowed vulnerabilities by severity level:
  - `Critical`: Maximum 1 critical vulnerability (strict control)
  - `High`: Maximum 8 high severity vulnerabilities
  - `Medium`: Maximum 10 medium severity vulnerabilities
  - `Low`: Maximum 15 low severity vulnerabilities
- **COMPLIANCE**: Compliance issue limits:
  - `Critical`: Maximum 1 critical compliance issue
- **PRIORITY**: Maximum allowed vulnerabilities by priority level:
  - `Very Critical`: Maximum 1 very critical priority vulnerability (strict control)
  - `Critical`: Maximum 8 critical priority vulnerabilities
  - `High`: Maximum 10 high priority vulnerabilities
  - `Medium Low`: Maximum 15 medium low priority vulnerabilities

##### General Configuration
- **MESSAGE_INFO_DAST**: Custom informational message displayed during DAST execution (e.g., forum links for support)
- **IGNORE_ERRORS**: Boolean flag to control error handling behavior during scanning
- **PRINT_API_CONFIG**: Boolean flag to enable/disable API configuration output for debugging

##### Nuclei Tool Configuration
- **VERSION**: Nuclei scanner version to use (e.g., `"3.3.5"`)
- **DOWNLOAD_URL**: Base URL for downloading Nuclei releases from GitHub
- **Performance Settings**:
  - `CONCURRENCY`: Number of concurrent requests (e.g., `1` for sequential scanning)
  - `RESPONSE_SIZE`: Maximum response size in KB to process (e.g., `256`)
  - `BULK_SIZE`: Number of targets to process in bulk (e.g., `1`)
  - `TIMEOUT`: Request timeout in seconds (e.g., `10`)
- **Installation Configuration**:
  - `BINARY_PATH`: Directory path where Nuclei binary will be installed
- **External Rules Configuration**:
  - `USE_EXTERNAL_CHECKS_GIT`: Enable external templates from Git repository
  - `USE_EXTERNAL_CHECKS_DIR`: Enable external templates from directory
  - `EXTERNAL_DIR_OWNER`: GitHub username/organization for external templates
  - `EXTERNAL_DIR_REPOSITORY`: Repository name containing custom templates
  - `APP_ID_GITHUB`: GitHub App ID for authentication
  - `INSTALLATION_ID_GITHUB`: GitHub App installation ID
  - `ENABLE_CUSTOM_RULES`: Boolean flag to enable custom rule processing

##### JWT Security Rules Configuration
- **RULES**: Custom security rules for JWT token analysis
- **Rule Structure**: Each JWT rule contains:
  - `checkID`: Unique identifier for the security check (e.g., `"ENGINE_JWT_001"`)
  - `environment`: Environment-specific enablement flags:
    - `dev`: Enable in development environment
    - `pdn`: Enable in production environment  
    - `qa`: Enable in QA environment
  - `guideline`: URL to security guideline documentation
  - `severity`: Risk level (`"Critical"`, `"High"`, `"Medium"`, `"Low"`)
  - `cvss`: CVSS score (if applicable)
  - `category`: Rule category (`"Vulnerability"`, `"Compliance"`)

### Exclusions.json

Defines exclusion rules for repositories and specific DAST findings.

#### Structure
```json
{
  "All": {
    "JWT": [
      {
        "id": "ENGINE_JWT_001",
        "where": "all",
        "create_date": "18112023",
        "expired_date": "18032024",
        "severity": "HIGH",
        "hu": "4338704"
      }
    ]
  }
}
```

#### Exclusion Types
- **All**: Global exclusions applied to all repositories
- **Repository-specific**: Exclusions for specific repositories (can be added as needed)
- **Tool-specific exclusions**: Organized by scanning tool/feature:
  - `JWT`: Exclusions for JWT-related findings
  - `NUCLEI`: Exclusions for Nuclei scanner findings (if needed)

#### Exclusion Fields
Each exclusion entry contains:
- `id`: Security rule identifier matching the checkID from configuration
- `where`: Scope of exclusion (`"all"` for global or specific endpoint/path)
- `create_date`: Date when exclusion was created (format: DDMMYYYY)
- `expired_date`: Expiration date for the exclusion (format: DDMMYYYY)
- `severity`: Original severity level of the excluded finding
- `hu`: Human user identifier for audit trail

## Main Responsibilities

- **DAST Orchestration:** Executes DAST tools (Nuclei) against APIs and web applications with configurable performance settings
- **Configuration Management:** Loads and processes scan configurations from JSON files with support for external templates
- **Authentication Handling:** Supports multiple authentication mechanisms (JWT, OAuth, client credentials) for API and web application testing
- **Integration:** Connects with external systems and the core engine for configuration, secrets, and result management
- **Result Processing:** Aggregates and normalizes findings for risk evaluation and reporting
- **Threshold Enforcement:** Validates findings against configured vulnerability and compliance thresholds
- **Custom Rules Management:** Supports external templates and custom security rules from GitHub repositories
- **JWT Security Analysis:** Specialized analysis of JWT token security configurations

## Key Components

- `runner_dast_scan.py`: Main entry point for DAST scan orchestration
- `entry_point_dast.py`: Initializes the DAST engine and triggers the scan process
- `dast_scan.py`: Core use case for executing the scan, handling configuration, exclusions, and result aggregation
- **Adapters:** Integrations for tools (Nuclei), authentication (JWT, OAuth), and HTTP clients
- **Models:** Represent API/WebApp configurations and operations

## Supported Tools and Features

- **Nuclei:** Advanced DAST scanning with configurable performance, external templates, and custom rules
- **Authentication:** JWT, OAuth, and client credentials supported for authenticated scans
- **GitHub Integration:** External template repositories via GitHub Apps authentication
- **Performance Tuning:** Configurable concurrency, timeouts, and response size limits
- **Custom Security Rules:** JWT token analysis and custom vulnerability detection
- **Configurable Targets:** Supports both API and web application targets via JSON configuration
- **Exclusions and Thresholds:** Handles exclusions and custom thresholds for findings with audit trail
- **Environment-aware Rules:** Different security rules for development, production, and QA environments

## Example Usage

1. Prepare a JSON configuration file describing the API or web application, including authentication details and operations.

> **Authentication oauth type**
```json
{
    "endpoint": "url base",
    "operations": [
        {
            "operation": {
                "security_auth": {
                    "type": "oauth",
                    "method": "POST",
                    "path": "/path/",
                    "grant_type": "client_credentials",
                    "scope": "",
                    "client_secret": "",
                    "client_id": "",
                    "headers": {
                        "accept": "application/json",
                        "content-type": "application/x-www-form-urlencoded;charset=utf-8"
                    }
                },
                "method": "POST",
                "path": "/path2",
                "payload": {
                    "data": {
                        
                    }
                },
                "headers": {
                    "Authorization": "#{authorization}#",
                    "x-consumer-type": "ext"
                }
            }
        }
    ]
}
```

> **Authentication jwt type**
```json
{
    "endpoint": "url base",
    "operations": [
        {
            "operation": {
                "security_auth": {
                    "type": "jwt",
                    "jwt_private_key": "",
                    "jwt_algorithm": "RS256",
                    "jwt_iss": "",
                    "jwt_sum": "",
                    "jwt_aud": "",
                    "jwt_header_name": "json-web-token"
                },
                "method": "POST",
                "path": "/path/",
                "payload": {
                    "data": {
                        "paginationRequest": {
                            "pageNumber": "0",
                            "pageSize": "2"
                        },
                    }
                },
                "headers": {
                    "content-type": "application/json",
                    "accept": "application/json",
                    "Message-Id": "",
                    "client-id": "",
                    "client-secret": "",
                    "x-client-certificate": ""
                }
            }
        }
    ]
}
```

2. Run the DAST engine via the orchestrator, specifying the configuration file and tool.

```sh
devsecops-engine-tools \
    --platform_devops github \
    --remote_config_source github \
    --remote_config_repo devsecops-config \
    --module engine_dast \
    --tool nuclei \
    --dast_file_path path/to/config.json
```

## Configuration Guidelines

### Performance Optimization
1. **Concurrency Settings**: Adjust `CONCURRENCY` based on target application capacity and rate limiting
2. **Timeout Configuration**: Set appropriate `TIMEOUT` values for slow-responding applications
3. **Response Size Limits**: Configure `RESPONSE_SIZE` to prevent memory issues with large responses
4. **Bulk Processing**: Use `BULK_SIZE` to optimize scanning of multiple targets

### External Templates Management
1. Enable `USE_EXTERNAL_CHECKS_DIR` for organization-specific templates
2. Configure GitHub App credentials for secure template repository access
3. Maintain custom templates in dedicated repositories for version control
4. Enable `ENABLE_CUSTOM_RULES` for specialized security checks

### Threshold Management
1. Set stricter thresholds for production environments vs development
2. Adjust thresholds based on application criticality and risk tolerance
3. Monitor threshold effectiveness and adjust based on false positive rates
4. Consider different thresholds for different types of applications

### Authentication Configuration
1. Support multiple authentication mechanisms in DAST configuration files
2. Secure storage of authentication credentials using secrets management
3. Test authentication flows before full DAST execution
4. Configure appropriate session management for long-running scans

### Exclusion Management
1. Add exclusions with specific rule IDs when possible
2. Set realistic expiration dates for temporary exclusions
3. Include detailed audit information for compliance tracking
4. Regular review and cleanup of expired exclusions
5. Use global exclusions sparingly - prefer targeted exclusions

## Extensibility

- New DAST tools can be added by extending the adapters and models
- Custom authentication methods can be implemented via authentication adapters
- External template repositories can be integrated for organization-specific security checks
- Custom security rules can be defined for specialized vulnerability detection
- Integrations with additional reporting or risk management systems can be implemented via the infrastructure layer
- JWT analysis can be extended for additional token security validations

## Testing

- Unit tests are provided in the `test/` directory, covering orchestration logic and configuration parsing
- Integration tests validate tool execution, authentication flows, and result processing
- Performance testing ensures scanning efficiency under various load conditions
- Authentication testing validates different auth mechanism integrations

