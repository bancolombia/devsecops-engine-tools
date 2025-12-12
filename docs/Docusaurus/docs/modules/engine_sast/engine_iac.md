# Module Engine IAC

## Overview

The `engine_iac` module is responsible for orchestrating Infrastructure as Code (IaC) security scanning within the DevSecOps Engine Tools platform. It automates the execution of IaC security tools, processes scan configurations, manages exclusions, and integrates results for further risk analysis and reporting.


## Configuration Structure

The module is configured through two main JSON files located in `example_remote_config_local/engine_sast/engine_iac/`:

### ConfigTool.json

Main configuration file that defines scanning behavior, tool versions, and security rules.

```json
{
  "SEARCH_PATTERN": ["ms_"],
  "IGNORE_SEARCH_PATTERN": "(.*_test)",
  "UPDATE_SERVICE_WITH_FILE_NAME_CFT": "True",
  "REGEX_CLEAN_END_PIPELINE_NAME": "",
  "MESSAGE_INFO_ENGINE_IAC": "engine_iac run successfully",
  "THRESHOLD": {
    "VULNERABILITY": {
      "Critical": 1,
      "High": 4,
      "Medium": 10,
      "Low": 15
    },
    "COMPLIANCE": {
      "Critical": 1
    },
    "PRIORITY": {
        "Very Critical": 1,
        "Critical": 4,
        "High": 10,
        "Medium Low": 15
    }
  },
  "CHECKOV": {
    "VERSION": "3.2.427",
    "INSTALL_TYPE": "remote-binary",
    "URL_FILE_LINUX": "https://github.com/bridgecrewio/checkov/releases/download/2.3.321/checkov_linux_X86_64_2.3.321.zip",
    "URL_FILE_LINUX_ARM64": "https://github.com/bridgecrewio/checkov/releases/download/2.3.321/checkov_linux_arm64_2.3.321.zip",
    "URL_FILE_DARWIN": "https://github.com/bridgecrewio/checkov/releases/download/2.3.321/checkov_darwin_X86_64_2.3.321.zip",
    "URL_FILE_WINDOWS": "https://github.com/bridgecrewio/checkov/releases/download/2.3.321/checkov_windows_X86_64_2.3.321.zip",
    "USE_EXTERNAL_CHECKS_GIT": false,
    "EXTERNAL_CHECKS_GIT": "",
    "EXTERNAL_GIT_SSH_HOST": "",
    "EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT": "",
    "USE_EXTERNAL_CHECKS_DIR": false,
    "EXTERNAL_DIR_OWNER": "",
    "EXTERNAL_DIR_REPOSITORY": "",
    "APP_ID_GITHUB": "",
    "INSTALLATION_ID_GITHUB": "",
    "DEFAULT_SEVERITY": "Critical",
    "DEFAULT_CATEGORY": "Compliance",
    "REGEX_CLEAN_RESOURCE": "",
	"RULES": {
		"RULES_DOCKER" {
			"CKV_DOCKER_1": {
				"checkID": "IAC-CKV-DOCKER-1 Ensure port 22 is not exposed",
				"environment": {
					"dev": true,
					"pdn": true,
					"qa": true
				},
				"guideline": "https://bit.ly/3IrJFQx",
				"severity": "Critical",
				"cvss": "",
				"category": "Vulnerability"
			},...
		},
		"RULES_K8S" : {
			"CKV_K8S_8": {
				"checkID": "IAC-CKV_K8S_8 Liveness Probe Should be Configured",
				"environment": {
					"dev": true,
					"pdn": true,
					"qa": true
				},
				"guideline": "https://bit.ly/3IrJFQx",
				"severity": "High",
				"cvss": "",
				"category": "Compliance"
            },....
		},
		"RULES_CLOUDFORMATION": {
			"CKV_AWS_26": {
                    "customID": "C-SNS-002",
                    "checkID": "C-SNS-002-AWS SNS is not encrypted",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "https://bit.ly/44frBRZ",
                    "severity": "High",
                    "cvss": "",
                    "category": "Vulnerability"
            },...
		},
		"RULES_TERRAFORM" : {
			"CKV_AWS_144": {
                    "checkID": "IAC-CKV-TERRAFORM-1 Ensure terraform",
                    "environment": {
                        "dev": true,
                        "pdn": true,
                        "qa": true
                    },
                    "guideline": "guideline",
                    "severity": "Medium",
                    "cvss": "",
                    "category": "Vulnerability"
            },...
		}
	}
  },
  "KICS": {
    "CLI_VERSION": "2.1.5",
    "PATH_KICS": "kics/bin/kics",
    "DOWNLOAD_KICS_ASSETS": false,
    "EXCLUDE_PATHS": ["name_folder_to_exclude_1", "name_folder_to_exclude_2"],
	"RULES":{
		"RULES_OPENAPI":{
			"CKV_OPENAPI_1":{
				"checkID": "6998389e-66b2-473d-8d05-c8d71ac4d04d",
				"overrideID": "6998389e-254as-473d-1234-c8d71ac4dabc",
				"environment": {
					"dev": true,
					"pdn": true,
					"qa": true
				},
				"guideline": "guideline",
				"severity": "Medium",
				"cvss": "",
				"category": "Vulnerability"
			},...
		}
	}
  },
  "KUBESCAPE": {
    "VERSION": "3.0.11"
  }
}
```

#### Configuration Parameters

##### Search and Pattern Configuration
- **SEARCH_PATTERN**: Array of patterns to search for in repository files/folders (e.g., `["ms_"]` for microservices)
- **IGNORE_SEARCH_PATTERN**: Regex pattern to exclude files/folders from scanning (e.g., `"(.*_test)"` ignores test files)
- **UPDATE_SERVICE_WITH_FILE_NAME_CFT**: Boolean flag to update service name with CloudFormation file name
- **REGEX_CLEAN_END_PIPELINE_NAME**: Regex pattern to clean pipeline names
- **MESSAGE_INFO_ENGINE_IAC**: Success message displayed when engine completes successfully

##### Threshold Configuration
- **THRESHOLD.VULNERABILITY**: Maximum allowed vulnerabilities by severity level:
  - `Critical`: Maximum 1 critical vulnerability allowed
  - `High`: Maximum 4 high severity vulnerabilities
  - `Medium`: Maximum 10 medium severity vulnerabilities  
  - `Low`: Maximum 15 low severity vulnerabilities
- **THRESHOLD.COMPLIANCE**: Maximum allowed compliance issues:
  - `Critical`: Maximum 1 critical compliance issue
- **THRESHOLD.PRIORITY**: Maximum allowed vulnerabilities by priority level:
  - `Very Critical`: Maximum 1 very critical priority vulnerability allowed
  - `Critical`: Maximum 4 critical priority vulnerabilities
  - `High`: Maximum 10 high priority vulnerabilities  
  - `Medium Low`: Maximum 15 medium low priority vulnerabilities

##### Checkov Tool Configuration
- **VERSION**: Checkov version to use (e.g., `"3.2.427"`)
- **INSTALL_TYPE**: Installation method (`"remote-binary"` for downloading binaries)
- **URL_FILE_***: Download URLs for different platforms:
  - `URL_FILE_LINUX`: Linux x86_64 binary URL
  - `URL_FILE_LINUX_ARM64`: Linux ARM64 binary URL  
  - `URL_FILE_DARWIN`: macOS binary URL
  - `URL_FILE_WINDOWS`: Windows binary URL
- **External Checks Configuration**:
  - `USE_EXTERNAL_CHECKS_GIT`: Enable external checks from Git repository
  - `EXTERNAL_CHECKS_GIT`: Git repository URL for external checks
  - `EXTERNAL_GIT_SSH_HOST`: SSH host for Git access
  - `EXTERNAL_GIT_PUBLIC_KEY_FINGERPRINT`: SSH public key fingerprint
  - `USE_EXTERNAL_CHECKS_DIR`: Enable external checks from directory
  - `EXTERNAL_DIR_OWNER`: Directory owner for external checks
  - `EXTERNAL_DIR_REPOSITORY`: Repository for external checks directory
- **GitHub Integration**:
  - `APP_ID_GITHUB`: GitHub App ID for authentication
  - `INSTALLATION_ID_GITHUB`: GitHub App installation ID
- **Default Values**:
  - `DEFAULT_SEVERITY`: Default severity level for new rules (`"Critical"`)
  - `DEFAULT_CATEGORY`: Default category for new rules (`"Compliance"`)
  - `REGEX_CLEAN_RESOURCE`: Regex pattern to clean resource names

##### KICS Tool Configuration
- **CLI_VERSION**: KICS CLI version (e.g., `"2.1.5"`)
- **PATH_KICS**: Relative path to KICS binary (`"kics/bin/kics"`)
- **DOWNLOAD_KICS_ASSETS**: Boolean flag to download KICS assets
- **EXCLUDE_PATHS**: Array of folder names to exclude from scanning

##### Kubescape Tool Configuration
- **VERSION**: Kubescape version to use (e.g., `"3.0.11"`)

##### Security Rules Configuration
Each tool contains rule sets organized by technology:

**Rule Structure**: Each security rule contains:
- `checkID`: Unique identifier and description of the security check
- `customID`: Custom internal identifier (CloudFormation rules only)
- `overrideID`: Override identifier for rule customization (KICS rules only)
- `environment`: Environment-specific enablement:
  - `dev`: Enable in development environment
  - `pdn`: Enable in production environment
  - `qa`: Enable in QA environment
- `guideline`: URL to security guideline documentation
- `severity`: Risk level (`"Critical"`, `"High"`, `"Medium"`, `"Low"`)
- `cvss`: CVSS score (if applicable)
- `category`: Rule category (`"Vulnerability"`, `"Compliance"`)

**Rule Categories**:
- **RULES_DOCKER**: Container security rules (port exposure, user configuration, file operations)
- **RULES_K8S**: Kubernetes security rules (resource limits, security contexts, RBAC)
- **RULES_CLOUDFORMATION**: AWS CloudFormation security rules (encryption, access controls, logging)
- **RULES_TERRAFORM**: Terraform-specific infrastructure security rules
- **RULES_OPENAPI**: API security rules for OpenAPI specifications

In the RULES section of each platform (RULES_DOCKER, RULES_K8S, RULES_CLOUDFORMATION, etc.), the body is empty. Example “RULES_DOCKER” {}, the tool executes all rules associated with it.

### Exclusions.json

Defines exclusion rules for repositories and specific security checks.

#### Structure
```json
{
  "All": {
    "CHECKOV": [
      {
        "id": "CKV_K8S_24",
        "where": "all",
        "create_date": "18112023",
        "expired_date": "18032024",
        "severity": "HIGH",
        "hu": "4338704"
      }
    ]
  },
  "Repository_Test": {
    "SKIP_TOOL": {
      "create_date": "24012024",
      "expired_date": "30012024",
      "hu": "3423213"
    },
    "CHECKOV": [
      {
        "id": "CKV_K8S_8",
        "where": "deployment-configmap.yaml",
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
- **Repository-specific**: Exclusions for specific repositories
- **SKIP_TOOL**: Complete tool bypass for a repository
- **Rule-specific**: Exclusions for specific security rules with:
  - `id`: Security rule identifier
  - `where`: File or location scope ("all" for global)
  - `create_date`: Exclusion creation date
  - `expired_date`: Exclusion expiration date
  - `severity`: Rule severity level
  - `hu`: Human user identifier for audit trail

## Main Responsibilities

- **IaC Security Orchestration:** Executes IaC security tools (Checkov, KICS, Kubescape) on infrastructure code
- **Configuration Management:** Loads and processes scan configurations and exclusions from remote repositories
- **Folder and File Discovery:** Identifies relevant folders/files for scanning based on patterns and configuration
- **Exclusions Management:** Applies exclusion rules based on configuration and DevSecOps policy
- **Result Processing:** Aggregates and normalizes findings for risk evaluation and reporting
- **Threshold Enforcement:** Validates findings against configured vulnerability and compliance thresholds


## Key Components

- `runner_iac_scan.py`: Main entry point for IaC scan orchestration
- `entry_point_tool.py`: Initializes the IaC engine and triggers the scan process
- `iac_scan.py`: Core use case for executing the scan, handling configuration, exclusions, and result aggregation
- **Adapters:** Integrations for IaC security tools (Checkov, KICS, Kubescape)

## Supported Tools and Features

- **Checkov:** Scans Terraform, CloudFormation, Kubernetes, Docker, and more for security misconfigurations
- **KICS:** Scans IaC files for vulnerabilities and compliance issues with OpenAPI support
- **Kubescape:** Focused on Kubernetes security scanning with RBAC analysis
- **Configurable Exclusions:** Supports exclusion of files/folders and custom ignore patterns with expiration dates
- **Thresholds and Policies:** Handles custom thresholds and build-breaking policies for vulnerabilities and compliance
- **Multi-platform Support:** Cross-platform binary distribution for Linux, macOS, and Windows

## Example Usage

The IaC engine is typically invoked as part of the overall DevSecOps pipeline, after infrastructure code changes are detected:

```sh
devsecops-engine-tools \
	--platform_devops github \
	--remote_config_source github \
	--remote_config_repo devsecops-config \
	--module engine_iac \
	--tool checkov \
	--folder_path path/to/iac
```

## Configuration Guidelines

### Configure Rules
1. Define the rule in the appropriate `RULES_*` section based on technology (Docker, K8S, CloudFormation, etc.)
2. Include all required fields: `checkID`, `environment`, `guideline`, `severity`, `category`
3. Set environment-specific enablement flags (`dev`, `pdn`, `qa`)
4. Provide documentation guidelines URL

### Managing Exclusions
1. Add exclusions to `Exclusions.json` with proper expiration dates
2. Use specific file paths in `where` field when possible (avoid "all" for security)
3. Include audit trail information (`hu` field) for compliance tracking
4. Review and clean expired exclusions regularly

### Tool Version Management
Update tool versions in the configuration and ensure corresponding binary URLs are available for all supported platforms.

## Extensibility

- New IaC security tools can be added by extending the adapters and use cases
- Custom rules can be defined in the configuration without code changes
- Supports integration with various version control and CI/CD platforms
- Exclusion logic can be extended for additional use cases and audit requirements

## Testing

- Unit tests are provided in the `test/` directory, covering orchestration logic, configuration parsing, and exclusion handling
- Integration tests validate tool execution and result processing workflows