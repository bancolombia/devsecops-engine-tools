# Module Engine Container

## Overview

The `engine_container` module is responsible for vulnerability scanning of container images within the DevSecOps Engine Tools platform. It automates the execution of container scanning tools, processes scan configurations, manages exclusions, and integrates results for further risk analysis and reporting.

## Configuration Structure

The module is configured through two main JSON files located in `example_remote_config_local/engine_sca/engine_container/`:

### ConfigTool.json

Main configuration file that defines scanning behavior, tool versions, and security policies.

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
    "SBOM_FORMAT": "cyclonedx",
    "VULN_TYPE": "all",
    "IGNORE_UNFIXED": false
  },
  "SBOM": {
    "ENABLED": false,
    "BRANCH_FILTER": ["trunk", "main"]
  },
  "GET_IMAGE_BASE": {
    "ENABLED": false,
    "BASE_IMAGE_LABELS": ["com.example.label1", "com.example.label2"],
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
    "BLACK_LIST": ["/test/"]
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
            "APPS": ["CodeApp", "CodeApp1", "CodeApp12"],
            "PROFILE": "STRONG",
            "PROFILE_PRIORITY": "STRONG_PRIORITY"
          }
        },
        {
          "Product Type Name2": {
            "APPS": "ALL",
            "PROFILE": "MODERATE",
            "PROFILE_PRIORITY": "MODERATE_PRIORITY"
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
      },
      "STRONG_PRIORITY": {
          "Very Critical": 0,
          "Critical": 0,
          "High": 5,
          "Mediumv Low": 15
      },
      "MODERATE_PRIORITY": {
          "Very Critical": 1,
          "Critical": 3,
          "High": 5,
          "Mediumv Low": 15
      }
    },
    "COMPLIANCE": {
      "Critical": 1
    },
    "PRIORITY": {
        "Very Critical": 99,
        "Critical": 99,
        "High": 99,
        "Medium Low": 99
    }
  }
}
```

#### Configuration Parameters

##### Prisma Cloud Configuration
- **TWISTCLI_PATH**: Path to Prisma Cloud's twistcli binary (e.g., `"twistcli"`)
- **PRISMA_CONSOLE_URL**: URL of the Prisma Cloud console for API access
- **PRISMA_API_VERSION**: API version to use for Prisma Cloud integration
- **SBOM_FORMAT**: SBOM output format (`"cyclonedx_json"` for CycloneDX JSON format)

##### Trivy Configuration
- **TRIVY_VERSION**: Trivy scanner version to use (e.g., `"0.62.1"`)
- **SBOM_FORMAT**: SBOM output format (`"cyclonedx"` for CycloneDX format)
- **VULN_TYPE**: Types of vulnerabilities to scan (`"all"` for comprehensive scanning)
- **IGNORE_UNFIXED**: Boolean flag to ignore vulnerabilities without available fixes

##### SBOM (Software Bill of Materials) Configuration
- **ENABLED**: Boolean flag to enable/disable SBOM generation
- **BRANCH_FILTER**: Array of branch names that trigger SBOM generation (e.g., `["trunk", "main"]`)

##### Base Image Management
**GET_IMAGE_BASE Configuration:**
- **ENABLED**: Boolean flag to enable base image detection
- **BASE_IMAGE_LABELS**: Array of Docker labels to identify base images
- **LABEL_KEYS**: Mapping of semantic keys to actual Docker label names:
  - `baseline_date`: Label containing the baseline date for the image
  - `specific_use`: Label indicating specific use cases
  - `key_image_exception`: Label for image name exceptions

**VALIDATE_BASE_IMAGE_DATE Configuration:**
- **ENABLED**: Boolean flag to enable base image date validation
- **REFERENCE_IMAGE_DATE**: Reference date in YYYYMMDD format for validation (e.g., `"20250206"`)

**BLACK_LIST_BASE_IMAGE Configuration:**
- **ENABLED**: Boolean flag to enable base image blacklisting
- **BLACK_LIST**: Array of patterns to blacklist base images (e.g., `["/test/"]`)

##### General Configuration
- **MESSAGE_INFO_ENGINE_CONTAINER**: Success message displayed when engine completes successfully
- **IGNORE_SEARCH_PATTERN**: Regex pattern to exclude images from scanning (e.g., `"(.*_demo0|.*_cer)"`)
- **REGEX_CLEAN_END_PIPELINE_NAME**: Regex pattern to clean pipeline names

##### Threshold Configuration
**Basic Vulnerability Thresholds:**
- **VULNERABILITY**: High tolerance thresholds for development/testing:
  - `Critical`: Maximum 99 critical vulnerabilities
  - `High`: Maximum 99 high severity vulnerabilities
  - `Medium`: Maximum 99 medium severity vulnerabilities
  - `Low`: Maximum 999 low severity vulnerabilities

**Quality-Based Vulnerability Management:**
- **PTS (Product Type Specifications)**: Array of product-specific configurations:
  - Product type definitions with associated applications and security profiles
  - `APPS`: Array of application names or `"ALL"` for universal application
  - `PROFILE`: Security profile (`"STRONG"` or `"MODERATE"`)
  - `PROFILE_PRIORITY`: Security profile to priority (`"STRONG_PRIORITY"` or `"MODERATE_PRIORITY"`)

**Security Profiles:**
- **STRONG Profile**: Strict security requirements:
  - `Critical`: 0 (zero tolerance)
  - `High`: 0 (zero tolerance)
  - `Medium`: Maximum 5
  - `Low`: Maximum 15
- **MODERATE Profile**: Balanced security requirements:
  - `Critical`: Maximum 1
  - `High`: Maximum 3
  - `Medium`: Maximum 5
  - `Low`: Maximum 15
- **STRONG_PRIORITY Profile**: Strict security requirements:
  - `Very Critical`: 0 (zero tolerance)
  - `Critical`: 0 (zero tolerance)
  - `High`: Maximum 5
  - `Medium Low`: Maximum 15
- **MODERATE_PRIORITY Profile**: Balanced security requirements:
  - `Very Critical`: Maximum 1
  - `Critical`: Maximum 3
  - `High`: Maximum 5
  - `Medium Low`: Maximum 15

**Compliance Thresholds:**
- **COMPLIANCE**: Compliance issue limits:
  - `Critical`: Maximum 1 critical compliance issue

- **PRIORITY**: High tolerance thresholds for development/testing:
  - `Very Critical`: Maximum 99 very critical priority vulnerabilities
  - `Critical`: Maximum 99 critical priority vulnerabilities
  - `High`: Maximum 99 high priority vulnerabilities
  - `Medium Low`: Maximum 999 medium low priority vulnerabilities

### Exclusions.json

Defines exclusion rules for repositories and specific vulnerability findings.

#### Structure
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

#### Exclusion Types
- **All**: Global exclusions applied to all repositories
- **Repository-specific**: Exclusions for specific repositories (e.g., `"Repository_Test"`)
- **Tool-specific exclusions**: Organized by scanning tool:
  - `PRISMA`: Exclusions for Prisma Cloud findings
  - `TRIVY`: Exclusions for Trivy findings (if needed)
- **Feature-specific exclusions**: Configuration feature bypasses:
  - `VALIDATE_BASE_IMAGE_DATE`: Skip base image date validation
  - `BLACK_LIST_BASE_IMAGE`: Skip base image blacklist checking

#### Exclusion Fields
**Vulnerability Exclusions:**
- `id`: Vulnerability identifier or empty for general exclusions
- `cve_id`: Specific CVE identifier for targeted exclusions
- `where`: Scope of exclusion (`"all"` for global or specific image/path)
- `create_date`: Date when exclusion was created (format: DDMMYYYY)
- `expired_date`: Expiration date for the exclusion (format: DDMMYYYY)
- `hu`: Human user identifier for audit trail
- `reason`: Justification for exclusion (e.g., `"False Positive"`, `"Business Risk Accepted"`)

**Feature Exclusions:**
- `create_date`: Date when feature exclusion was created
- `expired_date`: Expiration date for the feature exclusion
- `hu`: Human user identifier for audit trail

## Main Responsibilities

- **Container SCA Orchestration:** Executes container scanning tools (Trivy, Prisma Cloud) on container images
- **Configuration Management:** Loads and processes scan configurations and exclusions from remote repositories
- **Image Discovery:** Identifies and manages container images to be scanned with pattern-based filtering
- **Exclusions Management:** Applies exclusion rules based on configuration and DevSecOps policy with audit trail
- **Result Processing:** Aggregates and normalizes findings for risk evaluation and reporting
- **SBOM Generation:** Supports extraction and management of Software Bill of Materials (SBOM) for container images
- **Base Image Validation:** Validates base image compliance including date validation and blacklist checking
- **Quality-based Thresholds:** Applies different security profiles based on product types and applications

## Key Components

- `runner_container_scan.py`: Main entry point for container scan orchestration
- `entry_point_tool.py`: Initializes the container SCA engine and triggers the scan process
- `container_sca_scan.py`: Core use case for executing the scan, handling configuration, exclusions, and result aggregation
- **Adapters:** Integrations for container scanning tools (Trivy, Prisma Cloud) and Docker image management

## Supported Tools and Features

- **Trivy:** Comprehensive vulnerability scanning with SBOM generation and configurable vulnerability types
- **Prisma Cloud:** Advanced container security scanning with enterprise policy enforcement and console integration
- **SBOM Support:** Extracts and manages SBOMs in CycloneDX format for container images with branch-specific triggers
- **Base Image Management:** Validates base image compliance, dates, and blacklist rules with Docker label integration
- **Quality-based Security:** Applies different security profiles (STRONG/MODERATE) based on product types and applications
- **Configurable Exclusions:** Supports exclusion of images, vulnerabilities, and features with expiration dates and audit trail
- **Multi-format Support:** Handles various SBOM formats and vulnerability report formats

## Example Usage

The container SCA engine is typically invoked as part of the overall DevSecOps pipeline, after container images are built or updated:

### Trivy Scanning
```sh
devsecops-engine-tools \
	--platform_devops github \
	--remote_config_source github \
	--remote_config_repo my-org/devsecops-config \
	--module engine_container \
	--tool trivy \
	--image_to_scan myimage:latest
```

### Prisma Cloud Scanning
```sh
devsecops-engine-tools \
--platform_devops azure \
	--remote_config_source azure \
	--module engine_container \
	--tool prisma \
	--image_to_scan registry.example.com/myapp:v1.0.0
```

## Configuration Guidelines

### Setting Up Quality-based Thresholds
1. Define product types in the `PTS` array with associated applications
2. Assign appropriate security profiles (`STRONG` for critical apps, `MODERATE` for others)
3. Use `"ALL"` in the `APPS` field for universal application to a product type
4. Regularly review and update security profiles based on risk assessments

### Managing Base Image Policies
1. Configure `BASE_IMAGE_LABELS` to match your organization's Docker labeling strategy
2. Set appropriate `REFERENCE_IMAGE_DATE` for base image validation
3. Maintain `BLACK_LIST` patterns to prevent use of vulnerable or deprecated base images
4. Use label mapping in `LABEL_KEYS` to standardize across different image sources

### Exclusion Management
1. Add vulnerability exclusions with specific CVE IDs when possible
2. Include detailed reasons for exclusions for audit compliance
3. Set realistic expiration dates and review expired exclusions regularly
4. Use repository-specific exclusions instead of global ones when possible
5. Document business justification for risk acceptance

### SBOM Configuration
1. Enable SBOM generation for production branches only to reduce overhead
2. Choose appropriate SBOM format based on your toolchain requirements
3. Integrate SBOM data with vulnerability management and compliance systems

## Extensibility

- New container scanning tools can be added by extending the adapters and use cases
- Custom security profiles can be defined for specific product types or applications
- Supports integration with various container registries and CI/CD platforms
- Base image validation logic can be extended for additional compliance requirements
- SBOM processing can be enhanced for integration with supply chain security tools

## Testing

- Unit tests are provided in the `test/` directory, covering orchestration logic, configuration parsing, and exclusion handling
- Integration tests validate tool execution, SBOM generation, and result processing workflows
- Base image validation and quality-based threshold testing included