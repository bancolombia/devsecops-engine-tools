# Module Engine Secret

## Overview

The `engine_secret` module is responsible for orchestrating secret scanning within the DevSecOps Engine Tools platform. It automates the execution of secret scanning tools, processes scan configurations, manages exclusions, and integrates results for further risk analysis and reporting.

## Configuration Structure

The module is configured through two main JSON files located in `example_remote_config_local/engine_sast/engine_secret/`:

### ConfigTool.json

Main configuration file that defines scanning behavior, tool versions, and security thresholds.

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
    },
    "PRIORITY": {
        "Very Critical": 99,
        "Critical": 99,
        "High": 99,
        "Medium Low": 99
    }
  },
  "TARGET_BRANCHES": ["trunk", "develop"],
  "trufflehog": {
    "VERSION": "3.88.31",
    "EXCLUDE_PATH": [".git", "_venv"],
    "EXCLUDE_DETECTORS": ["aws", "userflow"],
    "NUMBER_THREADS": 4,
    "FILTER_ENTROPY": 3.0,
    "ENABLE_CUSTOM_RULES": false,
    "EXTERNAL_DIR_OWNER": "ExternalOrg",
    "EXTERNAL_DIR_REPOSITORY": "DevSecOps_Checks",
    "APP_ID_GITHUB": "",
    "INSTALLATION_ID_GITHUB": "",
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
    "ENABLE_CUSTOM_RULES": false,
    "EXTERNAL_DIR_OWNER": "ExternalOrg",
    "EXTERNAL_DIR_REPOSITORY": "DevSecOps_Checks",
    "APP_ID_GITHUB": "",
    "INSTALLATION_ID_GITHUB": "",
    "USE_EXTERNAL_CHECKS_GIT": false,
    "USE_EXTERNAL_CHECKS_DIR": false
  }
}
```

#### Configuration Parameters

##### General Configuration
- **IGNORE_SEARCH_PATTERN**: Regex pattern to exclude files/folders from scanning (e.g., `"(.*test.*)"` ignores test files)
- **MESSAGE_INFO_ENGINE_SECRET**: Success message displayed when engine completes successfully
- **TARGET_BRANCHES**: Array of branch names that should be scanned for secrets (e.g., `["trunk", "develop"]`)

##### Threshold Configuration
- **THRESHOLD.VULNERABILITY**: Maximum allowed vulnerabilities by severity level:
  - `Critical`: Maximum 99 critical vulnerabilities allowed (high tolerance for secrets)
  - `High`: Maximum 99 high severity vulnerabilities
  - `Medium`: Maximum 99 medium severity vulnerabilities
  - `Low`: Maximum 99 low severity vulnerabilities
- **THRESHOLD.COMPLIANCE**: Maximum allowed compliance issues:
  - `Critical`: Maximum 0 critical compliance issues (zero tolerance)
- **THRESHOLD.PRIORITY**: Maximum allowed vulnerabilities by priority level:
  - `Very Critical`: Maximum 99 very critical priority vulnerability allowed
  - `Critical`: Maximum 99 critical priority vulnerabilities
  - `High`: Maximum 99 high priority vulnerabilities  
  - `Medium Low`: Maximum 99 medium low priority vulnerabilities

##### Trufflehog Tool Configuration
- **VERSION**: Trufflehog version to use (e.g., `"3.88.31"`)
- **EXCLUDE_PATH**: Array of paths to exclude from scanning (e.g., `[".git", "_venv"]`)
- **EXCLUDE_DETECTORS**: Array of detector names to disable (e.g., `["aws", "userflow"]`)
- **NUMBER_THREADS**: Number of threads for parallel processing (e.g., `4`)
- **FILTER_ENTROPY**: Minimum entropy threshold for secret detection (e.g., `3.0`)
- **ENABLE_CUSTOM_RULES**: Boolean flag to enable custom detection rules
- **External Rules Configuration**:
  - `EXTERNAL_DIR_OWNER`: External organization for custom rules
  - `EXTERNAL_DIR_REPOSITORY`: Repository containing custom rules
  - `APP_ID_GITHUB`: GitHub App ID for authentication
  - `INSTALLATION_ID_GITHUB`: GitHub App installation ID
  - `USE_EXTERNAL_CHECKS_GIT`: Enable external checks from Git repository
  - `USE_EXTERNAL_CHECKS_DIR`: Enable external checks from directory
- **RULES**: Custom rule definitions with references and mitigation guidance

##### Gitleaks Tool Configuration
- **VERSION**: Gitleaks version to use (e.g., `"8.21.1"`)
- **EXCLUDE_PATH**: Array of paths to exclude from scanning (e.g., `[".git"]`)
- **NUMBER_THREADS**: Number of threads for parallel processing (e.g., `4`)
- **ALLOW_IGNORE_LEAKS**: Boolean flag to allow ignoring specific leaks
- **ENABLE_CUSTOM_RULES**: Boolean flag to enable custom detection rules
- **External Rules Configuration**: Same structure as Trufflehog for consistency

### Exclusions.json

Defines exclusion rules for repositories and specific secret scanning findings.

#### Structure
```json
{
  "All": {
    "TRUFFLEHOG": []
  },
  "Repository_test": {
    "TRUFFLEHOG": [
      {
        "id": "SECRET_SCANNING",
        "where": "azure_api/secretos_azure_api.txt",
        "create_date": "30042024",
        "expired_date": "undefined",
        "hu": "12345",
        "reason": "false_positive"
      },
      {
        "id": "SECRET_SCANNING",
        "where": "keys_test.txt",
        "create_date": "30042024",
        "expired_date": "undefined",
        "hu": "12345",
        "reason": "false_positive"
      }
    ]
  }
}
```

#### Exclusion Types
- **All**: Global exclusions applied to all repositories
- **Repository-specific**: Exclusions for specific repositories (e.g., `"Repository_test"`)
- **Tool-specific exclusions**: Organized by scanning tool:
  - `TRUFFLEHOG`: Exclusions for Trufflehog findings
  - `GITLEAKS`: Exclusions for Gitleaks findings (if needed)

#### Exclusion Fields
Each exclusion entry contains:
- `id`: Type of secret scanning finding (e.g., `"SECRET_SCANNING"`)
- `where`: Specific file path where the exclusion applies
- `create_date`: Date when exclusion was created (format: DDMMYYYY)
- `expired_date`: Expiration date for the exclusion (`"undefined"` for permanent)
- `hu`: Human user identifier for audit trail
- `reason`: Justification for exclusion (e.g., `"false_positive"`, `"test_data"`)

## Main Responsibilities

- **Secret Scanning Orchestration:** Executes secret scanning tools (Trufflehog, Gitleaks) on source code and pull requests
- **Configuration Management:** Loads and processes scan configurations and exclusions from remote repositories
- **Pull Request Analysis:** Identifies and filters files changed in pull requests for targeted secret scanning
- **Exclusions Management:** Applies exclusion rules based on configuration and DevSecOps policy with audit trail
- **Result Processing:** Aggregates and normalizes findings for risk evaluation and reporting
- **Threshold Enforcement:** Validates findings against configured vulnerability and compliance thresholds
- **Branch-specific Scanning:** Focuses scanning on specified target branches for efficiency

## Key Components

- `runner_secret_scan.py`: Main entry point for secret scan orchestration
- `entry_point_tool.py`: Initializes the secret scanning engine and triggers the scan process
- `secret_scan.py`: Core use case for executing the scan, handling configuration, exclusions, and result aggregation
- **Adapters:** Integrations for secret scanning tools (Trufflehog, Gitleaks) and Git operations

## Supported Tools and Features

- **Trufflehog:** Advanced secret detection with entropy filtering and custom detector exclusions
- **Gitleaks:** Fast and accurate secret detection with comprehensive rule sets
- **Pull Request Scanning:** Supports scanning only files changed in pull requests for efficiency
- **Configurable Exclusions:** Supports exclusion of files/folders and custom ignore patterns with expiration and audit trail
- **Thresholds and Policies:** Handles custom thresholds and build-breaking policies for different severity levels
- **Multi-threading:** Parallel processing support for improved scanning performance
- **External Rules Integration:** Support for custom rules from external repositories via GitHub Apps

## Example Usage

The secret scanning engine is typically invoked as part of the overall DevSecOps pipeline, after code changes are detected:

```sh
devsecops-engine-tools \
	--platform_devops github \
	--remote_config_source github \
	--remote_config_repo devsecops-config \
	--module engine_secret \
	--tool trufflehog \
	--folder_path path/to/source
```

### Tool-specific Usage

#### Trufflehog Scanning
```sh
devsecops-engine-tools \
	--platform_devops azure \
	--remote_config_source azure \
	--remote_config_repo devsecops-config \
	--module engine_secret \
	--tool trufflehog \
```

#### Gitleaks Scanning
```sh
devsecops-engine-tools \
	--platform_devops github \
	--remote_config_source loca \
	--remote_config_repo devsecops-config \
	--module engine_secret \
	--tool gitleaks \
	--folder_path src/
```

## Configuration Guidelines

### Adding Exclusions
1. Add exclusions to `Exclusions.json` with specific file paths when possible
2. Include creation date, expiration date, and human user identifier for audit compliance
3. Provide clear reason for exclusion (false_positive, test_data, etc.)
4. Review and clean expired exclusions regularly
5. Use repository-specific exclusions instead of global ones when possible

### Tuning Detection Parameters
1. **Entropy Filtering**: Adjust `FILTER_ENTROPY` in Trufflehog configuration to reduce false positives
2. **Detector Exclusions**: Add specific detectors to `EXCLUDE_DETECTORS` if they generate excessive false positives
3. **Path Exclusions**: Configure `EXCLUDE_PATH` to skip non-relevant directories
4. **Threading**: Adjust `NUMBER_THREADS` based on available system resources

### Managing Custom Rules
1. Enable `ENABLE_CUSTOM_RULES` for advanced detection scenarios
2. Configure external repository access via GitHub Apps authentication
3. Maintain custom rules in dedicated repository for version control
4. Document custom rules with references and mitigation guidance

## Extensibility

- New secret scanning tools can be added by extending the adapters and use cases
- Custom detection rules can be defined and loaded from external repositories
- Supports integration with various version control and CI/CD platforms
- Exclusion logic can be extended for additional use cases and audit requirements
- Tool-specific configurations can be expanded without code changes

## Testing

- Unit tests are provided in the `test/` directory, covering orchestration logic, configuration parsing, and exclusion handling
- Integration tests validate tool execution and result processing workflows
- Test data exclusions should be properly documented and maintained