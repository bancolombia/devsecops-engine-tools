# Module Engine Dependencies

## Overview

The `engine_dependencies` module is responsible for orchestrating Software Composition Analysis (SCA) for application dependencies within the DevSecOps Engine Tools platform. It automates the execution of dependency scanning tools, processes scan configurations, manages exclusions, and integrates results for further risk analysis and reporting.

## Configuration Structure

The module is configured through two main JSON files located in `example_remote_config_local/engine_sca/engine_dependencies/`:

### ConfigTool.json

Main configuration file that defines scanning behavior, tool versions, and security policies.

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
    "CVE": ["CVE-123123"],
    "PRIORITY": {
        "Very Critical": 3,
        "Critical": 5,
        "High": 10,
        "Medium Low": 15
    }
  },
  "DEPENDENCY_CHECK": {
    "CLI_VERSION": "11.1.0",
    "REGEX_EXPRESSION_EXTENSIONS": "\\.(jar|ear|war)$",
    "PACKAGES_TO_SCAN": ["node_modules", "site-packages"],
    "VULNERABILITY_CONFIDENCE": ["highest"]
  },
  "TRIVY": {
    "CLI_VERSION": "0.65.0"
  }
}
```

#### Configuration Parameters

##### Xray Tool Configuration
- **CLI_VERSION**: JFrog Xray CLI version to use (e.g., `"2.55.0"`)
- **REGEX_EXPRESSION_EXTENSIONS**: Regex pattern for file extensions to scan (e.g., `"\\.(jar|ear|war)$"` for Java artifacts)
- **PACKAGES_TO_SCAN**: Array of package directories to analyze (e.g., `["node_modules", "site-packages"]`)
- **Error Handling Configuration**:
  - `STDERR_EXPECTED_WORDS`: Expected keywords in stderr output for normal operation
  - `STDERR_BREAK_ERRORS`: Error keywords that should stop execution
  - `STDERR_ACCEPTED_ERRORS`: Error keywords that can be safely ignored

##### Dependency-Check Tool Configuration
- **CLI_VERSION**: OWASP Dependency-Check version to use (e.g., `"11.1.0"`)
- **REGEX_EXPRESSION_EXTENSIONS**: File extension patterns for dependency analysis
- **PACKAGES_TO_SCAN**: Package directories to include in analysis
- **VULNERABILITY_CONFIDENCE**: Array of confidence levels for vulnerability detection (e.g., `["highest"]`)

##### Trivy Tool Configuration
- **CLI_VERSION**: Trivy scanner version to use (e.g., `"0.65.0"`)

##### General Configuration
- **IGNORE_ANALYSIS_PATTERN**: Regex pattern to exclude directories/files from analysis (e.g., `"(.*_test)"` ignores test directories)
- **MESSAGE_INFO_ENGINE_DEPENDENCIES**: Custom success message displayed when engine completes
- **IGNORE_FILES**: Array of specific files to exclude from scanning (e.g., `["wrapper.jar"]`)

##### Threshold Configuration
- **VULNERABILITY**: Maximum allowed vulnerabilities by severity level:
  - `Critical`: Maximum 3 critical vulnerabilities
  - `High`: Maximum 5 high severity vulnerabilities
  - `Medium`: Maximum 10 medium severity vulnerabilities
  - `Low`: Maximum 15 low severity vulnerabilities
- **COMPLIANCE**: Compliance issue limits:
  - `Critical`: Maximum 1 critical compliance issue
- **CVE**: Array of specific CVE identifiers to monitor or exclude (e.g., `["CVE-123123"]`)
- **PRIORITY**: Maximum allowed vulnerabilities by priority level:
  - `Very Critical`: Maximum 3 very critical priority vulnerability
  - `Critical`: Maximum 5 critical priority vulnerabilities
  - `High`: Maximum 10 high priority vulnerabilities
  - `Medium Low`: Maximum 15 medium low priority vulnerabilities

### Exclusions.json

Defines exclusion rules for repositories and specific vulnerability findings.

#### Structure
```json
{
  "All": {
    "XRAY": [
      {
        "id": "XRAY-522015",
        "cve_id": "CVE-2023-35116",
        "where": "all",
        "create_date": "19022024",
        "expired_date": "undefined",
        "hu": "4662904"
      }
    ]
  }
}
```

#### Exclusion Types
- **All**: Global exclusions applied to all repositories
- **Repository-specific**: Exclusions for specific repositories (can be added as needed)
- **Tool-specific exclusions**: Organized by scanning tool:
  - `XRAY`: Exclusions for JFrog Xray findings
  - `DEPENDENCY_CHECK`: Exclusions for OWASP Dependency-Check findings
  - `TRIVY`: Exclusions for Trivy findings

#### Exclusion Fields
Each exclusion entry contains:
- `id`: Tool-specific vulnerability identifier (e.g., `"XRAY-522015"`)
- `cve_id`: CVE identifier for the vulnerability (e.g., `"CVE-2023-35116"`)
- `where`: Scope of exclusion (`"all"` for global or specific dependency/path)
- `create_date`: Date when exclusion was created (format: DDMMYYYY)
- `expired_date`: Expiration date for the exclusion (`"undefined"` for permanent exclusions)
- `hu`: Human user identifier for audit trail

## Main Responsibilities

- **Dependency SCA Orchestration:** Executes dependency scanning tools (Xray, Dependency-Check, Trivy) on application codebases
- **Configuration Management:** Loads and processes scan configurations and exclusions from remote repositories
- **Folder and File Discovery:** Identifies relevant folders/files for scanning based on patterns and configuration with regex filtering
- **Exclusions Management:** Applies exclusion rules based on configuration and DevSecOps policy with audit trail
- **Result Processing:** Aggregates and normalizes findings for risk evaluation and reporting
- **SBOM Generation:** Supports extraction and management of Software Bill of Materials (SBOM) for dependencies
- **Error Handling:** Sophisticated error processing and classification for different scanning tools
- **Threshold Enforcement:** Validates findings against configured vulnerability, compliance, and CVE-specific thresholds

## Key Components

- `runner_dependencies_scan.py`: Main entry point for dependency scan orchestration
- `entry_point_tool.py`: Initializes the dependency SCA engine and triggers the scan process
- `dependencies_sca_scan.py`: Core use case for executing the scan, handling configuration, exclusions, and result aggregation
- **Adapters:** Integrations for dependency scanning tools (Xray, Dependency-Check, Trivy) and SBOM management

## Supported Tools and Features

- **JFrog Xray:** Enterprise-grade dependency vulnerability scanning with advanced error handling and artifact analysis
- **OWASP Dependency-Check:** Open-source vulnerability detection with configurable confidence levels
- **Trivy:** Fast and comprehensive dependency scanning with SBOM generation capabilities
- **Multi-language Support:** Handles various dependency types including Java (JAR/WAR/EAR), Node.js (node_modules), Python (site-packages)
- **SBOM Support:** Extracts and manages Software Bill of Materials for dependencies across different tools
- **Advanced Filtering:** Regex-based file extension filtering and pattern-based directory exclusions
- **Error Classification:** Intelligent error handling with expected, breaking, and acceptable error categories
- **Configurable Exclusions:** Supports exclusion of dependencies and vulnerabilities with expiration dates and audit trail

## Example Usage

The dependency SCA engine is typically invoked as part of the overall DevSecOps pipeline, after code or dependency changes are detected:

### Trivy Dependency Scanning
```sh
devsecops-engine-tools \
	--platform_devops github \
	--remote_config_source github \
	--remote_config_repo devsecops-config \
	--module engine_dependencies \
	--tool trivy \
	--folder_path path/to/project
```

### JFrog Xray Scanning
```sh
devsecops-engine-tools \
	--platform_devops azure \
	--remote_config_source azure \	
	--module engine_dependencies \
	--tool xray \
	--folder_path src/main/java
```

### OWASP Dependency-Check
```sh
devsecops-engine-tools \
	--platform_devops local \
	--remote_config_source local \
	--module engine_dependencies \
	--tool dependency-check \
	--folder_path project-root/
```

## Configuration Guidelines

### Tool-Specific Configuration
1. **Xray Configuration:**
   - Configure appropriate `REGEX_EXPRESSION_EXTENSIONS` for your artifact types
   - Set up error handling keywords based on your environment's typical output
   - Ensure `PACKAGES_TO_SCAN` covers all relevant dependency directories

2. **Dependency-Check Configuration:**
   - Adjust `VULNERABILITY_CONFIDENCE` levels based on false positive tolerance
   - Configure file extensions to match your project's artifact types
   - Consider performance impact when scanning large dependency trees

3. **Trivy Configuration:**
   - Use latest CLI version for best vulnerability database coverage
   - Leverage Trivy's SBOM capabilities for supply chain security

### Threshold Management
1. Set realistic vulnerability thresholds based on your security posture
2. Use stricter thresholds for production branches and more lenient for development
3. Monitor and adjust thresholds based on organizational risk tolerance
4. Consider using CVE-specific monitoring for critical vulnerabilities

### Exclusion Management
1. Add exclusions with specific vulnerability IDs when possible
2. Include detailed audit information (create_date, hu, expiration)
3. Regularly review and clean up expired exclusions
4. Use global exclusions sparingly - prefer repository-specific exclusions
5. Document business justification for permanent exclusions

### Error Handling Optimization
1. Customize `STDERR_EXPECTED_WORDS` based on your scanning environment
2. Add tool-specific breaking errors to `STDERR_BREAK_ERRORS`
3. Configure `STDERR_ACCEPTED_ERRORS` for known non-critical issues
4. Monitor logs to identify new error patterns for classification

## Extensibility

- New dependency scanning tools can be added by extending the adapters and use cases
- Custom error handling patterns can be configured without code changes
- Supports integration with various package managers (npm, pip, Maven, Gradle) and CI/CD platforms
- SBOM processing can be enhanced for integration with supply chain security tools
- Threshold logic can be extended for more sophisticated risk assessment
- Exclusion logic can be enhanced for additional compliance and audit requirements

## Testing

- Unit tests are provided in the `test/` directory, covering orchestration logic, configuration parsing, and exclusion handling
- Integration tests validate tool execution, error handling, and result processing workflows
- Error handling and threshold validation testing included for robustness
- SBOM generation and processing tests ensure supply chain security compliance