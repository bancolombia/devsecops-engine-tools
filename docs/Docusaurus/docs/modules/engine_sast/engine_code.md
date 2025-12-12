# Module Engine Code

## Overview

The `engine_code` module is responsible for orchestrating Static Application Security Testing (SAST) within the DevSecOps Engine Tools platform. It automates the execution of SAST tools, processes code scan configurations, manages exclusions, and integrates results for further risk analysis and reporting.

## Configuration Structure

The module is configured through two main JSON example files located in `example_remote_config_local/engine_sast/engine_code/`:

### ConfigTool.json

The configuration file defines scan parameters, thresholds, and tool-specific settings:

```json
{
  "IGNORE_SEARCH_PATTERN": [
    ".git"
  ],
  "EXCLUDE_FOLDER": [],
  "MESSAGE_INFO_ENGINE_CODE": "test message",
  "THRESHOLD": {
    "VULNERABILITY": {
      "Critical": 999,
      "High": 999,
      "Medium": 999,
      "Low": 999
    },
    "COMPLIANCE": {
      "Critical": 999
    },
    "PRIORITY": {
        "Very Critical": 999,
        "Critical": 999,
        "High": 999,
        "Medium Low": 999
    }
  },
  "TARGET_BRANCHES": [
    "trunk",
    "develop"
  ],
  "BEARER": {
    "NUMBER_THREADS": 4
  },
  "KIUWAN": {
    "SERVER": {
      "BASE_URL": "https://api.kiuwan.com",
      "USER": "user",
      "DOMAIN_ID": "12345678910111213141516171819"
    },
    "MODELOS": {
      "Maven": "Reglas Java",
      "Gradle": "Reglas Java",
      "Npm": "Reglas Node",
      "Python": "Reglas Python",
      "Angular": "Reglas Angular",
      ".Net": "ReglasNet",
      "PHP": "PHP Symfony",
      "General": "CQM",
      "OWASP": "OWASP-benchmark"
    },
    "SEVERITY": {
      "Very High": "critical",
      "High": "high",
      "Normal": "medium",
      "Low": "low",
      "Very Low": "low"
    }
  }
}
```

#### Configuration Parameters

- **IGNORE_SEARCH_PATTERN**: Array of patterns to ignore during scanning (e.g., ".git")
- **EXCLUDE_FOLDER**: Array of folders to exclude from scanning
- **MESSAGE_INFO_ENGINE_CODE**: Custom informational message for the engine
- **THRESHOLD**: Defines vulnerability and compliance thresholds for build breaking
  - **VULNERABILITY**: Thresholds for different severity levels (Critical, High, Medium, Low)
  - **COMPLIANCE**: Threshold for compliance issues (Critical)
  - **PRIORITY**: Thresholds for different priority levels (Very Critical, Critical, High, Medium Low)
- **TARGET_BRANCHES**: Array of branch names where scanning should be performed
- **BEARER**: Bearer-specific configuration
  - **NUMBER_THREADS**: Number of threads for parallel processing
- **KIUWAN**: Kiuwan-specific configuration
  - **SERVER**: Server connection details (BASE_URL, USER, DOMAIN_ID)
  - **MODELOS**: Mapping of technology types to analysis models
  - **SEVERITY**: Mapping of Kiuwan severity levels to standard levels

### Exclusions.json

The exclusions file defines rules to exclude specific findings from results:

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
    ],
    "KIUWAN": [
      {
        "id": "test_id",
        "where": "all",
        "create_date": "18112023",
        "expired_date": "18032024",
        "severity": "Low",
        "hu": "0000000"
      }
    ]
  },
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
  },
  "Repository_Test_2": {
    "KIUWAN": [
      {
        "id": "35278412059",
        "where": "all",
        "create_date": "01082025",
        "expired_date": "10082025",
        "severity": "high",
        "hu": "0000000"
      }
    ]
  }
}
```

#### Exclusion Structure

- **All**: Global exclusions applied to all repositories
- **Repository_Name**: Repository-specific exclusions
- **Tool Arrays** (BEARER, KIUWAN): Tool-specific exclusion rules
  - **id**: Finding identifier or rule ID to exclude
  - **where**: Location specification ("all" for global, or specific file path)
  - **create_date**: Date when exclusion was created (format: DDMMYYYY)
  - **expired_date**: Date when exclusion expires (format: DDMMYYYY)
  - **severity**: Severity level of the excluded finding
  - **hu**: History Unit or tracking identifier

## Main Responsibilities

- **SAST Orchestration:** Executes SAST tools (e.g., Bearer, Kiuwan) on source code and pull requests.
- **Configuration Management:** Loads and processes scan configurations and exclusions from remote repositories.
- **Pull Request Analysis:** Identifies and filters files changed in pull requests for targeted scanning.
- **Exclusions Management:** Applies exclusion rules based on configuration and DevSecOps policy.
- **Result Processing:** Aggregates and normalizes findings for risk evaluation and reporting.

## Key Components

- `runner_engine_code.py`: Main entry point for SAST scan orchestration.
- `entry_point_tool.py`: Initializes the SAST engine and triggers the scan process.
- `code_scan.py`: Core use case for executing the scan, handling configuration, exclusions, and result aggregation.
- **Adapters:** Integrations for SAST tools (Bearer, Kiuwan) and Git operations.

## Supported Tools and Features

### Bearer
- **Primary SAST Tool:** Main tool for scanning source code for security vulnerabilities
- **Threading Support:** Configurable parallel processing with NUMBER_THREADS
- **Language Support:** Multi-language security analysis
- **Pull Request Scanning:** Supports scanning only files changed in pull requests
- **Configurable Exclusions:** Supports exclusion of files/folders and custom ignore patterns

### Kiuwan
- **Enterprise SAST Tool:** Advanced static analysis with compliance checking
- **Model-Based Analysis:** Technology-specific analysis models (Java, Node, Python, etc.)
- **Severity Mapping:** Custom severity level mapping from Kiuwan to standard levels
- **Server Integration:** Direct API integration with Kiuwan server
- **Compliance Analysis:** Handles both vulnerability and compliance analysis
- **Pull Request Scanning:** Supports scanning files changed in pull requests and files in folder_path

### Common Features
- **Thresholds and Policies:** Handles custom thresholds and build-breaking policies
- **Branch Targeting:** Configurable target branches for scanning
- **Pattern Exclusions:** Ignore patterns for files and directories
- **Time-Based Exclusions:** Exclusions with expiration dates

## Example Usage

The SAST engine is typically invoked as part of the overall DevSecOps pipeline, after code changes are detected:

### Bearer Scanning
```sh
devsecops-engine-tools \
  --platform_devops github \
  --remote_config_source github \
  --remote_config_repo devsecops-config \
  --module engine_code \
  --tool bearer \
  --folder_path path/to/source
```

### Kiuwan Scanning
```sh
devsecops-engine-tools \
  --platform_devops azure \
  --remote_config_source azure \
  --remote_config_repo devsecops-config \
  --module engine_code \
  --tool kiuwan \
  --folder_path path/to/source
```

## Extensibility

- New SAST tools can be added by extending the adapters and use cases
- Supports integration with various version control and CI/CD platforms
- Exclusion policies can be extended with new rule types and criteria
- Configuration can be extended with tool-specific parameters

## Testing

- Unit tests are provided in the `test/` directory, covering orchestration logic, configuration parsing, and exclusion handling