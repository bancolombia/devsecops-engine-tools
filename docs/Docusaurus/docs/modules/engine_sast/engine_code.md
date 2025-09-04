# Module Engine Code

## Overview

The `engine_code` module is responsible for orchestrating Static Application Security Testing (SAST) within the DevSecOps Engine Tools platform. It automates the execution of SAST tools, processes code scan configurations, manages exclusions, and integrates results for further risk analysis and reporting.

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

- **Bearer:** Main SAST tool for scanning source code for security issues.
- **Pull Request Scanning:** Supports scanning only files changed in pull requests.
- **Configurable Exclusions:** Supports exclusion of files/folders and custom ignore patterns.
- **Thresholds and Policies:** Handles custom thresholds and build-breaking policies.

- **Kiuwan:** Aditional SAST tool for scanning source code for security issues and compliances.
- **Pull Request Scanning:** Supports scanning files changed in pull requests and files in a "folder_path" directory.
- **Configurable Exclusions:** Supports exclusion of files/folders and custom ignore patterns.
- **Thresholds and Policies:** Handles custom thresholds and build-breaking policies.

## Example Usage

The SAST engine is typically invoked as part of the overall DevSecOps pipeline, after code changes are detected:

```sh
devsecops-engine-tools \
	--platform_devops github \
	--remote_config_source github \
	--remote_config_repo my-org/devsecops-config \
	--module engine_code \
	--tool bearer \
	--folder_path path/to/source
```

```sh
devsecops-engine-tools \
	--platform_devops azure \
	--remote_config_source azure \
	--remote_config_repo my-org/devsecops-config \
	--module engine_code \
	--tool kiuwan \
	--folder_path path/to/source
```

## Extensibility

- New SAST tools or exclusion policies can be added by extending the adapters and use cases.
- Supports integration with various version control and CI/CD platforms.

## Testing

- Unit tests are provided in the `test/` directory, covering orchestration logic, configuration parsing, and exclusion handling.
