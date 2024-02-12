# Introduction

DevSecOps Security Tools

# Objective

Tool that unifies the evaluation of the different devsecops practices being agnostic to the devops platform, using both open source and market tools.

# Components


📦 [common_devsecops_lib](https://github.com/bancolombia/NU0429001_devsecops_engine/tree/trunk/common_devsecops_lib): Utilities for DevSecOps tools




📦 [tools](https://github.com/bancolombia/NU0429001_devsecops_engine/tree/trunk/tools): DevSecOps Practice Modules

# Getting started

### Requirements

- Python >= 3.8

### Installation

```bash
python3 -m pip install https://artifactory.apps.bancolombia.com/artifactory/common-pypi/devsecops_engine_utilities/{last_version}/devsecops_engine_utilities-{last_version}-py3-none-any.whl -i https://artifactory.apps.bancolombia.com/api/pypi/python-org/simple
```

```bash
python3 -m pip install https://artifactory.apps.bancolombia.com/artifactory/common-pypi/devsecops_engine_tools/{last_version}/devsecops_engine_tools-{last_version}-py3-none-any.whl -i https://artifactory.apps.bancolombia.com/api/pypi/python-org/simple
```

### Scan running - flags (CLI)

```bash
python3 -m devsecops_engine_tools.engine_core.src.applications.runner_engine_core --remote_config_repo ["remote_config_repo"] --tool ["engine_iac", "engine_dast", "engine_secret", "engine_dependencies"] --environment ["dev", "qa", "pdn"] --use_secrets_manager ["false", "true"] --use_vulnerability_management ["false", "true"]
```

### Scan running sample (CLI)

```bash
python3 -m devsecops_engine_tools.engine_core.src.applications.runner_engine_core --remote_config_repo NU0429001_DevSecOps_Remote_Config --tool engine_iac --environment pdn --use_secrets_manager false --use_vulnerability_management false

```
### Scan result sample (CLI)

```bash
    ____            _____           ____                ____                         __                __    _      
   / __ \___ _   __/ ___/___  _____/ __ \____  _____   / __ )____ _____  _________  / /___  ____ ___  / /_  (_)___ _
  / / / / _ \ | / /\__ \/ _ \/ ___/ / / / __ \/ ___/  / __  / __ `/ __ \/ ___/ __ \/ / __ \/ __ `__ \/ __ \/ / __ `/
 / /_/ /  __/ |/ /___/ /  __/ /__/ /_/ / /_/ (__  )  / /_/ / /_/ / / / / /__/ /_/ / / /_/ / / / / / / /_/ / / /_/ / 
/_____/\___/|___//____/\___/\___/\____/ .___/____/  /_____/\__,_/_/ /_/\___/\____/_/\____/_/ /_/ /_/_.___/_/\__,_/  
                                     /_/                                                                            

2024-01-11 10:15:31,431 [WARNING | checkov_tool.py | configurate_external_checks | 55] > Secrets manager is not enabled to configure external checks
Secrets manager is not enabled to configure external checks

Below are all vulnerabilities detected.
╔══════════╦══════════════╦═════════════════════════════════════════════════════════════════════╦═════════════════════╗
║ Severity ║ ID           ║ Description                                                         ║ Where               ║
╠══════════╬══════════════╬═════════════════════════════════════════════════════════════════════╬═════════════════════╣
║ high     ║ CKV_DOCKER_3 ║ Ensure that a user for the container has been created               ║ /_AW1234/Dockerfile ║
║ high     ║ CKV_K8S_37   ║ Minimize the admission of containers with capabilities assigned     ║ /_AW1234/app.yaml   ║
║ high     ║ CKV_K8S_20   ║ Containers should not run with allowPrivilegeEscalation             ║ /_AW1234/app.yaml   ║
║ high     ║ CKV_K8S_22   ║ Use read-only filesystem for containers where possible              ║ /_AW1234/app.yaml   ║
║ high     ║ CKV_K8S_28   ║ Minimize the admission of containers with the NET_RAW capability    ║ /_AW1234/app.yaml   ║
║ high     ║ CKV_K8S_30   ║ Apply security context to your containers                           ║ /_AW1234/app.yaml   ║
║ high     ║ CKV_K8S_38   ║ Ensure that Service Account Tokens are only mounted where necessary ║ /_AW1234/app.yaml   ║
║ high     ║ CKV_K8S_23   ║ Minimize the admission of root containers                           ║ /_AW1234/app.yaml   ║
╚══════════╩══════════════╩═════════════════════════════════════════════════════════════════════╩═════════════════════╝
##[error]Security count issues (critical: 0, high: 8, medium: 0, low: 0) is greater than or equal to failure criteria (critical: 1, high: 8, medium: 10, low:15, operator: or)

Below are all compliances issues detected.
╔══════════╦═══════════╦══════════════════════════════════════╦═══════════════════╗
║ Severity ║ ID        ║ Description                          ║ Where             ║
╠══════════╬═══════════╬══════════════════════════════════════╬═══════════════════╣
║ critical ║ CKV_K8S_8 ║ Liveness Probe Should be Configured  ║ /_AW1234/app.yaml ║
║ low      ║ CKV_K8S_9 ║ Readiness Probe Should be Configured ║ /_AW1234/app.yaml ║
╚══════════╩═══════════╩══════════════════════════════════════╩═══════════════════╝
##[error]Compliance issues count is greater than or equal to failure criteria (critical: 1)
``````

# How can I help?

Review the issues, we hear new ideas. Read more [Contributing](https://github.com/bancolombia/NU0429001_devsecops_engine/blob/trunk/docs/CONTRIBUTING.md)
